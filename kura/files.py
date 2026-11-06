import hashlib
import json
import logging
import socket
import struct
from datetime import datetime, timedelta, timezone

import magic
from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from .models import ALLOWED_UPLOAD_MIME_TYPES, MAX_UPLOAD_BYTES, FileContent, QuarantinedFile, StoredFile

# Logger for security events
logger = logging.getLogger("kura.security")


def sanitize_filename(filename):
    """
    Strips directory traversal paths and leading/trailing whitespace from an uploaded filename.
    Returns 'download' if the name becomes empty.
    """
    clean_name = filename.replace("\\", "/").split("/")[-1].strip()
    return clean_name or "download"


def scan_file_for_malware(content_bytes):
    """
    Streams file bytes to ClamAV over a TCP socket before saving anything.
    Raises ValidationError if malware is found or if the scanner is required but unreachable.
    When ClamAV rejects the file, the error has code "malware" and carries what
    ClamAV reported (params["detection"]), so validate_and_save_upload can quarantine it.
    """
    clamav_host = getattr(settings, "CLAMAV_HOST", "clamav")
    clamav_port = getattr(settings, "CLAMAV_PORT", 3310)
    scanner_is_required = getattr(settings, "CLAMAV_REQUIRED", not settings.DEBUG)
    scanner_timeout = getattr(settings, "CLAMAV_TIMEOUT_SECONDS", 10)

    clamav_socket = None
    try:
        # Open a TCP stream socket to the ClamAV daemon.
        clamav_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clamav_socket.settimeout(scanner_timeout)
        clamav_socket.connect((clamav_host, clamav_port))

        # Send the zINSTREAM command (null-terminated chunk format).
        clamav_socket.sendall(b"zINSTREAM\x00")

        # Stream the file content in chunks (64 KiB at a time).
        # Each chunk starts with a 4-byte unsigned integer indicating the chunk size.
        chunk_size = 64 * 1024
        for offset in range(0, len(content_bytes), chunk_size):
            chunk = content_bytes[offset : offset + chunk_size]
            length_header = struct.pack("!I", len(chunk))
            clamav_socket.sendall(length_header + chunk)

        # Terminate the stream by sending a zero-length integer (0x00000000).
        clamav_socket.sendall(struct.pack("!I", 0))

        # Read the scan result response from ClamAV.
        scanner_response = b""
        while True:
            chunk = clamav_socket.recv(4096)
            if not chunk:
                break
            scanner_response += chunk
            if b"\x00" in scanner_response or b"\n" in scanner_response:
                break

    except (OSError, socket.timeout) as error:
        # In production (or when required), fail closed to keep the system safe.
        if scanner_is_required:
            logger.error("event=clamav.unavailable error_type=" + json.dumps(type(error).__name__))
            raise ValidationError("Antivirus service is unavailable. Upload rejected for safety.")
        # In development mode, allow the upload with a warning so offline development works.
        logger.error("event=clamav.unavailable error_type=" + json.dumps(type(error).__name__))
        return
    finally:
        # Always close the socket connection.
        if clamav_socket:
            try:
                clamav_socket.close()
            except OSError:
                pass

    # Convert the bytes response to text for inspection.
    scanner_response_text = scanner_response.decode("utf-8", errors="replace").strip("\x00\r\n ")

    # If ClamAV rejects the file, the response ends with "FOUND", for example
    # "stream: Eicar-Test-Signature FOUND" or "stream: Heuristics.Encrypted.Zip FOUND".
    # The words in between are the detection name; keep them for the quarantine record.
    if scanner_response_text.endswith("FOUND"):
        detection = scanner_response_text.removeprefix("stream:").removesuffix("FOUND").strip()
        # The user only ever sees this generic message (never the detection name).
        raise ValidationError(
            "The uploaded file failed security scanning.",
            code="malware",
            params={"detection": detection[:255] or "unknown"},
        )

    # If ClamAV encountered an internal scanning error (e.g. stream size limit exceeded).
    if "ERROR" in scanner_response_text:
        logger.error("event=clamav.unavailable error_type=ScannerError")
        if scanner_is_required:
            raise ValidationError("Security scanner encountered an error. Upload rejected.")
        return

    # A closed connection or malformed reply is not a successful clean scan.
    if not scanner_response.endswith((b"\x00", b"\n")) or scanner_response_text != "stream: OK":
        logger.error("event=clamav.unavailable error_type=InvalidScannerResponse")
        if scanner_is_required:
            raise ValidationError("Security scanner encountered an error. Upload rejected.")


def check_signature_age():
    """
    Asks ClamAV how old its virus signatures are and logs a warning when they
    are more than 3 days old (signature updates are probably failing).
    Kura policy: uploads continue with old signatures; this only warns.
    Any problem talking to ClamAV here is ignored: the scan itself already
    decides whether the scanner is usable.
    """
    clamav_socket = None
    try:
        # "zVERSION" answers e.g. "ClamAV 1.5.4/27812/Thu Nov  5 09:27:46 2026".
        clamav_socket = socket.create_connection(
            (getattr(settings, "CLAMAV_HOST", "clamav"), getattr(settings, "CLAMAV_PORT", 3310)),
            timeout=getattr(settings, "CLAMAV_TIMEOUT_SECONDS", 10),
        )
        clamav_socket.sendall(b"zVERSION\x00")
        version_reply = clamav_socket.recv(1024).decode("utf-8", errors="replace").strip("\x00\r\n ")
    except OSError as error:
        # Report an unavailable scanner without logging network details or user data.
        logger.error("event=clamav.unavailable error_type=" + json.dumps(type(error).__name__))
        return
    finally:
        if clamav_socket:
            clamav_socket.close()

    # The third part (after the second "/") is the date of the newest signatures.
    reply_parts = version_reply.split("/")
    if len(reply_parts) != 3:
        logger.warning("event=clamav.unavailable error_type=InvalidVersionResponse")
        return
    try:
        signature_date = datetime.strptime(reply_parts[2].strip(), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        logger.warning("event=clamav.unavailable error_type=InvalidSignatureDate")
        return

    # ClamAV reports the date in UTC. Warn when it is more than 3 days old.
    signature_age = datetime.now(timezone.utc).replace(tzinfo=None) - signature_date
    if signature_age > timedelta(days=3):
        logger.warning("event=clamav.signatures_old age_days=" + json.dumps(str(signature_age.days)))


def validate_and_save_upload(uploaded_file, user):
    """
    Validates file size (up to 25 MiB), checks bytes for malware with ClamAV,
    detects real MIME type with python-magic, computes a SHA-256 digest,
    and stores the metadata and binary content in PostgreSQL.
    """
    # Enforce file size limits: between 1 byte and 25 MiB.
    file_size = uploaded_file.size
    if file_size <= 0:
        logger.warning('event=file.upload_rejected reason="empty_file"')
        raise ValidationError("Uploaded file is empty.")
    if file_size > MAX_UPLOAD_BYTES:
        logger.warning('event=file.upload_rejected reason="size_limit"')
        raise ValidationError(f"File size exceeds the maximum limit of {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB.")

    # Read binary content to detect real MIME type and compute hash.
    content_bytes = uploaded_file.read()

    # Scan binary content for malware with ClamAV before storing.
    try:
        scan_file_for_malware(content_bytes)
    except ValidationError as error:
        # Only a file ClamAV rejected is quarantined; scanner outages are not.
        if error.code != "malware":
            # Scanner failures also reject the upload, but are not malware quarantines.
            logger.warning('event=file.upload_rejected reason="scanner_unavailable"')
            raise
        detection = error.params["detection"]
        original_filename = sanitize_filename(uploaded_file.name)
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()

        # Keep the rejected file for 7 days so an Admin can investigate.
        # .using("quarantine") saves on a separate database connection that
        # commits immediately, so the record survives even though the upload's
        # own transaction is about to be rolled back (see config/settings.py).
        QuarantinedFile.objects.using("quarantine").create(
            uploaded_by_id=user.id,
            original_filename=original_filename,
            size_bytes=file_size,
            sha256_hash=content_sha256,
            detection=detection,
            content=content_bytes,
        )

        # Quote every field so a hostile filename or scanner message cannot forge fields.
        logger.warning(
            "event=file.quarantined user_id="
            + json.dumps(str(user.id))
            + " sha256="
            + json.dumps(content_sha256)
            + " size="
            + json.dumps(str(file_size))
            + " detection="
            + json.dumps(detection[:500])
            + " filename="
            + json.dumps(original_filename[:500])
        )
        raise

    # Warn (but carry on) if ClamAV's virus signatures are out of date.
    check_signature_age()

    # Inspect the actual file bytes using python-magic (do not trust user extension).
    detected_mime_type = magic.from_buffer(content_bytes, mime=True)

    # Validate against allowed MIME types.
    if detected_mime_type not in ALLOWED_UPLOAD_MIME_TYPES:
        logger.warning('event=file.upload_rejected reason="mime_type"')
        raise ValidationError(
            "This file type isn't allowed. Allowed: PDF, Word, PowerPoint, Excel, "
            "OpenDocument, CSV, text, Markdown, images (PNG, JPEG, GIF, WebP), MP4, MP3, ZIP."
        )

    # Calculate SHA-256 hash.
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()

    original_filename = sanitize_filename(uploaded_file.name)

    # Save metadata to StoredFile.
    stored_file = StoredFile.objects.create(
        uploaded_by=user,
        original_filename=original_filename,
        mime_type=detected_mime_type,
        size_bytes=file_size,
        sha256_hash=content_sha256,
    )

    # Store binary data separately in FileContent.
    FileContent.objects.create(
        file=stored_file,
        content=content_bytes,
    )

    # Record safe metadata after both the file record and its content are stored.
    logger.info(
        "event=file.uploaded file_id="
        + json.dumps(str(stored_file.id))
        + " sha256="
        + json.dumps(content_sha256)
        + " size="
        + json.dumps(str(file_size))
        + " mime="
        + json.dumps(detected_mime_type)
    )

    return stored_file


def create_download_response(stored_file):
    """
    Builds an HTTP download response with forced attachment disposition,
    MIME type, nosniff, and no-store caching headers.
    """
    # Load binary data from FileContent.
    binary_content = stored_file.content.content

    response = HttpResponse(binary_content, content_type=stored_file.mime_type)
    safe_filename = sanitize_filename(stored_file.original_filename)

    # Force browser download instead of inline execution.
    response["Content-Disposition"] = f'attachment; filename="{safe_filename}"'

    # Prevent MIME confusion attacks.
    response["X-Content-Type-Options"] = "nosniff"

    # Ensure sensitive materials are not stored in shared caches.
    response["Cache-Control"] = "no-store"

    return response
