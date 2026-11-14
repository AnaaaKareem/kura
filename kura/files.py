import hashlib
import hmac
import logging
import os
import socket
import struct
from datetime import datetime, timedelta, timezone

import magic
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import HttpResponse
from django.utils.http import content_disposition_header
from .logging_utils import log_security_event
from .models import ALLOWED_UPLOAD_MIME_TYPES, MAX_UPLOAD_BYTES, FileContent, QuarantinedFile, StoredFile
from .vault import decrypt_file_content, encrypt_file_content

# Filename extensions accepted for each MIME type that validate_and_save_upload
# allows. A PDF renamed to .html would otherwise pass the MIME check and be
# stored under a web-page extension, so the two must agree. libmagic sometimes
# reports an Office or OpenDocument file as application/zip, so those
# extensions are also listed there to keep legitimate uploads working.
ALLOWED_EXTENSIONS_BY_MIME = {
    "application/pdf": {".pdf"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {".pptx"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "application/msword": {".doc", ".dot"},
    "application/vnd.ms-powerpoint": {".ppt", ".pps"},
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.oasis.opendocument.text": {".odt"},
    "application/vnd.oasis.opendocument.presentation": {".odp"},
    "application/vnd.oasis.opendocument.spreadsheet": {".ods"},
    "image/png": {".png"},
    "image/jpeg": {".jpg", ".jpeg"},
    "image/gif": {".gif"},
    "image/webp": {".webp"},
    # Plain text is what libmagic reports for .txt, .md and sometimes .csv.
    "text/plain": {".txt", ".csv", ".md"},
    "text/csv": {".csv"},
    "text/markdown": {".md"},
    "video/mp4": {".mp4", ".m4v"},
    "audio/mpeg": {".mp3"},
    "application/zip": {".zip", ".docx", ".pptx", ".xlsx", ".odt", ".odp", ".ods"},
}


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
            log_security_event(None, "clamav.unavailable", {"error_type": type(error).__name__}, level=logging.ERROR)
            raise ValidationError("Antivirus service is unavailable. Upload rejected for safety.")
        # In development mode, allow the upload with a warning so offline development works.
        log_security_event(None, "clamav.unavailable", {"error_type": type(error).__name__}, level=logging.ERROR)
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
        log_security_event(None, "clamav.unavailable", {"error_type": "ScannerError"}, level=logging.ERROR)
        if scanner_is_required:
            raise ValidationError("Security scanner encountered an error. Upload rejected.")
        return

    # A closed connection or malformed reply is not a successful clean scan.
    if not scanner_response.endswith((b"\x00", b"\n")) or scanner_response_text != "stream: OK":
        log_security_event(None, "clamav.unavailable", {"error_type": "InvalidScannerResponse"}, level=logging.ERROR)
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
        log_security_event(None, "clamav.unavailable", {"error_type": type(error).__name__}, level=logging.ERROR)
        return
    finally:
        if clamav_socket:
            clamav_socket.close()

    # The third part (after the second "/") is the date of the newest signatures.
    reply_parts = version_reply.split("/")
    if len(reply_parts) != 3:
        log_security_event(None, "clamav.unavailable", {"error_type": "InvalidVersionResponse"}, level=logging.WARNING)
        return
    try:
        signature_date = datetime.strptime(reply_parts[2].strip(), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        log_security_event(None, "clamav.unavailable", {"error_type": "InvalidSignatureDate"}, level=logging.WARNING)
        return

    # ClamAV reports the date in UTC. Warn when it is more than 3 days old.
    signature_age = datetime.now(timezone.utc).replace(tzinfo=None) - signature_date
    if signature_age > timedelta(days=3):
        log_security_event(None, "clamav.signatures_old", {"age_days": signature_age.days}, level=logging.WARNING)


def validate_and_save_upload(uploaded_file, user, request=None, log_context=None):
    """
    Validates file size (up to 25 MiB), checks bytes for malware with ClamAV,
    detects real MIME type with python-magic, computes a SHA-256 digest,
    and stores the metadata and binary content in PostgreSQL.
    """
    # Enforce file size limits: between 1 byte and 25 MiB.
    file_size = uploaded_file.size
    if file_size <= 0:
        log_security_event(request, "file.upload_rejected", {"reason": "empty_file"}, level=logging.WARNING)
        raise ValidationError("Uploaded file is empty.")
    if file_size > MAX_UPLOAD_BYTES:
        log_security_event(request, "file.upload_rejected", {"reason": "size_limit"}, level=logging.WARNING)
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
            log_security_event(request, "file.upload_rejected", {"reason": "scanner_unavailable"}, level=logging.WARNING)
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

        # Log only safe file identifiers; omit original_filename to keep PII out of logs.
        log_security_event(
            request,
            "file.quarantined",
            {
                "user_id": user.id,
                "sha256": content_sha256,
                "size": file_size,
                "detection": detection[:500],
            },
            level=logging.WARNING,
        )
        raise

    # Warn (but carry on) if ClamAV's virus signatures are out of date.
    check_signature_age()

    # Inspect the actual file bytes using python-magic (do not trust user extension).
    detected_mime_type = magic.from_buffer(content_bytes, mime=True)

    # Validate against allowed MIME types.
    if detected_mime_type not in ALLOWED_UPLOAD_MIME_TYPES:
        log_security_event(request, "file.upload_rejected", {"reason": "mime_type"}, level=logging.WARNING)
        raise ValidationError(
            "This file type isn't allowed. Allowed: PDF, Word, PowerPoint, Excel, "
            "OpenDocument, CSV, text, Markdown, images (PNG, JPEG, GIF, WebP), MP4, MP3, ZIP."
        )

    # Calculate SHA-256 hash.
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()

    # The extension must match the detected type, so a valid PDF named .html
    # cannot be stored and later downloaded under a web-page extension (INP-01).
    original_filename = sanitize_filename(uploaded_file.name)
    extension = os.path.splitext(original_filename)[1].lower()
    if extension not in ALLOWED_EXTENSIONS_BY_MIME.get(detected_mime_type, set()):
        log_security_event(request, "file.upload_rejected", {"reason": "extension_mismatch"}, level=logging.WARNING)
        raise ValidationError("The file extension does not match the detected file type.")

    # Save metadata and encrypted file content atomically so Vault failure leaves no orphan row.
    with transaction.atomic():
        stored_file = StoredFile.objects.create(
            uploaded_by=user,
            original_filename=original_filename,
            mime_type=detected_mime_type,
            size_bytes=file_size,
            sha256_hash=content_sha256,
        )

        encrypted = encrypt_file_content(content_bytes, stored_file.id)
        FileContent.objects.create(
            file=stored_file,
            content=encrypted["content"],
            wrapped_key=encrypted["wrapped_key"],
            nonce=encrypted["nonce"],
            encryption_version=encrypted["encryption_version"],
        )

    # Record safe metadata after both the file record and its content are stored.
    upload_details = {
        "file_id": stored_file.id,
        "sha256": content_sha256,
        "size": file_size,
        "mime": detected_mime_type,
    }
    if log_context:
        upload_details.update(log_context)
    log_security_event(request, "file.uploaded", upload_details)

    return stored_file


def create_download_response(stored_file):
    """
    Builds an HTTP download response with forced attachment disposition,
    MIME type, nosniff, and no-store caching headers after decrypting and re-verifying SHA-256.
    """
    # Decrypt FileContent in memory and fail closed with a generic error on crypto failure.
    try:
        binary_content = decrypt_file_content(stored_file.content)
    except ValidationError:
        return HttpResponse("File decryption failed.", status=500)

    actual_sha256 = hashlib.sha256(binary_content).hexdigest()
    if not hmac.compare_digest(actual_sha256, stored_file.sha256_hash):
        log_security_event(
            None,
            "file.integrity_failed",
            {"file_id": stored_file.id, "expected_sha256": stored_file.sha256_hash},
            level=logging.ERROR,
        )
        return HttpResponse("File integrity verification failed.", status=500)

    response = HttpResponse(binary_content, content_type=stored_file.mime_type)
    safe_filename = sanitize_filename(stored_file.original_filename)

    # Force browser download instead of inline execution. Django's helper quotes and
    # escapes the name and adds filename*=UTF-8'' for non-ASCII names, so a stored
    # filename containing a quote or semicolon cannot inject extra header parameters.
    response["Content-Disposition"] = content_disposition_header(True, safe_filename)

    # Prevent MIME confusion attacks.
    response["X-Content-Type-Options"] = "nosniff"

    # Ensure sensitive materials are not stored in shared caches.
    response["Cache-Control"] = "no-store"

    return response
