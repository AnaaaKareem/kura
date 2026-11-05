import hashlib
import magic
from django.core.exceptions import ValidationError
from django.http import HttpResponse
from .models import ALLOWED_UPLOAD_MIME_TYPES, MAX_UPLOAD_BYTES, FileContent, StoredFile

# Logger for security events
def sanitize_filename(filename):
    """
    Strips directory traversal paths and leading/trailing whitespace from an uploaded filename.
    Returns 'download' if the name becomes empty.
    """
    clean_name = filename.replace("\\", "/").split("/")[-1].strip()
    return clean_name or "download"


def validate_and_save_upload(uploaded_file, user):
    """
    Validates file size (up to 25 MiB), detects real MIME type with python-magic,
    computes a SHA-256 digest,
    and stores the metadata and binary content in PostgreSQL.
    """
    # Enforce file size limits: between 1 byte and 25 MiB.
    file_size = uploaded_file.size
    if file_size <= 0:
        raise ValidationError("Uploaded file is empty.")
    if file_size > MAX_UPLOAD_BYTES:
        raise ValidationError(f"File size exceeds the maximum limit of {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB.")

    # Read binary content to detect real MIME type and compute hash.
    content_bytes = uploaded_file.read()


    # Inspect the actual file bytes using python-magic (do not trust user extension).
    detected_mime_type = magic.from_buffer(content_bytes, mime=True)

    # Validate against allowed MIME types.
    if detected_mime_type not in ALLOWED_UPLOAD_MIME_TYPES:
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
