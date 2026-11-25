"""Unicode normalization, bidi/control character rejection, and filename safety (G08)."""

import re
import unicodedata

from django.core.exceptions import ValidationError

# Explicit bidirectional overrides/isolates, zero-width space/joiners, BOM, and soft hyphen.
BIDI_AND_INVISIBLE = frozenset(
    {
        "\u00ad",
        "\u200b",
        "\u200c",
        "\u200d",
        "\u200e",
        "\u200f",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\ufeff",
    }
)

_TOKEN_SPLIT_RE = re.compile(r"[\s\-_.,;:/@]+")


def normalize_text(value, *, multiline=False):
    """Apply NFKC normalization and reject invisible bidi or control characters.

    Who can use it: Form field cleaning via SafeTextMixin across all text entry forms.
    Security: Rejects U+202E right-to-left overrides, zero-width characters, and Cc/Cf
    controls instead of stripping them silently so deceptive input fails validation.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    normalized = unicodedata.normalize("NFKC", value)
    for ch in normalized:
        if multiline and ch in ("\n", "\r", "\t"):
            continue
        if ch in BIDI_AND_INVISIBLE or unicodedata.category(ch) in ("Cc", "Cf"):
            raise ValidationError("This field contains characters that are not allowed.", code="unsafe_unicode")
    return normalized


def normalize_email(value):
    """Normalize an email address with NFKC and require institutional ASCII characters.

    Who can use it: Login, password-reset, and account creation forms plus UserManager.
    Security: Collapses full-width compatibility forms (for example full-width ASCII) and
    rejects homoglyph non-ASCII local/domain parts before account lookup or creation.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    cleaned = unicodedata.normalize("NFKC", value.strip()).strip().lower()
    if not cleaned:
        return ""
    for ch in cleaned:
        if ch in BIDI_AND_INVISIBLE or unicodedata.category(ch) in ("Cc", "Cf"):
            raise ValidationError("This field contains characters that are not allowed.", code="unsafe_unicode")
    if not cleaned.isascii():
        raise ValidationError("Enter a valid institutional ASCII email address.", code="non_ascii_email")
    return cleaned


def has_mixed_scripts(value):
    """Return True when a single word token mixes Latin with Cyrillic or Greek letters.

    Who can use it: SafeTextMixin security telemetry for suspicious spoofing patterns.
    Security: Flags potential confusable names without rejecting legitimate multilingual
    inputs; callers log input.mixed_script at INFO level for visibility.
    """
    if not value or not isinstance(value, str):
        return False
    for token in _TOKEN_SPLIT_RE.split(value):
        scripts = set()
        for ch in token:
            if not unicodedata.category(ch).startswith("L"):
                continue
            name = unicodedata.name(ch, "")
            family = name.split()[0] if name else ""
            if family in ("LATIN", "CYRILLIC", "GREEK"):
                scripts.add(family)
        if "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts):
            return True
    return False
