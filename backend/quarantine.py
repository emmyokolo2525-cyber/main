from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from typing import NamedTuple


class QuarantineError(ValueError):
    """Raised when an uploaded file fails quarantine signature checks."""
    pass


class VideoFormat(NamedTuple):
    """Describes a known video format with expected extension(s) and MIME type(s).

    Multiple formats can share the same magic-bytes (e.g. WebM and MKV both
    use the EBML header); the format name returned by ``detect_format`` is
    used as a "family" for cross-validation so that any valid extension/MIME
    within the family is accepted.
    """
    name: str                         # Display / family name
    extensions: frozenset[str]        # Allowed file extensions
    mime_types: frozenset[str]        # Allowed MIME types


# ---------------------------------------------------------------------------
# Known video format families
#
# The detection logic works in two tiers:
#   1. read magic bytes from the file header
#   2. look up the family (format name) whose signature matches
#
# The cross-validation step then ensures that the declared filename
# extension and content type belong to the same family.
#
# ``application/octet-stream`` is treated as a wildcard — any valid video
# magic counts as consistent.
# ---------------------------------------------------------------------------

# Number of bytes to read for header analysis.  32 is enough to
# distinguish all known video families.
_HEADER_BYTES = 32

_KNOWN_FORMATS: list[VideoFormat] = [
    VideoFormat(
        name="MP4",
        extensions=frozenset({".mp4", ".m4v", ".m4a", ".m4b", ".mp4v"}),
        mime_types=frozenset({"video/mp4", "video/x-m4v"}),
    ),
    VideoFormat(
        name="MOV",
        extensions=frozenset({".mov", ".qt"}),
        mime_types=frozenset({"video/quicktime"}),
    ),
    VideoFormat(
        name="3GP",
        extensions=frozenset({".3gp", ".3g2"}),
        mime_types=frozenset({"video/3gpp", "video/3gp", "video/3gpp2"}),
    ),
    VideoFormat(
        name="Matroska",
        extensions=frozenset({".webm", ".mkv", ".mka", ".mks"}),
        mime_types=frozenset({"video/webm", "video/x-matroska", "video/mkv", "audio/webm"}),
    ),
    VideoFormat(
        name="AVI",
        extensions=frozenset({".avi"}),
        mime_types=frozenset({"video/x-msvideo", "video/avi"}),
    ),
]


# ---------------------------------------------------------------------------
# Magic-byte detection helpers
# ---------------------------------------------------------------------------


def _read_header(path: Path) -> bytes | None:
    """Read the first ``_HEADER_BYTES`` from *path*.

    Returns ``None`` if the file is too small or unreadable.
    """
    if not path.is_file():
        return None
    try:
        with path.open("rb") as f:
            header = f.read(_HEADER_BYTES)
    except OSError:
        return None
    return header


def _detect_format_family(header: bytes) -> str | None:
    """Detect the video format family from magic bytes in *header*.

    Returns the format *name* (e.g. ``"MP4"``, ``"Matroska"``, ``"AVI"``) or
    ``None`` when no known video signature is found.
    """
    if len(header) < 12:
        return None

    # EBML header ─ Matroska / WebM / MKV family
    if header.startswith(b"\x1a\x45\xdf\xa3"):
        return "Matroska"

    # ISO Base Media File Format ─ check the ftyp brand at offset 8
    if header[4:8] == b"ftyp":
        brand = header[8:12] if len(header) >= 12 else b""
        if brand[:3] in {b"3gp", b"3g2"}:
            return "3GP"
        if brand[:2] == b"qt":
            return "MOV"
        # Everything else that starts with ftyp is treated as MP4,
        # which is the safest default for the ISO BMFF family.
        return "MP4"

    # AVI ─ RIFF container with "AVI " form type
    if header[:4] == b"RIFF" and len(header) >= 12 and header[8:12] == b"AVI ":
        return "AVI"

    return None


def _normalise_extension(filename: str) -> str | None:
    """Return a lower-case file extension (including the dot), or None."""
    dot = filename.rfind(".")
    if dot == -1 or dot == len(filename) - 1:
        return None
    return filename[dot:].lower()


def _normalise_mime(content_type: str | None) -> str | None:
    """Return a lower-case content type, stripping any parameters."""
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower()


def _fmt_by_extension(ext: str) -> VideoFormat | None:
    """Return the ``VideoFormat`` matching *ext* (e.g. ``".mp4"``), or None."""
    for fmt in _KNOWN_FORMATS:
        if ext in fmt.extensions:
            return fmt
    return None


def _fmt_by_mime(mime: str) -> VideoFormat | None:
    """Return the ``VideoFormat`` matching *mime* (e.g. ``"video/mp4"``), or None."""
    for fmt in _KNOWN_FORMATS:
        if mime in fmt.mime_types:
            return fmt
    return None


def _fmt_by_name(name: str) -> VideoFormat | None:
    """Return the ``VideoFormat`` with the given *name*, or None."""
    for fmt in _KNOWN_FORMATS:
        if fmt.name == name:
            return fmt
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class SignatureScanner:
    """
    Scans file magic bytes to verify structural compatibility with expected
    video formats before allowing ffmpeg to parse them.
    """

    @staticmethod
    def is_valid_video(path: Path) -> bool:
        """Return ``True`` when *path* contains recognised video magic bytes.

        This is the legacy compatibility interface.
        """
        header = _read_header(path)
        if header is None:
            return False
        return _detect_format_family(header) is not None

    @classmethod
    def detect_format(cls, path: Path) -> str | None:
        """Detect the video format of *path* by inspecting header bytes.

        Returns the format family name (e.g. ``"MP4"``, ``"Matroska"``) or
        ``None`` if the file does not match any known video signature.
        """
        header = _read_header(path)
        if header is None:
            return None
        if len(header) < 12:
            return None
        return _detect_format_family(header)

    @classmethod
    def verify_consistency(
        cls,
        path: Path,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> tuple[bool, str | None]:
        """Verify that *path* contains valid video magic bytes and that the
        detected format family is consistent with the original *filename*
        extension and *content_type* (if provided).

        ``application/octet-stream`` is treated as a wildcard and never
        triggers a content-type mismatch.

        Returns ``(is_valid, error_message)``.  When *is_valid* is ``False``
        the error message describes the failure.
        """
        header = _read_header(path)
        if header is None:
            return False, "uploaded file is empty, too small, or unreadable"

        if len(header) < 12:
            return False, "uploaded file is too small to contain a valid video header"

        # ── Detect format family from magic bytes ──
        detected = _detect_format_family(header)
        if detected is None:
            return False, "uploaded file failed signature scan; invalid or unsupported video format"

        # ── Cross-validate file extension ──
        if filename:
            ext = _normalise_extension(filename)
            if ext:
                fmt_by_ext = _fmt_by_extension(ext)
                if fmt_by_ext is None:
                    return False, f"uploaded file has unsupported extension '{ext}'"
                if fmt_by_ext.name != detected:
                    return (
                        False,
                        f"uploaded file claims to be '{ext}' but its signature matches {detected}; "
                        f"possible content-type spoofing",
                    )

        # ── Cross-validate content type (octet-stream is wildcard) ──
        if content_type:
            mime = _normalise_mime(content_type)
            if mime and mime != "application/octet-stream":
                fmt_by_mime_val = _fmt_by_mime(mime)
                if fmt_by_mime_val is None:
                    return False, f"uploaded file has unsupported content type '{mime}'"
                if fmt_by_mime_val.name != detected:
                    return (
                        False,
                        f"uploaded file claims '{mime}' but its signature matches {detected}; "
                        f"possible content-type spoofing",
                    )

        return True, None


@contextlib.contextmanager
def isolate_upload(flask_file, *, filename: str | None = None, content_type: str | None = None):
    """
    Context manager to safely save an uploaded file to an isolated
    temporary directory for quarantine processing. Yields the path
    to the safely quarantined file if it passes the signature scan
    and cross-validation.

    Parameters
    ----------
    flask_file:
        A Werkzeug ``FileStorage`` (or duck-typed equivalent) with a
        ``save(dst)`` method.
    filename: optional
        The original filename for cross-validation.  Falls back to
        ``flask_file.filename``.
    content_type: optional
        The declared content type for cross-validation.  Falls back to
        ``flask_file.content_type``.
    """
    resolved_name = filename if filename is not None else getattr(flask_file, "filename", None)
    resolved_type = content_type if content_type is not None else getattr(flask_file, "content_type", None)

    with tempfile.TemporaryDirectory(prefix="harpocrates-quarantine-") as tmp_dir:
        tmp_path = Path(tmp_dir) / "upload.tmp"
        flask_file.save(str(tmp_path))

        # Restrict permissions
        os.chmod(tmp_path, 0o600)

        valid, error = SignatureScanner.verify_consistency(
            tmp_path,
            filename=resolved_name,
            content_type=resolved_type,
        )
        if not valid:
            raise QuarantineError(error)

        yield tmp_path
