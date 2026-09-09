"""
Standardized API error envelope for the Harpocrates backend.

Every response body — success or error — includes a ``request_id`` for
correlation with server logs.  Error payloads additionally carry a
machine-readable ``code`` and a human-readable ``message``.

Error envelope shape::

    {
      "ok": false,
      "error": {
        "code": "VALIDATION_ERROR",
        "message": "video and metadata are required",
        "request_id": "a1b2c3d4-..."
      }
    }

Success responses retain their existing ``"ok": true`` top-level key with an
added ``"request_id"`` field.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from flask import Flask, Response, g, jsonify, request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------

VALIDATION_ERROR = "VALIDATION_ERROR"
"""Client-supplied data failed validation (400)."""

PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
"""Request body exceeds the configured size limit (413)."""

NOT_FOUND = "NOT_FOUND"
"""The requested resource or capability is unavailable (404)."""

INTERNAL_ERROR = "INTERNAL_ERROR"
"""An unexpected server-side failure occurred (500)."""

UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"
"""The uploaded file has an unsupported content type (400)."""

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def error_response(
    *,
    code: str,
    message: str,
    status: int,
) -> tuple[Response, int]:
    """Return a Flask response tuple for a standardized error envelope.

    Args:
        code: Machine-readable error code (one of the module-level constants).
        message: Human-readable error description.
        status: HTTP status code.
    """
    request_id = _get_request_id()
    return (
        jsonify(
            {
                "ok": False,
                "error": {
                    "code": code,
                    "message": message,
                    "request_id": request_id,
                },
            },
        ),
        status,
    )


def ok_response(
    data: dict[str, Any] | None = None,
    *,
    ok: bool = True,
    status: int = 200,
) -> tuple[Response, int]:
    """Return a Flask response tuple for a successful result.

    The returned dict always contains ``"ok"`` and ``"request_id"``.
    Extra keys from *data* are merged in, and any caller-supplied
    ``"ok"`` key in *data* takes precedence over *ok*.

    Args:
        data: Additional key-value pairs to include in the response body.
        ok: Value for the top-level ``"ok"`` field (default ``True``).
        status: HTTP status code (default 200).
    """
    request_id = _get_request_id()
    body: dict[str, Any] = {"ok": ok, "request_id": request_id}
    if data:
        body.update(data)
    return jsonify(body), status


def init_request_id(app: Flask) -> None:
    """Register a ``before_request`` hook that assigns a UUID to ``g.request_id``.

    Call once during application factory setup.
    """
    logger.debug("Registering request-id middleware on Flask app %s", app)

    @app.before_request
    def _assign_request_id() -> None:
        # Prefer an incoming header so proxied requests stay traceable
        incoming = request.headers.get("X-Request-Id")
        g.request_id = incoming if incoming else str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


def _get_request_id() -> str:
    """Return the request ID for the current Flask request context."""
    return getattr(g, "request_id", "unknown")
