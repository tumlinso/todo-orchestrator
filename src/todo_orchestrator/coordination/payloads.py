"""Small, bounded human-authored coordination payloads.

This validator rejects common credential and raw-log shapes. It is a guardrail,
not a secret detector; callers should store large or sensitive material in a
separately controlled provider and send only a typed reference and digest.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3


MAX_INLINE_TEXT_BYTES = 4096
MAX_INLINE_LINES = 8
MAX_INLINE_LINE_CHARS = 1000

_CREDENTIAL_SHAPES = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/]{12,}={0,2}", re.IGNORECASE),
    re.compile(r"\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[^\s,;]{4,}", re.IGNORECASE),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,}\b"),
)
_ISSUED_TOKEN_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])")
_LOG_SHAPES = (
    re.compile(r"Traceback \(most recent call last\):"),
    re.compile(r"^\s+File \"[^\"]+\", line \d+", re.MULTILINE),
    re.compile(r"^\s+at\s+[A-Za-z_$][\w.$]*(?:\([^\n]*\))?\s*$", re.MULTILINE),
    re.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?\s+(?:DEBUG|INFO|WARN|ERROR|CRITICAL)\b", re.MULTILINE),
)


class PayloadRejectedError(ValueError):
    """Inline text is too large or resembles a credential or uncontrolled log."""


def validate_bounded_text(
    value: str,
    *,
    field: str = "text",
    max_bytes: int = MAX_INLINE_TEXT_BYTES,
    connection: sqlite3.Connection | None = None,
    allow_multiline: bool = True,
) -> str:
    """Validate an inline field and return its unchanged canonical text.

    When a SQLite connection is available, exact bearer-shaped values are also
    SHA-256 checked against issued capability digests without reading token
    plaintext. Arbitrary secrets cannot be detected reliably by this function.
    """

    if not isinstance(value, str) or not value or value != value.strip():
        raise PayloadRejectedError(f"{field} must be non-empty trimmed text")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_INLINE_TEXT_BYTES:
        raise ValueError("max_bytes must be from 1 through the bounded payload maximum")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PayloadRejectedError(f"{field} contains invalid Unicode") from exc
    if len(encoded) > max_bytes:
        raise PayloadRejectedError(f"{field} exceeds the {max_bytes}-byte inline limit")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise PayloadRejectedError(f"{field} contains control characters")
    lines = value.splitlines()
    if not allow_multiline and len(lines) != 1:
        raise PayloadRejectedError(f"{field} must be one line")
    if len(lines) > MAX_INLINE_LINES or any(len(line) > MAX_INLINE_LINE_CHARS for line in lines):
        raise PayloadRejectedError(f"{field} resembles an uncontrolled log or transcript")
    if any(pattern.search(value) for pattern in _CREDENTIAL_SHAPES):
        raise PayloadRejectedError(f"{field} resembles a credential")
    if any(pattern.search(value) for pattern in _LOG_SHAPES):
        raise PayloadRejectedError(f"{field} resembles an uncontrolled log")
    if connection is not None:
        for match in _ISSUED_TOKEN_CANDIDATE.finditer(value):
            digest = hashlib.sha256(match.group(0).encode("ascii")).hexdigest()
            if connection.execute(
                "SELECT 1 FROM capability_tokens WHERE token_digest = ?", (digest,)
            ).fetchone() is not None:
                raise PayloadRejectedError(f"{field} contains an issued bearer token")
    return value


__all__ = [
    "MAX_INLINE_LINES",
    "MAX_INLINE_LINE_CHARS",
    "MAX_INLINE_TEXT_BYTES",
    "PayloadRejectedError",
    "validate_bounded_text",
]
