"""Response helpers — encoding that cannot be turned into a 500 by a client.

Found by the property-based suite: ``json.loads('{"m": "\\ud800"}')`` yields a
Python string containing a *lone surrogate*, which is not encodable as UTF-8. A
handler that echoed that value back then raised ``UnicodeEncodeError`` while
rendering its own response — an attacker-triggerable 500 that no amount of
schema-shaped testing would have surfaced.

Two layers fix it, deliberately redundant:

1. **Input validation** (``api/schemas.py``) rejects lone surrogates with a clear
   ``422`` — the honest answer for text that is not valid Unicode.
2. **This response class** guarantees the *output* side can always be rendered:
   the normal path stays ``ensure_ascii=False`` (so Indic text is not bloated
   into ``\\uXXXX`` escapes), and only a payload that cannot be UTF-8 encoded
   falls back to ASCII escaping.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.responses import JSONResponse


class SafeJSONResponse(JSONResponse):
    """``JSONResponse`` that never fails to render on non-encodable input."""

    def render(self, content: Any) -> bytes:
        text = json.dumps(
            content, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
        try:
            return text.encode("utf-8")
        except UnicodeEncodeError:
            # Lone surrogates (or any other non-UTF-8-encodable code point):
            # escape everything rather than 500 on the way out.
            return json.dumps(
                content, ensure_ascii=True, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")


def sanitize_text(value: str) -> str:
    """Replace lone surrogates with U+FFFD (used before echoing input back)."""
    if not any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        return value
    return "".join(
        "\ufffd" if 0xD800 <= ord(ch) <= 0xDFFF else ch for ch in value
    )


def sanitize_for_json(obj: Any) -> Any:
    """Recursively make a structure safe to serialise (dicts/lists/strings)."""
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, dict):
        return {sanitize_text(k) if isinstance(k, str) else k: sanitize_for_json(v)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    return obj
