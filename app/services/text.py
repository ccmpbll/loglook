"""Small helpers for turning log text into something safe and compact to return."""
import re
from datetime import datetime

_MAC = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX = re.compile(r"\b0x[0-9a-fA-F]+\b")
_NUM = re.compile(r"\d+")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
EXAMPLE_CHARS = 240


def normalize(text: str) -> str:
    """A line with the parts that differ every time (MACs, IPs, hex, numbers) replaced, so that
    repeats of the same message share one key."""
    t = _MAC.sub("<mac>", text)
    t = _IP.sub("<ip>", t)
    t = _HEX.sub("<hex>", t)
    return _NUM.sub("#", t)[:200]


def clean(text: str, limit: int = EXAMPLE_CHARS) -> str:
    """Log text is untrusted: no control characters, and bounded."""
    return _CONTROL.sub("", text)[:limit]


def iso(ts: datetime | None) -> str | None:
    return ts.isoformat(timespec="seconds") if ts else None
