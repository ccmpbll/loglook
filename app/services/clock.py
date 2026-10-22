from datetime import datetime, timezone


def now() -> datetime:
    """The current time, timezone-aware. One place to replace in tests."""
    return datetime.now(timezone.utc)
