import os
import secrets
from pathlib import Path

VERSION = os.environ.get("LOGLOOK_VERSION", "dev")

# Where the admin login and API tokens live (the only state loglook keeps).
DATA_DIR = Path(os.environ.get("LOGLOOK_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# The folder Unraid's syslog server writes to: syslog-<ip>.log plus rotated .log.1 ... Read-only.
LOG_DIR = Path(os.environ.get("LOGLOOK_LOG_DIR", "/logs"))

# Which IP is which device, and what to ignore or watch for it.
CONFIG_PATH = Path(os.environ.get("LOGLOOK_CONFIG", "/config/sources.yml"))

DB_PATH = DATA_DIR / "loglook.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"


def _resolve_secret_key() -> str:
    env_value = os.environ.get("LOGLOOK_SECRET_KEY", "").strip()
    if env_value:
        return env_value
    # No key provided: generate one and keep it, so sessions survive restarts.
    key_path = DATA_DIR / "secret_key"
    if key_path.exists():
        existing = key_path.read_text().strip()
        if existing:
            return existing
    generated = secrets.token_hex(32)
    key_path.write_text(generated)
    key_path.chmod(0o600)
    return generated


SECRET_KEY = _resolve_secret_key()

# Mark the session cookie Secure. Turn on when served over TLS behind a reverse proxy.
SECURE_COOKIES = os.environ.get("LOGLOOK_SECURE_COOKIES", "").strip().lower() in ("1", "true", "yes")
