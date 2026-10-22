"""Which IP is which device.

`sources.yml` maps each source IP to a name and, optionally, how long silence is worth flagging. It is
re-read when it changes; a file that stops parsing keeps the last good one in service and the error
shows on the Sources page. Files in the log folder with no entry are reported as `unmapped`.
"""
import ipaddress
import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from app.config import CONFIG_PATH, LOG_DIR
from app.services import clock, logreader
from app.services.text import iso

NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
DURATION_RE = re.compile(r"^(\d+)([mhd])$")
FILE_RE = re.compile(r"^syslog-(\d{1,3}(?:\.\d{1,3}){3})\.log(?:\.\d+)?$")
SOURCE_KEYS = {"name", "quiet_after"}
DEFAULT_TZ = "America/New_York"


class ConfigError(ValueError):
    pass


@dataclass
class Source:
    ip: str
    name: str
    quiet_after: timedelta | None = None


@dataclass
class Config:
    tz: ZoneInfo
    sources: dict[str, Source]  # by IP

    def by_name(self, name: str) -> Source | None:
        return next((s for s in self.sources.values() if s.name == name), None)


def _duration(value, where: str) -> timedelta:
    m = DURATION_RE.match(str(value))
    if not m:
        raise ConfigError(f"{where}: quiet_after must look like 15m, 24h or 2d")
    n = int(m.group(1))
    try:
        return timedelta(minutes=n) if m.group(2) == "m" else timedelta(hours=n) if m.group(2) == "h" else timedelta(days=n)
    except OverflowError:
        raise ConfigError(f"{where}: quiet_after is too large") from None


def parse(text: str) -> Config:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"not valid YAML: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError("expected a mapping with `tz` and `sources`")
    extra = set(data) - {"tz", "sources"}
    if extra:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(map(str, extra)))}")
    try:
        tz = ZoneInfo(str(data.get("tz", DEFAULT_TZ)))
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"unknown timezone {data.get('tz')!r}") from None
    raw = data.get("sources")
    if not isinstance(raw, dict) or not raw:
        raise ConfigError("`sources` must list at least one IP")
    sources: dict[str, Source] = {}
    names: set[str] = set()
    for key, body in raw.items():
        ip = str(key)
        where = f"source {ip}"
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            raise ConfigError(f"{where}: not an IPv4 address") from None
        if not isinstance(body, dict):
            raise ConfigError(f"{where}: expected a name")
        unknown = set(body) - SOURCE_KEYS
        if unknown:
            raise ConfigError(f"{where}: unknown keys {', '.join(sorted(map(str, unknown)))}")
        name = str(body.get("name", ""))
        if not NAME_RE.match(name):
            raise ConfigError(f"{where}: name must be 1-40 characters: letters, digits, '.', '_' or '-'")
        if name in names:
            raise ConfigError(f"{where}: the name {name!r} is used twice")
        names.add(name)
        sources[ip] = Source(ip, name, _duration(body["quiet_after"], where) if "quiet_after" in body else None)
    return Config(tz, sources)


_cache: dict = {"mtime": None, "config": None, "error": ""}


def get_config() -> tuple[Config | None, str]:
    """The current config and any error text. A config that stops parsing keeps the last good one."""
    try:
        mtime = CONFIG_PATH.stat().st_mtime_ns
    except OSError:
        return _cache["config"], f"{CONFIG_PATH} was not found"
    if mtime != _cache["mtime"]:
        _cache["mtime"] = mtime
        try:
            _cache["config"], _cache["error"] = parse(CONFIG_PATH.read_text()), ""
        except Exception as exc:  # noqa: BLE001 - a bad file (bad bytes, unreadable, absurd value) keeps the last good config
            _cache["error"] = str(exc) or type(exc).__name__
    return _cache["config"], _cache["error"]


def discover(directory: Path | None = None) -> dict[str, list[Path]]:
    """Every IP that has a file in the log folder, with its files (live file first, then rotated)."""
    directory = directory or LOG_DIR
    ips = set()
    try:
        for p in directory.iterdir():
            m = FILE_RE.match(p.name)
            if m:
                ips.add(m.group(1))
    except OSError:
        return {}
    return {ip: logreader.log_files(directory, ip) for ip in sorted(ips, key=lambda x: tuple(int(o) for o in x.split(".")))}


def status(ip: str, files: list[Path], source: Source | None, tz: ZoneInfo) -> dict:
    now = clock.now()
    last = logreader.last_line_time(files, now, tz)
    age = (now - last).total_seconds() if last else None
    recent = logreader.count_lines(files, now - timedelta(hours=1), now, tz)
    quiet = None
    if source is not None and source.quiet_after is not None:
        quiet = age is None or age > source.quiet_after.total_seconds()
    return {
        "ip": ip,
        "name": source.name if source else None,
        "mapped": source is not None,
        "last_seen": iso(last.astimezone(tz)) if last else None,
        "age_seconds": int(age) if age is not None else None,
        "quiet": quiet,
        "lines_last_hour": recent,
        "files": [p.name for p in files],
        "bytes": sum(p.stat().st_size for p in files if p.exists()),
    }


def all_statuses(config: Config) -> list[dict]:
    found = discover()
    out = [status(ip, found.get(ip, []), src, config.tz) for ip, src in config.sources.items()]
    out += [status(ip, files, None, config.tz) for ip, files in found.items() if ip not in config.sources]
    return out
