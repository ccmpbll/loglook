"""Which IP is which device.

`sources.yml` maps each source IP to a name and, optionally, how long silence is worth flagging. The
Sources page writes it (nobody has to edit it by hand, though a hand edit is picked up). It is re-read
when it changes; a file that stops parsing keeps the last good one in service and the error shows on
the Sources page. No file yet is an empty config. Files in the log folder with no entry are reported as
`unmapped`.
"""
import ipaddress
import os
import re
import threading
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
    data = {} if data is None else data  # an empty file is an empty config
    if not isinstance(data, dict):
        raise ConfigError("expected a mapping with `tz` and `sources`")
    extra = set(data) - {"tz", "sources"}
    if extra:
        raise ConfigError(f"unknown top-level keys: {', '.join(sorted(map(str, extra)))}")
    try:
        tz = ZoneInfo(str(data.get("tz", DEFAULT_TZ)))
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"unknown timezone {data.get('tz')!r}") from None
    raw = data.get("sources") or {}
    if not isinstance(raw, dict):
        raise ConfigError("`sources` must map each IP to a name")
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


def format_duration(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    return f"{minutes // 1440}d" if minutes % 1440 == 0 else f"{minutes // 60}h" if minutes % 60 == 0 else f"{minutes}m"


_cache: dict = {"stamp": None, "config": None, "error": ""}
_lock = threading.Lock()  # one edit at a time: each reads the file, changes it, writes it back


def get_config() -> tuple[Config | None, str]:
    """The current config and any error text. No file yet is an empty config; a file that stops
    parsing keeps the last good one."""
    try:
        st = CONFIG_PATH.stat()
    except FileNotFoundError:
        _cache.update(stamp=None, config=None, error="")
        return Config(ZoneInfo(DEFAULT_TZ), {}), ""
    except OSError as exc:
        return _cache["config"], f"{CONFIG_PATH}: {exc.strerror}"
    stamp = (st.st_mtime_ns, st.st_size)
    if stamp != _cache["stamp"]:
        _cache["stamp"] = stamp
        try:
            _cache["config"], _cache["error"] = parse(CONFIG_PATH.read_text()), ""
        except Exception as exc:  # noqa: BLE001 - a bad file (bad bytes, unreadable, absurd value) keeps the last good config
            _cache["error"] = str(exc) or type(exc).__name__
    return _cache["config"], _cache["error"]


def _edit(change) -> None:
    """Change the config as a plain dict, check the result like any file, and write it in one step.
    A file that does not parse is never overwritten: fix or delete it first."""
    with _lock:
        config, error = get_config()
        if error:
            raise ConfigError(f"sources.yml has a problem: {error}. Fix or delete it, then try again.")
        data = {"tz": config.tz.key, "sources": {ip: {"name": s.name, **({"quiet_after": format_duration(s.quiet_after)} if s.quiet_after else {})} for ip, s in config.sources.items()}}
        change(data)
        text = yaml.safe_dump(data, sort_keys=False)
        parse(text)  # the same checks as a hand-written file
        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        tmp.write_text(text)
        os.replace(tmp, CONFIG_PATH)


def _entry(name: str, quiet_after: str) -> dict:
    return {"name": name.strip(), **({"quiet_after": quiet_after.strip()} if quiet_after.strip() else {})}


def add(ip: str, name: str, quiet_after: str = "") -> None:
    ip = ip.strip()

    def change(data):
        if ip in data["sources"]:
            raise ConfigError(f"{ip} already has a name")
        data["sources"][ip] = _entry(name, quiet_after)

    _edit(change)


def update(ip: str, name: str, quiet_after: str = "") -> None:
    def change(data):
        if ip not in data["sources"]:
            raise ConfigError(f"{ip} is not a named source")
        data["sources"][ip] = _entry(name, quiet_after)

    _edit(change)


def remove(ip: str) -> None:
    _edit(lambda data: data["sources"].pop(ip, None))


def set_timezone(tz: str) -> None:
    _edit(lambda data: data.update(tz=tz.strip()))


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
        "quiet_after": format_duration(source.quiet_after) if source and source.quiet_after else "",
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
