"""Reading syslog files by time, not by file age.

Unraid writes one file per source IP and rotates by size, so a quiet device (the switch) keeps
months of lines in one file while a chatty one rotates every couple of weeks. A window of "the last
24 hours" therefore has to be found from the timestamp on each line, across the live file and the
rotated copies, without reading whole files: seek to where the window starts, then stream forward.

Syslog lines carry no year and no timezone: the year is inferred and the time is read as local
time in the configured zone.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator
from zoneinfo import ZoneInfo

CHUNK = 256 * 1024
MAX_LINES = 3_000_000  # most lines one read will look at, so a huge window cannot run away
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
LINE_RE = re.compile(rb"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) (.*)$", re.S)


@dataclass(slots=True)
class Line:
    ts: datetime  # timezone-aware
    host: str
    text: str  # everything after the host: the tag, the message and any extra timestamp


@dataclass
class ReadStats:
    scanned: int = 0
    unparsed: int = 0
    truncated: bool = False
    files: list[str] = field(default_factory=list)


def parse_line(raw: bytes, now: datetime, tz: ZoneInfo) -> Line | None:
    m = LINE_RE.match(raw.rstrip(b"\r\n"))
    if m is None:
        return None
    month = MONTHS.get(m.group(1).decode("ascii", "replace"))
    if month is None:
        return None
    local_now = now.astimezone(tz)
    try:
        ts = datetime(local_now.year, month, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=tz)
        if ts > now + timedelta(days=1):  # December lines read in January
            ts = ts.replace(year=local_now.year - 1)
    except ValueError:  # Feb 30, hour 25, a Feb 29 in a non-leap year
        return None
    return Line(ts=ts, host=m.group(6).decode("utf-8", "replace"), text=m.group(7).decode("utf-8", "replace"))


def _start_offset(path: Path, cutoff: datetime, now: datetime, tz: ZoneInfo) -> tuple[int, bool]:
    """Byte offset of the first line at or after `cutoff`, and whether the window reaches back past
    the start of this file (so an older file may hold part of it too)."""
    size = path.stat().st_size
    if size == 0:
        return 0, False
    with path.open("rb") as f:
        end = size
        while end > 0:
            start = max(0, end - CHUNK)
            f.seek(start)
            data = f.read(end - start)
            first = 0
            if start > 0:  # the chunk begins mid-line: skip to the first whole line
                nl = data.find(b"\n")
                if nl == -1:
                    end = start
                    continue
                first = nl + 1
            offset = first
            parsed = []  # (offset, ts) of the parseable lines in this chunk, in order
            for raw in data[first:].split(b"\n"):
                line = parse_line(raw, now, tz)
                if line is not None:
                    parsed.append((offset, line.ts))
                offset += len(raw) + 1
            if not parsed:  # nothing readable in this chunk: look earlier
                if start == 0:
                    return 0, True
                end = start
                continue
            if parsed[0][1] >= cutoff:
                if start == 0:
                    return 0, True  # the whole file is inside the window
                end = start + first  # look earlier; the partial line is read again there
                continue
            for off, ts in parsed:
                if ts >= cutoff:
                    return start + off, False
            return end, False  # everything in this chunk is older: the window begins at its end
    return 0, True


def log_files(directory: Path, ip: str) -> list[Path]:
    """The live file first, then rotated copies newest to oldest: syslog-<ip>.log, .log.1, .log.2 ..."""
    live = directory / f"syslog-{ip}.log"
    rotated = []
    for p in directory.glob(f"syslog-{ip}.log.*"):
        suffix = p.name.rsplit(".", 1)[-1]
        if suffix.isdigit():
            rotated.append((int(suffix), p))
    return ([live] if live.is_file() else []) + [p for _, p in sorted(rotated)]


def read_window(files: list[Path], start: datetime, end: datetime, now: datetime, tz: ZoneInfo, stats: ReadStats | None = None) -> Iterator[Line]:
    """Lines with start <= time <= end, oldest first, across `files` (newest file first)."""
    stats = stats if stats is not None else ReadStats()
    plan: list[tuple[Path, int]] = []
    for path in files:
        try:
            offset, reaches_older = _start_offset(path, start, now, tz)
        except OSError:
            continue
        plan.append((path, offset))
        if not reaches_older:
            break
    for path, offset in reversed(plan):
        stats.files.append(path.name)
        try:
            f = path.open("rb")
        except OSError:
            continue
        with f:
            f.seek(offset)
            for raw in f:
                if stats.scanned >= MAX_LINES:
                    stats.truncated = True
                    return
                stats.scanned += 1
                line = parse_line(raw, now, tz)
                if line is None:
                    stats.unparsed += 1
                    continue
                if line.ts < start:
                    continue
                if line.ts > end:
                    return
                yield line


def last_line_time(files: list[Path], now: datetime, tz: ZoneInfo) -> datetime | None:
    """When the source last wrote anything: the last parseable line of the newest non-empty file."""
    for path in files:
        try:
            size = path.stat().st_size
            if size == 0:
                continue
            with path.open("rb") as f:
                f.seek(max(0, size - 65536))
                tail = f.read()
        except OSError:
            continue
        for raw in reversed(tail.split(b"\n")):
            line = parse_line(raw, now, tz)
            if line is not None:
                return line.ts
    return None
