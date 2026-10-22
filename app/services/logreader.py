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
WRAP = timedelta(days=180)  # a line this much earlier or later than its neighbour is a year boundary, not clock jitter
MAX_LATE = 1000  # consecutive lines after the window's end before reading stops
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


def parse_line(raw: bytes, now: datetime, tz: ZoneInfo, year: int | None = None) -> Line | None:
    """`year` is given when the file's own order has settled it; otherwise it is guessed from `now`."""
    m = LINE_RE.match(raw.rstrip(b"\r\n"))
    if m is None:
        return None
    month = MONTHS.get(m.group(1).decode("ascii", "replace"))
    if month is None:
        return None
    local_now = now.astimezone(tz)
    try:
        ts = datetime(year or local_now.year, month, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=tz)
        if year is None and ts > now + timedelta(days=1):  # December lines read in January
            ts = ts.replace(year=local_now.year - 1)
    except ValueError:  # Feb 30, hour 25, a Feb 29 in a non-leap year
        return None
    return Line(ts=ts, host=m.group(6).decode("utf-8", "replace"), text=m.group(7).decode("utf-8", "replace"))


def _year_before(ts: datetime, ceiling: datetime) -> datetime | None:
    """Walking backwards through a file, a line that reads as much later than the one after it
    belongs to the year before (a file that never rotates can hold more than a year of lines)."""
    while ts - ceiling > WRAP:
        try:
            ts = ts.replace(year=ts.year - 1)
        except ValueError:  # Feb 29
            return None
    return ts


def _start_offset(path: Path, cutoff: datetime, now: datetime, tz: ZoneInfo) -> tuple[int, bool, datetime | None]:
    """Byte offset of the first line at or after `cutoff`, whether the window reaches back past the
    start of this file (so an older file may hold part of it too), and the time of the line at the
    offset (which settles the year for reading forward from there)."""
    size = path.stat().st_size
    if size == 0:  # a file just rotated: it says nothing about older lines
        return 0, True, None
    with path.open("rb") as f:
        end = size
        ceiling = None  # the earliest line seen so far, from the later chunks
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
            later, fixed = ceiling, []
            for off, ts in reversed(parsed):
                if later is not None:
                    ts = _year_before(ts, later)
                    if ts is None:
                        continue
                fixed.append((off, ts))
                if later is None or ts >= later - WRAP:  # a wild early line must not drag the rest back
                    later = ts
            fixed.reverse()
            if not fixed:  # nothing readable in this chunk: look earlier
                if start == 0:
                    return 0, True, ceiling
                end = start
                continue
            if fixed[0][1] >= cutoff:
                if start == 0:
                    return 0, True, fixed[0][1]  # the whole file is inside the window
                ceiling = later
                end = start + first  # look earlier; the partial line is read again there
                continue
            for off, ts in fixed:
                if ts >= cutoff:
                    return start + off, False, ts
            return end, False, ceiling  # everything in this chunk is older: the window begins at its end
    return 0, True, ceiling


def log_files(directory: Path, ip: str) -> list[Path]:
    """The live file first, then rotated copies newest to oldest: syslog-<ip>.log, .log.1, .log.2 ..."""
    live = directory / f"syslog-{ip}.log"
    rotated = []
    for p in directory.glob(f"syslog-{ip}.log.*"):
        suffix = p.name.rsplit(".", 1)[-1]
        if suffix.isdigit():
            rotated.append((int(suffix), p))
    return ([live] if live.is_file() else []) + [p for _, p in sorted(rotated)]


def _plan(files: list[Path], start: datetime, now: datetime, tz: ZoneInfo) -> list[tuple[Path, int, datetime | None]]:
    """The files a window needs, oldest first, each with where to start reading and the time there."""
    plan = []
    for path in files:
        try:
            offset, reaches_older, anchor = _start_offset(path, start, now, tz)
        except OSError:
            continue
        plan.append((path, offset, anchor))
        if not reaches_older:
            break
    plan.reverse()
    return plan


def _stream(f, anchor: datetime | None, now: datetime, tz: ZoneInfo) -> Iterator[Line | None]:
    """Every line from here on, or None for one that is not readable. When the offset's time is
    known the year is carried forward and bumped when the months wrap round."""
    year = anchor.year if anchor else None
    prev = anchor
    for raw in f:
        line = parse_line(raw, now, tz, year)
        if line is not None and prev is not None and prev - line.ts > WRAP:  # December, then January
            try:
                line.ts = line.ts.replace(year=line.ts.year + 1)
            except ValueError:
                line = None
            else:
                if line.ts > now + timedelta(days=1):  # not a new year, a wild clock
                    line = None
                else:
                    year = line.ts.year
        if line is not None and (prev is None or line.ts >= prev - WRAP):
            prev = line.ts
        yield line


def read_window(files: list[Path], start: datetime, end: datetime, now: datetime, tz: ZoneInfo, stats: ReadStats | None = None) -> Iterator[Line]:
    """Lines with start <= time <= end, oldest first, across `files` (newest file first)."""
    stats = stats if stats is not None else ReadStats()
    late = 0  # lines in a row after `end`; one with a fast clock must not end the read
    for path, offset, anchor in _plan(files, start, now, tz):
        stats.files.append(path.name)
        try:
            f = path.open("rb")
        except OSError:
            continue
        with f:
            f.seek(offset)
            for line in _stream(f, anchor, now, tz):
                if stats.scanned >= MAX_LINES:
                    stats.truncated = True
                    return
                stats.scanned += 1
                if line is None:
                    stats.unparsed += 1
                    continue
                if line.ts < start:
                    continue
                if line.ts > end:
                    late += 1
                    if late >= MAX_LATE:
                        return
                    continue
                late = 0
                yield line


def count_lines(files: list[Path], start: datetime, now: datetime, tz: ZoneInfo) -> int:
    """How many lines the window holds, counted without parsing them (up to now, for a quick status)."""
    total = 0
    for path, offset, _ in _plan(files, start, now, tz):
        try:
            with path.open("rb") as f:
                f.seek(offset)
                while chunk := f.read(1 << 20):
                    total += chunk.count(b"\n")
        except OSError:
            continue
    return total


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
