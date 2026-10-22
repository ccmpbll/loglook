"""The three ways to look at a source's lines: the lines themselves, grouped patterns, and counts
per captured value. All read-only, all bounded in lines, bytes and time.

Every query shares one window (`hours` long, ending `ago` hours before now) and one filter
(`q` literal text, `include` and `exclude` regular expressions)."""
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path

import regex as regex_module

from app.services import clock, logreader
from app.services.sources import Config
from app.services.text import clean, iso, normalize, strip_control

MAX_HOURS = 24 * 14
MAX_AGO = 24 * 90
LINES_MAX = 500
LINES_MAX_BYTES = 64 * 1024
LINE_CHARS = 500
REGEX_BUDGET = 0.25  # seconds one pattern may spend on one line
BUDGET_SECONDS = 15  # seconds one query may run
MAX_KEYS = 5000  # distinct patterns or values kept; past this, new ones are only counted as overflow


class QueryError(ValueError):
    pass


def compile_regex(pattern: str, what: str):
    if len(pattern) > 300:
        raise QueryError(f"{what} is at most 300 characters")
    try:
        return regex_module.compile(pattern)
    except regex_module.error as exc:
        raise QueryError(f"{what} is not a valid regular expression: {exc}") from None


class Filter:
    """Which lines count: contains `q` (any case), matches `include`, does not match `exclude`."""

    def __init__(self, q: str = "", include: str = "", exclude: str = ""):
        if len(q) > 200:
            raise QueryError("q is at most 200 characters")
        self.q = q.lower()
        self.include = compile_regex(include, "include") if include else None
        self.exclude = compile_regex(exclude, "exclude") if exclude else None

    def __call__(self, text: str) -> bool:
        try:
            if self.q and self.q not in text.lower():
                return False
            if self.include is not None and self.include.search(text, timeout=REGEX_BUDGET) is None:
                return False
            if self.exclude is not None and self.exclude.search(text, timeout=REGEX_BUDGET) is not None:
                return False
        except TimeoutError:
            raise QueryError("that pattern is too slow on this log; make it simpler") from None
        return True


class Scan:
    """One pass over the window, handing back the lines that pass the filter and keeping the totals."""

    def __init__(self, config: Config, files: list[Path], hours: float, ago: float, flt: Filter):
        self.config, self.files, self.flt = config, files, flt
        self.now = clock.now()
        self.end = self.now - timedelta(hours=ago)
        self.start = self.end - timedelta(hours=hours)
        self.hours, self.ago = hours, ago
        self.scanned = self.matched = 0
        self.stats = logreader.ReadStats()
        self.timed_out = False

    def lines(self):
        deadline = time.monotonic() + BUDGET_SECONDS
        for line in logreader.read_window(self.files, self.start, self.end, self.now, self.config.tz, self.stats):
            self.scanned += 1
            if self.flt(line.text):
                self.matched += 1
                yield line
            if time.monotonic() > deadline:  # every line: a slow pattern can spend REGEX_BUDGET on each one
                self.timed_out = True
                return

    @property
    def truncated(self) -> bool:
        return self.stats.truncated or self.timed_out

    def header(self) -> dict:
        tz = self.config.tz
        return {
            "window": {"start": iso(self.start.astimezone(tz)), "end": iso(self.end.astimezone(tz)), "hours": self.hours, "ago": self.ago},
            "scanned": self.scanned,
            "matched": self.matched,
            "unparsed": self.stats.unparsed,
            "files": self.stats.files,
        }


def lines(config: Config, source: str, files: list[Path], hours: float, ago: float, flt: Filter, limit: int) -> dict:
    """The most recent `limit` matching lines, oldest first. Cut by count and by total bytes."""
    limit = max(1, min(limit, LINES_MAX))
    scan = Scan(config, files, hours, ago, flt)
    kept: deque = deque(maxlen=limit)
    for line in scan.lines():
        kept.append(line)
    out, size, cut = [], 0, False
    for line in reversed(kept):  # newest first while the byte budget lasts
        item = {"time": iso(line.ts.astimezone(config.tz)), "host": clean(line.host, 100), "text": clean(line.text, LINE_CHARS)}
        size += len(item["text"]) + 60
        if size > LINES_MAX_BYTES:
            cut = True
            break
        out.append(item)
    out.reverse()
    return {"source": source, **scan.header(), "returned": len(out), "truncated": cut or scan.matched > len(out) or scan.truncated, "lines": out}


def top(config: Config, source: str, files: list[Path], hours: float, ago: float, flt: Filter, n: int) -> dict:
    """Matching lines normalised (MACs, IPs, hex and numbers replaced) and grouped, biggest first."""
    scan = Scan(config, files, hours, ago, flt)
    groups: dict[str, list] = {}  # key -> [count, first, last, example]
    overflow = 0
    for line in scan.lines():
        key = normalize(strip_control(line.text))
        g = groups.get(key)
        if g is None:
            if len(groups) >= MAX_KEYS:
                overflow += 1
            else:
                groups[key] = [1, line.ts, line.ts, clean(line.text)]
        else:
            g[0] += 1
            g[2] = line.ts
    ranked = sorted(groups.items(), key=lambda kv: -kv[1][0])[:n]
    tz = config.tz
    return {
        "source": source,
        **scan.header(),
        "patterns": len(groups),
        "overflow": overflow,
        "truncated": scan.truncated,
        "top": [{"pattern": k, "count": g[0], "first": iso(g[1].astimezone(tz)), "last": iso(g[2].astimezone(tz)), "example": g[3]} for k, g in ranked],
    }


def count(config: Config, source: str, files: list[Path], hours: float, ago: float, flt: Filter, pattern: str, n: int) -> dict:
    """Count matches of `pattern` per captured value. With one group the value is what it captured
    (for example a MAC); with several they are joined by a space; with none everything counts as one."""
    if not pattern:
        raise QueryError("pattern is required")
    rx = compile_regex(pattern, "pattern")
    scan = Scan(config, files, hours, ago, flt)
    counts: Counter = Counter()
    counted = overflow = 0
    for line in scan.lines():
        try:
            m = rx.search(line.text, timeout=REGEX_BUDGET)
        except TimeoutError:
            raise QueryError("that pattern is too slow on this log; make it simpler") from None
        if m is None:
            continue
        counted += 1
        key = clean(" ".join(g for g in m.groups() if g is not None), LINE_CHARS) if rx.groups else ""
        if key in counts or len(counts) < MAX_KEYS:
            counts[key] += 1
        else:
            overflow += 1
    return {
        "source": source,
        **scan.header(),
        "pattern": pattern,
        "counted": counted,
        "distinct": len(counts),
        "overflow": overflow,
        "truncated": scan.truncated,
        "top": [{"value": k, "count": c} for k, c in counts.most_common(n)],
    }
