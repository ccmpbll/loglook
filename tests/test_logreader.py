"""Self-check for reading syslog files by time.

  1. Lines parse from the real formats seen on Gandalf: pfSense, the switch (an extra embedded date),
     the AP, Tasmota; the year is inferred and December lines read in January belong to last year.
  2. A window is found from line timestamps, across the live file and rotated copies, with the scan
     backwards done in tiny chunks to exercise it; a quiet source that never rotates still works.
  3. Reads are bounded, and "last seen" comes from the newest readable line.

Run directly: python3 tests/test_logreader.py
"""
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fixtures as fx  # noqa: E402

data, logs, cfg = fx.make_env()

from app.services import logreader as lr  # noqa: E402

TZ, NOW, LOCAL_NOW = fx.TZ, fx.NOW, fx.LOCAL_NOW


def test_parse():
    cases = {
        b"Oct 22 10:24:15 10.42.11.5 mping[21025]: Target default gateway 10.42.11.1 via br0": ("10.42.11.5", "mping[21025]: Target default gateway 10.42.11.1 via br0"),
        b"Oct 13 18:05:11 10.42.11.2 13/10/2026 18:05:10 Port 23 link down": ("10.42.11.2", "13/10/2026 18:05:10 Port 23 link down"),
        b"Oct 22 10:22:25 ecthelion.cmpbll.casa syslogd restart": ("ecthelion.cmpbll.casa", "syslogd restart"),
        b"Oct  2 09:00:00 EZPlug-rack-2522 ESP-MQT: tele/EZPlug_rack/STATE = {}": ("EZPlug-rack-2522", "ESP-MQT: tele/EZPlug_rack/STATE = {}"),
    }
    for raw, (host, text) in cases.items():
        line = lr.parse_line(raw, NOW, TZ)
        assert line and line.host == host and line.text == text, raw
        assert line.ts.tzinfo is not None
    assert lr.parse_line(b"Oct 22 10:24:15 10.42.11.5 x", NOW, TZ).ts == datetime(2026, 10, 22, 10, 24, 15, tzinfo=TZ), "read as local time"
    for bad in (b"garbage", b"", b"Foo 22 10:24:15 h x", b"Feb 30 10:00:00 h x", b"Oct 22 25:00:00 h x", b"Oct 22 10:24:15"):
        assert lr.parse_line(bad, NOW, TZ) is None, bad
    jan = datetime(2027, 1, 2, 12, 0, tzinfo=timezone.utc)
    assert lr.parse_line(b"Dec 31 23:59:59 h x", jan, TZ).ts.year == 2026, "a December line read in January is last year's"
    assert lr.parse_line(b"Jan 02 07:00:00 h x", jan, TZ).ts.year == 2027
    assert lr.parse_line(b"Feb 29 12:00:00 h x", NOW, TZ) is None, "no Feb 29 in 2026"


def write_series(path, start, n, step_seconds, host="10.0.0.9"):
    fx.write(path, [(start + timedelta(seconds=step_seconds * i), host, f"prog[1]: event {i}") for i in range(n)])


def test_windows_across_rotation():
    d = logs / "series"
    d.mkdir()
    lr.CHUNK = 300  # tiny chunks, so the backwards scan crosses many boundaries
    try:
        base = datetime(2026, 10, 20, 0, 0, tzinfo=TZ)
        write_series(d / "syslog-10.0.0.9.log.2", base - timedelta(hours=20), 600, 60)  # older again
        write_series(d / "syslog-10.0.0.9.log.1", base, 1000, 60)
        write_series(d / "syslog-10.0.0.9.log", base + timedelta(seconds=60 * 1000), 1500, 60)
        files = lr.log_files(d, "10.0.0.9")
        assert [p.name for p in files] == ["syslog-10.0.0.9.log", "syslog-10.0.0.9.log.1", "syslog-10.0.0.9.log.2"], "live first, then rotated by number"
        end = LOCAL_NOW
        everything = [base - timedelta(hours=20) + timedelta(seconds=60 * i) for i in range(600)] + [base + timedelta(seconds=60 * i) for i in range(2500)]
        for hours in (1, 6, 24, 40, 60, 100):
            stats = lr.ReadStats()
            got = list(lr.read_window(files, end - timedelta(hours=hours), end, NOW, TZ, stats))
            want = [t for t in everything if end - timedelta(hours=hours) <= t <= end]
            assert [g.ts for g in got] == want, f"{hours} h: {len(got)} lines, wanted {len(want)}"
        # a window that ends before now (an earlier day), crossing from the live file into .1
        stats = lr.ReadStats()
        got = list(lr.read_window(files, end - timedelta(hours=48), end - timedelta(hours=24), NOW, TZ, stats))
        want = [t for t in everything if end - timedelta(hours=48) <= t <= end - timedelta(hours=24)]
        assert [g.ts for g in got] == want and want
        # only the files the window needs are read
        stats = lr.ReadStats()
        list(lr.read_window(files, end - timedelta(hours=2), end, NOW, TZ, stats))
        assert stats.files == ["syslog-10.0.0.9.log"], stats.files
    finally:
        lr.CHUNK = 256 * 1024


def test_a_quiet_source_that_never_rotates():
    sw = logs / "syslog-10.42.11.2.log"
    fx.build_logs(logs)
    lines = list(lr.read_window([sw], LOCAL_NOW - timedelta(days=30), LOCAL_NOW, NOW, TZ))
    assert len(lines) == 5 + 6, "the five October 13 events and today's flap"
    recent = list(lr.read_window([sw], LOCAL_NOW - timedelta(hours=24), LOCAL_NOW, NOW, TZ))
    assert len(recent) == 6 and all("Port 7" in l.text for l in recent), "an old event is not recent just because it is in the live file"
    assert lr.last_line_time([sw], NOW, TZ) > LOCAL_NOW - timedelta(hours=4)


def test_empty_missing_and_junk():
    empty = logs / "syslog-10.1.1.1.log"
    empty.write_text("")
    assert list(lr.read_window([empty], LOCAL_NOW - timedelta(hours=1), LOCAL_NOW, NOW, TZ)) == []
    assert lr.last_line_time([empty], NOW, TZ) is None
    assert list(lr.read_window([logs / "nope.log"], LOCAL_NOW - timedelta(hours=1), LOCAL_NOW, NOW, TZ)) == []
    junk = logs / "syslog-10.1.1.2.log"
    junk.write_bytes(b"\xff\xfe not syslog\n" + f"{fx.stamp(LOCAL_NOW - timedelta(minutes=5))} h ok \xe9\xe8 text\n".encode("latin-1") + b"continuation line\n")
    stats = lr.ReadStats()
    got = list(lr.read_window([junk], LOCAL_NOW - timedelta(hours=1), LOCAL_NOW, NOW, TZ, stats))
    assert len(got) == 1 and stats.unparsed == 2 and "text" in got[0].text, "bad bytes and continuation lines are skipped, not fatal"


def test_a_line_out_of_order_does_not_leak_into_the_window():
    f = logs / "syslog-10.1.1.4.log"
    rows = [(LOCAL_NOW - timedelta(hours=5), "h", "old but first"), (LOCAL_NOW - timedelta(hours=1), "h", "in window"), (LOCAL_NOW - timedelta(hours=9), "h", "clock jumped back"), (LOCAL_NOW - timedelta(minutes=10), "h", "also in window")]
    with open(f, "w") as fh:  # written in this order on purpose, not sorted
        for t, host, text in rows:
            fh.write(f"{fx.stamp(t)} {host} {text}\n")
    got = [l.text for l in lr.read_window([f], LOCAL_NOW - timedelta(hours=2), LOCAL_NOW, NOW, TZ)]
    assert got == ["in window", "also in window"], got


def test_reads_are_bounded():
    big = logs / "syslog-10.1.1.3.log"
    write_series(big, LOCAL_NOW - timedelta(hours=5), 600, 10, "10.1.1.3")
    old = lr.MAX_LINES
    lr.MAX_LINES = 100
    try:
        stats = lr.ReadStats()
        got = list(lr.read_window([big], LOCAL_NOW - timedelta(hours=5), LOCAL_NOW, NOW, TZ, stats))
        assert len(got) == 100 and stats.truncated
    finally:
        lr.MAX_LINES = old


def main():
    test_parse()
    test_windows_across_rotation()
    test_a_quiet_source_that_never_rotates()
    test_empty_missing_and_junk()
    test_a_line_out_of_order_does_not_leak_into_the_window()
    test_reads_are_bounded()
    print("OK: syslog lines parse, and windows are found by timestamp across rotated files.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(data.parent, ignore_errors=True)
