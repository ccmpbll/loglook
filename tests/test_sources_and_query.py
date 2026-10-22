"""Self-check for sources.yml and the three queries (lines, top, count).

  1. sources.yml: valid and invalid files, unknown keys, duplicate names, bad durations and zones;
     a file that stops parsing keeps the last good one in service; unmapped and quiet sources show.
  2. lines: the most recent matches, literal text, include and exclude, windows that end earlier,
     bounded in count and bytes, control characters stripped, slow regexes refused.
  3. top: near-identical lines collapse (MACs, IPs, hex, numbers), counts and examples.
  4. count: per captured value, the busy station stands out, days compare with `ago`.

Run directly: python3 tests/test_sources_and_query.py
"""
import shutil
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fixtures as fx  # noqa: E402

data, logs, cfg = fx.make_env()

from app.services import clock, query, sources  # noqa: E402

clock.now = lambda: fx.NOW
cfg.write_text(fx.SOURCES_YML)
fx.build_logs(logs)


def raises(fn, contains):
    try:
        fn()
    except (sources.ConfigError, query.QueryError) as exc:
        assert contains in str(exc), f"{contains!r} not in {exc}"
        return
    raise AssertionError(f"accepted, expected {contains!r}")


def test_config_parse():
    c = sources.parse(fx.SOURCES_YML)
    assert c.by_name("ruckus-ap").ip == "10.42.11.5" and c.by_name("ruckus-ap").quiet_after == timedelta(minutes=15)
    assert c.by_name("pfsense").quiet_after == timedelta(hours=24) and c.by_name("switch").quiet_after is None
    assert sources.parse("sources:\n  1.2.3.4: {name: a, quiet_after: 2d}\n").sources["1.2.3.4"].quiet_after == timedelta(days=2)
    raises(lambda: sources.parse("not: [valid"), "not valid YAML")
    raises(lambda: sources.parse("- a\n- b\n"), "expected a mapping")
    raises(lambda: sources.parse("tz: Mars/Base\nsources:\n  1.2.3.4: {name: a}\n"), "unknown timezone")
    raises(lambda: sources.parse("sources: {}\n"), "at least one")
    raises(lambda: sources.parse("sources:\n  nope: {name: a}\n"), "not an IPv4")
    raises(lambda: sources.parse("sources:\n  1.2.3.4: {name: 'bad name!'}\n"), "name must be")
    raises(lambda: sources.parse("sources:\n  1.2.3.4: {name: a}\n  1.2.3.5: {name: a}\n"), "used twice")
    raises(lambda: sources.parse("sources:\n  1.2.3.4: {name: a, quiet_after: soon}\n"), "quiet_after")
    raises(lambda: sources.parse("sources:\n  1.2.3.4: {name: a, ignore: [x]}\n"), "unknown keys")
    raises(lambda: sources.parse("tz: UTC\nextra: 1\nsources:\n  1.2.3.4: {name: a}\n"), "unknown top-level")


def test_config_reload_keeps_last_good():
    c1, err = sources.get_config()
    assert c1 and not err
    time.sleep(0.01)
    cfg.write_text("sources: [broken\n")
    c2, err = sources.get_config()
    assert c2 is c1 and "not valid YAML" in err, "a bad edit keeps the last good config and says why"
    time.sleep(0.01)
    cfg.write_text(fx.SOURCES_YML.replace("ruckus-ap", "ap"))
    c3, err = sources.get_config()
    assert not err and c3.by_name("ap") and not c3.by_name("ruckus-ap")
    time.sleep(0.01)
    cfg.write_text(fx.SOURCES_YML)
    sources.get_config()


def test_status_unmapped_and_quiet():
    config, _ = sources.get_config()
    by_ip = {s["ip"]: s for s in sources.all_statuses(config)}
    assert by_ip["10.42.11.99"]["mapped"] is False and by_ip["10.42.11.99"]["name"] is None, "a file with no entry is unmapped"
    assert by_ip["10.42.11.77"]["quiet"] is True and by_ip["10.42.11.77"]["last_seen"], "last wrote 30 hours ago, allowed 1"
    assert by_ip["10.42.11.5"]["quiet"] is False and by_ip["10.42.11.5"]["lines_last_hour"] > 10
    assert by_ip["10.42.11.1"]["quiet"] is False and by_ip["10.42.11.2"]["quiet"] is None, "no threshold, no quiet flag"
    assert by_ip["10.42.11.5"]["files"] == ["syslog-10.42.11.5.log", "syslog-10.42.11.5.log.1"]
    assert "10.42.11.5" in by_ip and sources.discover()["10.42.11.5"][0].name == "syslog-10.42.11.5.log"
    assert not any(ip == "10.1.1.9" for ip in by_ip), "only IPs from file names or the config"
    (logs / "syslog-not-an-ip.log").write_text("x")
    assert "not-an-ip" not in str(sources.discover()), "odd file names are ignored"


def files_of(name):
    config, _ = sources.get_config()
    src = config.by_name(name)
    return config, src, sources.discover().get(src.ip, [])


def test_lines():
    config, src, files = files_of("ruckus-ap")
    r = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter("status=fail"), 100)
    assert r["matched"] == 1 and r["lines"][0]["text"].startswith("mping[21025]: status=fail"), r
    r = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter("STATUS=FAIL"), 100)
    assert r["matched"] == 1, "q is a literal, any case"
    r = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter(include=r"No free worker"), 100)
    assert r["matched"] == 1
    r = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter(q="disassociated", exclude=fx.MAC_BUSY), 100)
    assert r["matched"] == 5 and all(fx.MAC_QUIET in l["text"] for l in r["lines"]), "exclude removes the busy station"
    r = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter("disassociated"), 10)
    assert r["returned"] == 10 and r["truncated"] and r["matched"] == 505, "the most recent N, and it says so"
    times = [l["time"] for l in r["lines"]]
    assert times == sorted(times), "oldest first within the returned lines"
    huge = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter("disassociated"), 100000)
    assert huge["returned"] <= query.LINES_MAX, "a limit above the cap is clamped, not honoured"
    assert query.lines(config, "ruckus-ap", files, 24, 0, query.Filter("disassociated"), 0)["returned"] == 1, "a limit of zero still returns one line"
    older = query.lines(config, "ruckus-ap", files, 24, 24, query.Filter("disassociated"), 500)
    assert older["matched"] > 0 and older["window"]["ago"] == 24 and older["window"]["start"] < r["window"]["start"], "ago steps back a day"
    assert query.lines(config, "ruckus-ap", files, 1, 0, query.Filter(q="nothing like this"), 5)["lines"] == []
    # the bytes cap
    old = query.LINES_MAX_BYTES
    query.LINES_MAX_BYTES = 1000
    try:
        r = query.lines(config, "ruckus-ap", files, 24, 0, query.Filter("disassociated"), 500)
        assert r["returned"] < 20 and r["truncated"]
    finally:
        query.LINES_MAX_BYTES = old
    # bad and slow patterns
    raises(lambda: query.Filter(include="("), "include is not a valid")
    raises(lambda: query.Filter(exclude="x" * 301), "at most 300")
    raises(lambda: query.Filter(q="x" * 201), "at most 200")
    saved = query.REGEX_BUDGET
    query.REGEX_BUDGET = 0.05
    try:
        slow = query.Filter(include=r"(a|aa)+$")
        (logs / "syslog-10.9.9.9.log").write_text(f"{fx.stamp(fx.LOCAL_NOW - timedelta(minutes=1))} h {'a' * 60}b\n")
        c = sources.parse("sources:\n  10.9.9.9: {name: slowbox}\n")
        raises(lambda: query.lines(c, "slowbox", sources.discover()["10.9.9.9"], 1, 0, slow, 5), "too slow")
    finally:
        query.REGEX_BUDGET = saved


def test_control_characters_and_markup_in_log_text_are_returned_clean():
    (logs / "syslog-10.9.9.8.log").write_text(f"{fx.stamp(fx.LOCAL_NOW - timedelta(minutes=1))} h bell\x07 esc\x1b[31m red <script>alert(1)</script>\n")
    c = sources.parse("sources:\n  10.9.9.8: {name: nasty}\n")
    r = query.lines(c, "nasty", sources.discover()["10.9.9.8"], 1, 0, query.Filter(), 5)
    text = r["lines"][0]["text"]
    assert "\x07" not in text and "\x1b" not in text and "<script>" in text, "control characters go; markup is left for the page to escape"


def test_top():
    config, src, files = files_of("ruckus-ap")
    r = query.top(config, "ruckus-ap", files, 24, 0, query.Filter(), 5)
    assert r["top"][0]["count"] == 505 and "<mac>" in r["top"][0]["pattern"], "both stations are one pattern: that is what count is for"
    assert "STA " in r["top"][0]["example"] and "<mac>" not in r["top"][0]["example"], "an example keeps the real values"
    patterns = {t["pattern"] for t in r["top"]}
    assert any("status=succ result=#" in p for p in patterns), "numbers are normalised, so 200 lines are one pattern"
    r = query.top(config, "ruckus-ap", files, 24, 0, query.Filter(exclude=r"disassociated|status=succ|LogoutAdmin"), 5)
    assert {t["pattern"].split(":")[0] for t in r["top"]} == {"mping[#]", "appweb"}, r["top"]
    pf = files_of("pfsense")
    r = query.top(pf[0], "pfsense", pf[2], 24, 0, query.Filter(), 10)
    assert any(t["pattern"].startswith("/usr/sbin/cron[#]") and t["count"] == 6 for t in r["top"]), "the cron noise is one row of 6"
    old = query.MAX_KEYS
    query.MAX_KEYS = 3
    try:
        r = query.top(config, "ruckus-ap", files, 24, 0, query.Filter(), 10)
        assert r["patterns"] == 3 and r["overflow"] > 0, "distinct patterns are capped; the rest are counted as overflow"
    finally:
        query.MAX_KEYS = old


def test_count():
    config, src, files = files_of("ruckus-ap")
    pat = r"STA ([0-9a-f:]{17}) IEEE 802\.11: disassociated"
    today = query.count(config, "ruckus-ap", files, 24, 0, query.Filter(), pat, 10)
    assert today["top"][0] == {"value": fx.MAC_BUSY, "count": 500} and today["top"][1] == {"value": fx.MAC_QUIET, "count": 5}, today
    assert today["counted"] == 505 and today["distinct"] == 2
    yesterday = query.count(config, "ruckus-ap", files, 24, 24, query.Filter(), pat, 10)
    day_before = query.count(config, "ruckus-ap", files, 24, 48, query.Filter(), pat, 10)
    assert yesterday["top"] and yesterday["top"][0]["value"] == fx.MAC_BUSY and yesterday["top"][0]["count"] < 200, "the same station, far fewer a day earlier: a jump n8n can see"
    assert sum(r["count"] for r in yesterday["top"]) + sum(r["count"] for r in day_before["top"]) > 0
    whole = query.count(config, "ruckus-ap", files, 24, 0, query.Filter(), r"mping", 10)
    assert whole["top"] == [{"value": "", "count": 201}], "no capture group counts everything under one value"
    two = query.count(config, "ruckus-ap", files, 24, 0, query.Filter(), r"(wlan\d): STA ([0-9a-f:]{17})", 10)
    assert {r["value"] for r in two["top"]} == {f"wlan0 {fx.MAC_BUSY}", f"wlan1 {fx.MAC_QUIET}"}, "several groups are joined"
    raises(lambda: query.count(config, "ruckus-ap", files, 24, 0, query.Filter(), "", 5), "pattern is required")
    raises(lambda: query.count(config, "ruckus-ap", files, 24, 0, query.Filter(), "(", 5), "pattern is not a valid")
    old = query.MAX_KEYS
    query.MAX_KEYS = 1
    try:
        r = query.count(config, "ruckus-ap", files, 24, 0, query.Filter(), pat, 10)
        assert r["distinct"] == 1 and r["overflow"] == 5
    finally:
        query.MAX_KEYS = old
    plug = files_of("plug-octoprint")
    up = query.count(plug[0], "plug-octoprint", plug[2], 24, 0, query.Filter(), r'"UptimeSec":(\d+)', 400)
    assert up["counted"] == 360 and up["distinct"] == 360, "a value can be any captured text"


def test_a_config_that_cannot_be_read_keeps_the_last_good_one():
    good, err = sources.get_config()
    assert good and not err
    for body, words in ((b"tz: UTC\n\xff\xfe", "codec"), ("sources:\n  1.2.3.4: {name: a, quiet_after: 99999999999d}\n".encode(), "quiet_after is too large")):
        time.sleep(0.01)
        cfg.write_bytes(body)
        for _ in range(2):  # asked twice: the error must not vanish after the first look
            c, err = sources.get_config()
            assert c is good and words in err, (c, err)
    time.sleep(0.01)
    cfg.write_text(fx.SOURCES_YML)
    c, err = sources.get_config()
    assert not err and c is not good


def test_a_slow_pattern_is_cut_off_by_the_query_budget_not_after_thousands_of_lines():
    config, src, files = files_of("ruckus-ap")
    old = query.BUDGET_SECONDS
    query.BUDGET_SECONDS = -1  # already over budget
    try:
        r = query.top(config, "ruckus-ap", files, 24, 0, query.Filter(), 10)
        assert r["truncated"] and r["scanned"] <= 1, r["scanned"]
    finally:
        query.BUDGET_SECONDS = old


def test_nothing_returned_carries_control_characters():
    (logs / "syslog-10.9.9.6.log").write_text(f"{fx.stamp(fx.LOCAL_NOW - timedelta(minutes=1))} h\x1b[31m esc\x1b[0m\x07 value=a\x1bb\n")
    c = sources.parse("sources:\n  10.9.9.6: {name: ctl}\n")
    files = sources.discover()["10.9.9.6"]
    lines = query.lines(c, "ctl", files, 1, 0, query.Filter(), 5)["lines"]
    top = query.top(c, "ctl", files, 1, 0, query.Filter(), 5)["top"]
    count = query.count(c, "ctl", files, 1, 0, query.Filter(), r"value=(\S+)", 5)["top"]
    seen = repr((lines, top, count))
    assert "\\x1b" not in seen and "\\x07" not in seen, seen
    assert count[0]["value"] == "ab"


def main():
    test_config_parse()
    test_config_reload_keeps_last_good()
    test_status_unmapped_and_quiet()
    test_lines()
    test_control_characters_and_markup_in_log_text_are_returned_clean()
    test_top()
    test_count()
    test_a_config_that_cannot_be_read_keeps_the_last_good_one()
    test_a_slow_pattern_is_cut_off_by_the_query_budget_not_after_thousands_of_lines()
    test_nothing_returned_carries_control_characters()
    print("OK: sources.yml is validated, and lines, top and count read the right window with the right limits.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(data.parent, ignore_errors=True)
