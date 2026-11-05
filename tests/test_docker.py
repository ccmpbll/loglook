"""Self-check for container logs read through Docker's HTTP API (a read-only socket proxy).

A fake Docker API stands in for the proxy. It answers like the real one: a chunked, multiplexed
stream (8-byte frames) for normal containers, a raw stream for TTY containers, nanosecond
timestamps of varying length, and it refuses with 403 when told to.

  1. Containers are listed by name (leading slash removed, short id when there is no name) and
     become sources named `docker:<container>`. With nothing configured, a mounted Docker socket is
     used; a socket-proxy URL works too; `off` turns it off; a down or refusing Docker is an error
     message, never a crash.
  2. Lines: only the window, oldest first, timezone-aware, colour codes stripped (so a regex can
     match across them), unreadable lines counted, a corrupt stream refused, bounded in lines.
  3. The same three queries work on a container; /v1/sources keeps its old shape and lists
     containers apart; unknown names are refused; the viewer and Sources page show them, escaped.
     A syslog device nobody has named yet can be read by its IP.
  4. Read-only: every request loglook made is a GET that the socket-proxy allow-list permits.

Run directly: python3 tests/test_docker.py
"""
import http.server
import json
import os
import re
import shutil
import socketserver
import struct
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fixtures as fx  # noqa: E402

# The GET allow-list of the socket-proxy on Gandalf (SP_ALLOW_GET): loglook must stay inside it.
ALLOW_GET = re.compile(r"/(v1\..{1,2}/)?(_ping|info|version|events.*|system/df|containers/json|containers/[^/]+/(logs|json|stats))")
REQUESTS: list[tuple[str, str]] = []  # (method, path without query)
STATE = {"deny": False, "deny_logs": False, "corrupt": "huge", "hostile": False, "slow": 0.0}


def at(minutes: float) -> datetime:
    return fx.NOW - timedelta(minutes=minutes) + timedelta(microseconds=123456)


WEB = [
    (at(90), 1, "old line, outside the hour"),
    (at(30), 1, "\x1b[32mINFO\x1b[0m server started"),
    (at(20), 2, "ERROR \x1b[1;31mdisk full\x1b[0m on /dev/sda1"),
    (at(10), 1, "request id=101 took 12ms"),
    (at(9), 1, "request id=102 took 13ms"),
    (at(8), 1, "request id=103 took 14ms"),
    (at(5), 1, "<script>alert(1)</script> hello"),
    (fx.NOW + timedelta(seconds=0.5), 1, "half a second too late"),  # Docker's `until` is whole seconds, so this comes back
    (fx.NOW + timedelta(hours=3), 1, "from the future"),
]
TTY = [(at(15), 1, "tty hello"), (at(5), 1, "tty \x1b[0mworld")]
HOSTILE = [  # a listing that is not what it should be: none of these may become a request
    {"Id": "../../etc", "Names": ["/evil"], "State": "running", "Status": ""},
    {"Id": 12345, "Names": ["/num"]},
    "not even an object",
    {"Id": "f" * 64, "Names": ["/has space/and slash"], "State": "running", "Status": "Up"},
]
IDS = {"web": "a" * 64, "tty-app": "b" * 64, "empty": "c" * 64, "nameless": "d" * 64, "corrupt": "e" * 64, "long": "9" * 64}
LISTING = [
    {"Id": IDS["web"], "Names": ["/web"], "State": "running", "Status": "Up 3 hours"},
    {"Id": IDS["tty-app"], "Names": ["tty-app"], "State": "running", "Status": "Up 2 days"},  # some containers have no leading slash
    {"Id": IDS["empty"], "Names": ["/empty"], "State": "exited", "Status": "Exited (0) 1 hour ago"},
    {"Id": IDS["nameless"], "Names": [], "State": "created", "Status": "Created"},
    {"Id": IDS["corrupt"], "Names": ["/corrupt"], "State": "running", "Status": "Up 1 minute"},
    {"Id": IDS["long"], "Names": ["/long"], "State": "running", "Status": "Up 5 minutes"},
]


def stamp(t: datetime, i: int) -> str:
    digits = (9, 8, 6)[i % 3]  # Docker trims trailing zeros, so the fraction varies in length
    frac = f"{t.microsecond:06d}000"[:digits]
    return f"{t.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%S}.{frac}Z"


def frame(stream: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", stream, len(payload)) + payload


class FakeDocker(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            self.serve()
        except OSError:  # a client that gave up waiting
            pass

    def serve(self):
        path, _, query = self.path.partition("?")
        REQUESTS.append(("GET", path))
        if STATE["deny"]:
            return self.reply(403, b"forbidden")
        if STATE["deny_logs"] and path.endswith("/logs"):
            return self.reply(403, b"forbidden")
        if STATE["slow"]:
            time.sleep(STATE["slow"])
        if path == "/containers/json":
            return self.reply(200, json.dumps(LISTING + (HOSTILE if STATE["hostile"] else [])).encode())
        m = re.fullmatch(r"/containers/([0-9a-f]+)/logs", path)
        cid = m.group(1) if m else None
        name = next((n for n, i in IDS.items() if i == cid), None)
        if name is None:
            return self.reply(404, b"no such container")
        params = dict(p.split("=") for p in query.split("&") if p)
        since, until = int(params.get("since", 0)), int(params.get("until", 2**40))
        if name == "corrupt":
            data = b"\x01\x00\x00\x00\xff\xff\xff\xff" if STATE["corrupt"] == "huge" else frame(1, b"x" * 100)[:30]  # a frame that never finishes
        elif name == "long":  # Docker cuts a long line into frames: each has a timestamp, only the last ends in a newline
            t = at(12)
            data = b"".join(frame(1, f"{stamp(t, i)} {text}".encode()) for i, text in enumerate(["AAAA", "BBBB", "CCCC\n"]))
            data += frame(1, f"{stamp(t, 0)} next line\n".encode())
            data += frame(2, f"{stamp(t, 1)} XX".encode()) + frame(2, b"YY\n")  # a piece with no timestamp of its own
            data += frame(1, f"{stamp(t, 2)} ends without a newline".encode())
        elif name == "tty-app":  # a TTY container: no frames, CRLF line ends
            data = b"".join(f"{stamp(t, i)} {text}\r\n".encode() for i, (t, _, text) in enumerate(TTY) if since <= int(t.timestamp()) < until)
        elif name == "web":
            data = b"".join(frame(s, f"{stamp(t, i)} {text}\n".encode()) for i, (t, s, text) in enumerate(WEB) if since <= int(t.timestamp()) < until)
            data += frame(1, b"no timestamp on this line\n")
        else:
            data = b""
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.docker.multiplexed-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for i in range(0, len(data), 3):  # tiny chunks: a frame header arrives split across reads
            piece = data[i : i + 3]
            self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeDocker)
threading.Thread(target=server.serve_forever, daemon=True).start()
URL = f"http://127.0.0.1:{server.server_address[1]}"

SOCK_DIR = Path(tempfile.mkdtemp(prefix="ll-", dir="/tmp"))  # short: a unix socket path has a length limit
SOCK = SOCK_DIR / "docker.sock"
unix_server = socketserver.ThreadingUnixStreamServer(str(SOCK), FakeDocker)
threading.Thread(target=unix_server.serve_forever, daemon=True).start()

data, logs, cfg = fx.make_env()
os.environ["LOGLOOK_DOCKER_URL"] = URL

from fastapi.testclient import TestClient  # noqa: E402

from app import config as app_config  # noqa: E402
from app.database import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.services import clock, dockerlogs, logreader, query, sources, tokens  # noqa: E402
from app.services.text import iso  # noqa: E402

app_config.DOCKER_SOCKET = "/nonexistent/docker.sock"  # nothing is auto-detected unless a test says so
clock.now = lambda: fx.NOW
cfg.write_text(fx.SOURCES_YML)
fx.build_logs(logs)
init_db()
client = TestClient(app)
admin = TestClient(app)
_, TOKEN = tokens.create("t", "", 30)
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def container(name):
    return next(c for c in dockerlogs.containers()[0] if c.container == name)


def read(c, minutes=60, ending=0, stats=None):
    end = fx.NOW - timedelta(minutes=ending)
    return list(c.read_window(end - timedelta(minutes=minutes), end, stats))


def expect_error(fn, contains):
    try:
        fn()
    except dockerlogs.DockerError as exc:
        assert contains in str(exc), f"{contains!r} not in {exc}"
        return
    raise AssertionError(f"no error, expected {contains!r}")


def with_url(url, fn):
    saved = app_config.DOCKER_URL
    app_config.DOCKER_URL = url
    try:
        return fn()
    finally:
        app_config.DOCKER_URL = saved


def test_container_list():
    cs, err = dockerlogs.containers()
    assert not err
    assert [c.name for c in cs] == ["docker:corrupt", "docker:dddddddddddd", "docker:empty", "docker:long", "docker:tty-app", "docker:web"], [c.name for c in cs]
    assert container("web").state == "running" and container("empty").state == "exited", "stopped containers are listed too"
    assert container("dddddddddddd").id == IDS["nameless"], "no name: the short id stands in"


def test_hostile_listing():
    STATE["hostile"] = True
    try:
        cs, err = dockerlogs.containers()
    finally:
        STATE["hostile"] = False
    assert not err and [c.container for c in cs] == ["corrupt", "dddddddddddd", "empty", "ffffffffffff", "long", "tty-app", "web"]  # the odd name falls back to its short id, [c.container for c in cs]
    assert all(dockerlogs.ID_RE.match(c.id) for c in cs), "an id that is not hex never reaches a URL"


def test_off_down_refused():
    before = len(REQUESTS)
    assert with_url("off", dockerlogs.containers) == ([], ""), "off: no error"
    assert with_url("", dockerlogs.containers) == ([], ""), "nothing set and no socket mounted: off, no error"
    assert len(REQUESTS) == before, "off means no request at all"
    cs, err = with_url("http://127.0.0.1:1", dockerlogs.containers)
    assert cs == [] and "not reachable" in err, err
    web = container("web")  # found while Docker is up; now it goes away
    expect_error(lambda: with_url("http://127.0.0.1:1", lambda: read(web)), "not reachable")
    cs, err = with_url("ftp://somewhere", dockerlogs.containers)
    assert cs == [] and "http://" in err and "unix://" in err, "only http (a socket proxy) or unix:// is supported: " + err
    cs, err = with_url("unix:///nonexistent/docker.sock", dockerlogs.containers)
    assert cs == [] and "not reachable" in err, err
    STATE["deny"] = True
    try:
        cs, err = dockerlogs.containers()
        assert cs == [] and "403" in err and "allow" in err.lower(), err
    finally:
        STATE["deny"] = False


def test_listing_fails_fast():
    """The container list is asked for on every page: a Docker that stalls must not stall the page for the read timeout."""
    saved = dockerlogs.LIST_TIMEOUT
    dockerlogs.LIST_TIMEOUT, STATE["slow"] = 0.2, 1.0
    try:
        started = time.monotonic()
        cs, err = dockerlogs.containers()
        took = time.monotonic() - started
    finally:
        dockerlogs.LIST_TIMEOUT, STATE["slow"] = saved, 0.0
    assert cs == [] and "not reachable" in err and took < 0.8, (cs, err, took)


def test_unix_socket():
    """The zero-configuration path: the Docker socket is mounted and nothing else is set."""
    url = f"unix://{SOCK}"
    cs, err = with_url(url, dockerlogs.containers)
    assert not err and len(cs) == 6, err
    web = next(c for c in cs if c.container == "web")
    assert [l.text for l in with_url(url, lambda: read(web))][:2] == ["INFO server started", "ERROR disk full on /dev/sda1"]
    saved = app_config.DOCKER_SOCKET
    app_config.DOCKER_SOCKET = str(SOCK)
    try:
        cs, err = with_url("", dockerlogs.containers)
        assert not err and len(cs) == 6, "no URL set but the socket is there: it is used"
        assert with_url("off", dockerlogs.containers) == ([], ""), "off beats the socket"
    finally:
        app_config.DOCKER_SOCKET = saved


def test_read_window():
    stats = logreader.ReadStats()
    got = read(container("web"), 60, 0, stats)
    assert [l.text for l in got] == [
        "INFO server started",
        "ERROR disk full on /dev/sda1",
        "request id=101 took 12ms",
        "request id=102 took 13ms",
        "request id=103 took 14ms",
        "<script>alert(1)</script> hello",
    ], [l.text for l in got]
    assert all(l.host == "web" and l.ts.tzinfo is not None for l in got)
    assert [l.ts for l in got] == [at(30), at(20), at(10), at(9), at(8), at(5)], "9, 8 and 6 digit fractions all read to the same instant"
    assert stats.unparsed == 1 and stats.scanned == 7 and stats.files == ["web"], (stats.unparsed, stats.scanned, stats.files)  # 6 in the window and 1 unreadable; the one half a second late came back from Docker but is not counted
    assert [l.text for l in read(container("web"), 60, 15)] == ["INFO server started", "ERROR disk full on /dev/sda1"], "a window that ended 15 minutes ago"
    assert [l.text for l in read(container("tty-app"))] == ["tty hello", "tty world"], "TTY container: raw lines, CRLF and colour codes gone"
    assert read(container("empty")) == []
    expect_error(lambda: read(container("corrupt")), "frame too large")
    STATE["corrupt"] = "short"
    try:
        expect_error(lambda: read(container("corrupt")), "cut short")
    finally:
        STATE["corrupt"] = "huge"


def test_long_lines_are_joined():
    got = read(container("long"))
    assert [l.text for l in got] == ["AAAABBBBCCCC", "next line", "XXYY", "ends without a newline"], [l.text for l in got]
    assert got[0].ts == at(12) and all(l.ts == got[0].ts for l in got), "the first piece's time stands for the line"
    saved, dockerlogs.MAX_LINE = dockerlogs.MAX_LINE, 36  # the first piece starts with a 31-character timestamp
    try:
        assert [l.text for l in read(container("long"))][0] == "AAAAB", "a joined line is bounded"
    finally:
        dockerlogs.MAX_LINE = saved


def test_bounded():
    saved = logreader.MAX_LINES
    logreader.MAX_LINES = 3
    try:
        stats = logreader.ReadStats()
        got = read(container("web"), 60, 0, stats)
        assert len(got) == 3 and stats.truncated, "the line limit applies to containers too"
    finally:
        logreader.MAX_LINES = saved
    saved, dockerlogs.MAX_FRAME = dockerlogs.MAX_FRAME, 20
    try:
        expect_error(lambda: read(container("tty-app")), "line too long")  # a TTY line that never ends cannot grow without limit
    finally:
        dockerlogs.MAX_FRAME = saved


def test_queries():
    config, _ = sources.get_config()
    web = container("web")
    r = query.lines(config, web.name, web, 1, 0, query.Filter(), 100)
    assert r["source"] == "docker:web" and r["returned"] == 6 and r["unparsed"] == 1 and r["files"] == ["web"]
    assert r["lines"][0]["text"] == "INFO server started" and r["lines"][0]["host"] == "web"
    r = query.lines(config, web.name, web, 1, 0, query.Filter(include=r"INFO\s+server"), 100)
    assert r["returned"] == 1, "a pattern matches across where the colour codes were"
    r = query.top(config, web.name, web, 1, 0, query.Filter(), 15)
    top = {t["pattern"]: t for t in r["top"]}
    assert top["request id=# took #ms"]["count"] == 3, top
    assert not any("\x1b" in t["example"] or "[32m" in t["example"] for t in r["top"]), "no colour codes left in examples"
    r = query.count(config, web.name, web, 1, 0, query.Filter(), r"id=(\d+)", 15)
    assert r["distinct"] == 3 and r["counted"] == 3
    expect_error(lambda: with_url("http://127.0.0.1:1", lambda: query.lines(config, web.name, web, 1, 0, query.Filter(), 10)), "not reachable")  # Docker's fault, not a bad query: a DockerError


def test_api():
    r = client.get("/v1/sources", headers=AUTH)
    body = r.json()
    assert r.status_code == 200 and body["docker_error"] is None
    assert not any(str(s["name"]).startswith("docker:") for s in body["sources"]), "the old `sources` list keeps its shape"
    assert not any(str(u).startswith("docker") for u in body["unmapped"]) and body["quiet"] == ["silent-box"], "Docker leaves the syslog quiet/unmapped lists alone"
    web = next(c for c in body["containers"] if c["source"] == "docker:web")
    assert web["container"] == "web" and web["state"] == "running" and web["id"] == "a" * 12, web
    assert len(body["containers"]) == 6
    r = client.get("/v1/lines", params={"source": "docker:web", "hours": 1}, headers=AUTH)
    assert r.status_code == 200 and r.json()["source"] == "docker:web" and r.json()["returned"] == 6
    assert client.get("/v1/top", params={"source": "docker:web", "hours": 1}, headers=AUTH).status_code == 200
    r = client.get("/v1/count", params={"source": "docker:web", "hours": 1, "pattern": r"id=(\d+)"}, headers=AUTH)
    assert r.status_code == 200 and r.json()["distinct"] == 3
    for bad in ("docker:nope", "docker:", "docker:../etc", "docker:web/../../x", "web", "docker"):
        assert client.get("/v1/lines", params={"source": bad}, headers=AUTH).status_code == 404, bad
    assert client.get("/v1/lines", params={"source": "docker:corrupt", "hours": 1}, headers=AUTH).status_code == 502, "Docker's stream is broken: 502, not 'your query is wrong'"
    assert client.get("/v1/lines", params={"source": "docker:web", "include": "("}, headers=AUTH).status_code == 400, "a bad pattern is still the caller's fault"
    STATE["deny_logs"] = True  # the list works, the logs do not (a proxy allow list that stops short)
    try:
        r = client.get("/v1/lines", params={"source": "docker:web", "hours": 1}, headers=AUTH)
        assert r.status_code == 502 and "403" in r.json()["detail"], r.text
    finally:
        STATE["deny_logs"] = False
    h = client.get("/v1/health", headers=AUTH).json()
    assert h["status"] == "ok" and h["docker_error"] is None and h["config_error"] is None, "nothing named yet, everything readable: ok"
    h = with_url("http://127.0.0.1:1", lambda: client.get("/v1/health", headers=AUTH)).json()
    assert h["status"] == "degraded" and "not reachable" in h["docker_error"], "a Docker we cannot reach is not 'ok'"
    assert with_url("off", lambda: client.get("/v1/health", headers=AUTH)).json()["status"] == "ok", "off is a choice, not a fault"
    r = client.get("/v1/lines", params={"source": "docker:web", "hours": 1}, headers=AUTH).json()
    assert r["first_line"] == iso(at(30).astimezone(sources.get_config()[0].tz)), (r["first_line"], "the oldest line read, so a caller can see how far back Docker goes")
    assert client.get("/v1/lines", params={"source": "docker:empty", "hours": 1}, headers=AUTH).json()["first_line"] is None
    assert client.get("/v1/lines", params={"source": "docker:web"}).status_code == 401, "still behind the token"

    r = with_url("off", lambda: client.get("/v1/lines", params={"source": "docker:web"}, headers=AUTH))
    assert r.status_code == 404, "off: no containers"
    assert with_url("off", lambda: client.get("/v1/sources", headers=AUTH)).json()["containers"] == []
    r = with_url("http://127.0.0.1:1", lambda: client.get("/v1/lines", params={"source": "docker:web"}, headers=AUTH))
    assert r.status_code == 502 and "not reachable" in r.json()["detail"], "Docker being down is not 'no such container': 502, so a caller can retry"
    assert client.get("/v1/lines", params={"source": "docker:nope"}, headers=AUTH).status_code == 404, "a container Docker did not list is a plain 404"
    r = with_url("http://127.0.0.1:1", lambda: client.get("/v1/sources", headers=AUTH))
    assert r.status_code == 200 and "not reachable" in r.json()["docker_error"] and r.json()["sources"], "syslog sources still answer when Docker is down"


def test_pages():
    r = admin.post("/setup", data={"username": "chris", "password": "correct-horse", "password_confirm": "correct-horse"}, follow_redirects=False)
    assert r.status_code == 303
    r = admin.get("/logs?source=docker:web&hours=1")
    assert r.status_code == 200 and '<option value="docker:web" selected>' in r.text and '<option value="pfsense"' in r.text
    assert "server started" in r.text and "\x1b" not in r.text
    assert "<script>alert(1)" not in r.text and "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text, "container output is escaped"
    assert "(oldest " in admin.get("/logs?source=docker:web&hours=1").text
    r = admin.get("/logs?source=docker:corrupt&hours=1")
    assert r.status_code == 502 and "corrupt" in r.text
    r = admin.get("/logs?source=docker:nope")
    assert r.status_code == 404 and "No container named" in r.text and "lines read" not in r.text, "a missing container is said so, not swapped for another source"
    r = with_url("http://127.0.0.1:1", lambda: admin.get("/logs?source=docker:web"))
    assert r.status_code == 502 and "not reachable" in r.text and "lines read" not in r.text, "Docker down: the reason, not pfSense's lines under a docker URL"
    r = admin.get("/sources")
    assert r.status_code == 200 and "Containers" in r.text and 'href="/logs?source=docker:web"' in r.text
    r = with_url("http://127.0.0.1:1", lambda: admin.get("/sources"))
    assert "not reachable" in r.text and "Containers" in r.text
    assert "Containers" not in with_url("off", lambda: admin.get("/sources")).text, "off: no Containers card"
    cfg.write_text("")  # no syslog sources at all: containers alone fill the picker
    try:
        r = admin.get("/logs?source=docker:web&hours=1")
        assert r.status_code == 200 and "server started" in r.text and "No sources named yet" not in r.text
    finally:
        cfg.write_text(fx.SOURCES_YML)


def test_unmapped_device_readable_by_ip():
    """Nobody has to name a device first: its IP works as the source."""
    ip = "10.42.11.99"  # in the fixtures, in the log folder, not in sources.yml
    r = client.get("/v1/lines", params={"source": ip, "hours": 1}, headers=AUTH)
    assert r.status_code == 200 and r.json()["source"] == ip and r.json()["lines"][0]["text"] == "hello from an unlisted device", r.text
    assert client.get("/v1/top", params={"source": ip, "hours": 1}, headers=AUTH).status_code == 200
    assert client.get("/v1/lines", params={"source": "10.42.11.250"}, headers=AUTH).status_code == 404, "an IP with no log file is not a source"
    assert client.get("/v1/lines", params={"source": "10.42.11.99/../x"}, headers=AUTH).status_code == 404
    r = admin.get(f"/logs?source={ip}&hours=1")
    assert r.status_code == 200 and f'<option value="{ip}" selected>' in r.text and "hello from an unlisted device" in r.text
    assert client.get("/v1/lines", params={"source": "ruckus-ap", "hours": 1}, headers=AUTH).json()["source"] == "ruckus-ap", "named sources still answer to their name"


def test_one_listing_per_request():
    """Docker is asked for its container list once per request, not once per lookup."""
    def listings(fn):
        before = len(REQUESTS)
        fn()
        return [p for _, p in REQUESTS[before:]].count("/containers/json")

    assert listings(lambda: admin.get("/logs?source=docker:web&hours=1")) == 1, "viewer"
    assert listings(lambda: client.get("/v1/lines", params={"source": "docker:web", "hours": 1}, headers=AUTH)) == 1, "API"
    assert listings(lambda: client.get("/v1/lines", params={"source": "docker:nope"}, headers=AUTH)) == 1, "API, unknown container"
    assert listings(lambda: client.get("/v1/lines", params={"source": "ruckus-ap", "hours": 1}, headers=AUTH)) == 0, "a syslog source never asks Docker"


def test_read_only():
    assert REQUESTS, "nothing was requested"
    assert all(m == "GET" and ALLOW_GET.fullmatch(p) for m, p in REQUESTS), [r for r in REQUESTS if not (r[0] == "GET" and ALLOW_GET.fullmatch(r[1]))]
    assert any(p.endswith("/logs") for _, p in REQUESTS) and any(p == "/containers/json" for _, p in REQUESTS)


def main():
    test_container_list()
    test_hostile_listing()
    test_off_down_refused()
    test_listing_fails_fast()
    test_unix_socket()
    test_read_window()
    test_long_lines_are_joined()
    test_bounded()
    test_queries()
    test_api()
    test_pages()
    test_unmapped_device_readable_by_ip()
    test_one_listing_per_request()
    test_read_only()
    print("OK: containers read through a read-only Docker API, colour codes stripped, only allow-listed GETs sent.")


if __name__ == "__main__":
    try:
        main()
    finally:
        server.shutdown()
        unix_server.shutdown()
        shutil.rmtree(data.parent, ignore_errors=True)
        shutil.rmtree(SOCK_DIR, ignore_errors=True)
