"""Container logs, read through Docker's HTTP API.

Read-only by construction: the only requests made are GET /containers/json and GET
/containers/<id>/logs. Nothing to configure when the Docker socket is mounted; a socket proxy that
allows only those reads (LOGLOOK_DOCKER_URL=http://socket-proxy:2375) is the safer way to connect.

Every container becomes a source named `docker:<container>`. Docker keeps the lines (its own log
rotation decides how far back they go) and stamps each one with an exact UTC time, so no year or
timezone guessing is needed. The stream is multiplexed (8-byte frames) unless the container has a
TTY, when it is plain text; both are read.
"""
import http.client
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator
from urllib.parse import urlsplit

from app import config
from app.services import logreader
from app.services.logreader import Line, ReadStats

PREFIX = "docker:"
TIMEOUT = 15  # seconds Docker may be silent while a log is read
LIST_TIMEOUT = 5  # the container list is asked for on every page: a Docker that does not answer quickly is down
MAX_FRAME = 4 * 1024 * 1024  # a bigger frame than this is a broken stream, not a log line
MAX_LINE = 1024 * 1024  # a line joined from several frames stops growing here
ID_RE = re.compile(r"^[0-9a-f]{12,64}$")
# Docker's own rule for container names (longer than the 40 characters a device name gets on the Sources page).
CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")  # colour and cursor codes: they would sit inside what a regex wants to match
STAMP_RE = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$")


class DockerError(Exception):
    pass


@dataclass(frozen=True)
class Container:
    id: str
    container: str  # the container's own name
    state: str = ""
    status: str = ""

    @property
    def name(self) -> str:  # the source name
        return PREFIX + self.container

    def read_window(self, start: datetime, end: datetime, stats: ReadStats | None = None) -> Iterator[Line]:
        """Lines with start <= time <= end, oldest first (same contract as logreader.FileSet)."""
        return _read(self, start, end, stats)


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _target():
    """Where Docker is: ('unix', path), ('tcp', host, port, prefix) or None when it is off."""
    url = config.DOCKER_URL
    if url.lower() == "off":
        return None
    if not url:
        return ("unix", config.DOCKER_SOCKET) if os.path.exists(config.DOCKER_SOCKET) else None
    u = urlsplit(url)
    if u.scheme == "unix" and u.path:
        return ("unix", u.path)
    if u.scheme == "http" and u.hostname:
        return ("tcp", u.hostname, u.port or 80, u.path.rstrip("/"))
    raise DockerError("LOGLOOK_DOCKER_URL must look like http://socket-proxy:2375 or unix:///var/run/docker.sock")


def _open(path: str, timeout: float = TIMEOUT):
    target = _target()
    if target is None:
        raise DockerError("Docker is not configured")
    where = config.DOCKER_URL or config.DOCKER_SOCKET
    conn = _UnixConnection(target[1], timeout) if target[0] == "unix" else http.client.HTTPConnection(target[1], target[2], timeout=timeout)
    try:
        conn.request("GET", ("" if target[0] == "unix" else target[3]) + path)
        resp = conn.getresponse()
    except (OSError, http.client.HTTPException) as exc:
        conn.close()
        raise DockerError(f"Docker is not reachable at {where}: {exc}") from None
    if resp.status != 200:
        conn.close()
        hint = ": the socket proxy is probably not allowing loglook (add it to its allowed clients)" if resp.status == 403 else ""
        raise DockerError(f"Docker answered {resp.status} for {path.split('?')[0]}{hint}")
    return conn, resp


def containers() -> tuple[list[Container], str]:
    """Every container, running or not, by name; and an error text when Docker could not be asked
    (empty when it is off or fine)."""
    try:
        if _target() is None:
            return [], ""
        conn, resp = _open("/containers/json?all=1", LIST_TIMEOUT)
        try:
            data = resp.read(8 * 1024 * 1024)
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(f"Docker is not reachable: {exc}") from None
        finally:
            conn.close()
        listing = json.loads(data)
    except DockerError as exc:
        return [], str(exc)
    except ValueError:
        return [], "Docker answered with something that is not a container list"
    out = []
    for item in listing if isinstance(listing, list) else []:
        if not isinstance(item, dict) or not ID_RE.match(str(item.get("Id", ""))):
            continue
        cid = item["Id"]
        names = item.get("Names") or [""]
        name = str(names[0]).removeprefix("/")  # some containers are stored without the slash
        out.append(Container(cid, name if CONTAINER_NAME_RE.match(name) else cid[:12], str(item.get("State", ""))[:20], str(item.get("Status", ""))[:60]))
    return sorted(out, key=lambda c: c.container.lower()), ""


def _payloads(resp) -> Iterator[bytes]:
    """The pieces of a log stream: one per frame, or one per line (newline kept) when Docker sent plain text."""
    buf = bytearray()
    # Decided from the first bytes. A frame starts with 0, 1 or 2 and three zero bytes; a TTY stream
    # (asked for with timestamps) starts with the year's ASCII digits, so the two cannot be confused.
    framed = None
    while True:
        try:
            chunk = resp.read1(65536)
        except (OSError, http.client.HTTPException) as exc:
            raise DockerError(f"Docker stopped answering: {exc}") from None
        buf += chunk
        if framed is None and (len(buf) >= 4 or not chunk):
            framed = len(buf) >= 4 and buf[0] in (0, 1, 2) and not any(buf[1:4])
        if framed:
            while len(buf) >= 8:
                size = int.from_bytes(buf[4:8], "big")
                if size > MAX_FRAME:
                    raise DockerError("Docker sent a corrupt log stream (frame too large)")
                if len(buf) < 8 + size:
                    break
                yield bytes(buf[8 : 8 + size])
                del buf[: 8 + size]
        elif framed is False:
            while (i := buf.find(b"\n")) >= 0:
                yield bytes(buf[: i + 1])
                del buf[: i + 1]
            if len(buf) > MAX_FRAME:
                raise DockerError("Docker sent a corrupt log stream (line too long)")
        if not chunk:
            break
    if framed and buf:
        raise DockerError("Docker sent a corrupt log stream (cut short)")
    if framed is False and buf:
        yield bytes(buf)


def _lines(payloads: Iterator[bytes]) -> Iterator[bytes]:
    """Whole log lines from the pieces. Docker cuts a line longer than about 16 KB into several frames:
    only the last ends in a newline, and each one starts with its own timestamp, which is dropped when
    the pieces are joined. A joined line is kept to MAX_LINE bytes."""
    pending = b""  # the start of a line that has not ended yet
    for payload in payloads:
        parts = payload.split(b"\n")
        if pending:
            stamp, _, rest = parts[0].partition(b" ")
            parts[0] = (pending + (rest if STAMP_RE.match(stamp.decode("ascii", "replace")) else parts[0]))[:MAX_LINE]
        pending = parts.pop()  # what follows the last newline: empty when the piece ended a line
        yield from (p for p in parts if p)
    if pending:
        yield pending


def _parse(raw: bytes, host: str) -> Line | None:
    stamp, _, message = raw.partition(b" ")
    m = STAMP_RE.match(stamp.decode("ascii", "replace"))
    if m is None:
        return None
    base, frac, zone = m.groups()
    try:
        ts = datetime.fromisoformat(f"{base}.{(frac or '')[:6].ljust(6, '0')}{'+00:00' if zone == 'Z' else zone}")
    except ValueError:
        return None
    return Line(ts=ts, host=host, text=ANSI_RE.sub("", message.decode("utf-8", "replace")).rstrip("\r"))


def _read(c: Container, start: datetime, end: datetime, stats: ReadStats | None) -> Iterator[Line]:
    stats = stats if stats is not None else ReadStats()
    stats.files.append(c.container)
    since, until = int(start.timestamp()), int(end.timestamp()) + 1
    conn, resp = _open(f"/containers/{c.id}/logs?stdout=1&stderr=1&timestamps=1&since={since}&until={until}")
    try:
        for raw in _lines(_payloads(resp)):
            if stats.scanned >= logreader.MAX_LINES:
                stats.truncated = True
                return
            line = _parse(raw, c.container)
            if line is None:
                stats.scanned += 1
                stats.unparsed += 1
            elif start <= line.ts <= end:  # Docker's since/until are whole seconds, so a few lines just outside come back: not counted
                stats.scanned += 1
                yield line
    finally:
        conn.close()
