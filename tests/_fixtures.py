"""A syslog folder built from the real lines seen on Gandalf (2026-10-22), for the self-checks.

Fixed "now" is 2026-10-22 10:30 New York time (14:30 UTC)."""
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/New_York")
NOW = datetime(2026, 10, 22, 14, 30, tzinfo=timezone.utc)
LOCAL_NOW = NOW.astimezone(TZ)


def stamp(t: datetime) -> str:
    return f"{t.strftime('%b')} {t.day:2d} {t.strftime('%H:%M:%S')}"


def write(path: Path, rows):
    """rows: (datetime, host, text), written oldest first."""
    with open(path, "w") as f:
        for t, host, text in sorted(rows, key=lambda r: r[0]):
            f.write(f"{stamp(t)} {host} {text}\n")


def make_env():
    """Create data, log and config directories, set the environment, return (data, logs, config_path)."""
    base = Path(tempfile.mkdtemp(prefix="loglook-test-"))
    data, logs = base / "data", base / "logs"
    data.mkdir(), logs.mkdir()
    cfg = base / "sources.yml"
    os.environ["LOGLOOK_DATA_DIR"] = str(data)
    os.environ["LOGLOOK_LOG_DIR"] = str(logs)
    os.environ["LOGLOOK_CONFIG"] = str(cfg)
    return data, logs, cfg


SOURCES_YML = """tz: America/New_York
sources:
  10.42.11.1:  {name: pfsense,  quiet_after: 24h}
  10.42.11.2:  {name: switch}
  10.42.11.5:  {name: ruckus-ap, quiet_after: 15m}
  10.42.11.43: {name: plug-octoprint, quiet_after: 15m}
  10.42.11.77: {name: silent-box, quiet_after: 1h}
"""

MAC_BUSY = "9c:c8:e9:75:07:81"
MAC_QUIET = "2c:fd:b3:36:8f:c4"


def build_logs(logs: Path):
    now = LOCAL_NOW
    ap = "10.42.11.5"
    # AP: rotated copy holds yesterday and the day before, the live file today.
    old, live = [], []
    for i in range(300):  # a busy station, about every 10 minutes for 2 days back to 26 hours ago
        old.append((now - timedelta(hours=26) - timedelta(minutes=10 * i), ap, f"hostapd: wlan0: STA {MAC_BUSY} IEEE 802.11: disassociated"))
    for i in range(500):  # the same station today: 500 in 24 hours, a clear jump
        live.append((now - timedelta(minutes=2 + i * 2), ap, f"hostapd: wlan0: STA {MAC_BUSY} IEEE 802.11: disassociated"))
    for i in range(5):
        live.append((now - timedelta(minutes=30 + i * 100), ap, f"hostapd: wlan1: STA {MAC_QUIET} IEEE 802.11: disassociated"))
    for i in range(200):
        live.append((now - timedelta(minutes=1 + i * 3), ap, "mping[21025]: status=succ result=34 to_pid=1438 ports=1 ports_signaled=1"))
    for i in range(40):
        live.append((now - timedelta(minutes=5 + i * 30), ap, f"syslog: M972192S0D0 pid=2418[2418], LogoutAdmin():cred lookup fail "))
    live.append((now - timedelta(minutes=45), ap, "mping[21025]: status=fail result=0 to_pid=1438 ports=1 ports_signaled=0"))
    live.append((now - timedelta(minutes=50), ap, "appweb: appweb error: : appweb: Error:<pid 1 tid 2> No free worker threads. Increase ThreadLimit. (currently allocated 10)"))
    write(logs / f"syslog-{ap}.log.1", old)
    write(logs / f"syslog-{ap}.log", live)

    # Switch: sparse, never rotates; the real Oct 13 events, plus a flap today.
    sw = "10.42.11.2"
    rows = []
    for t, text in [
        (datetime(2026, 10, 13, 18, 5, 11, tzinfo=TZ), "13/10/2026 18:05:10 Port 23 link down"),
        (datetime(2026, 10, 13, 18, 5, 15, tzinfo=TZ), "13/10/2026 18:05:14 Port 23 link up, 2.5Gbps FULL duplex"),
        (datetime(2026, 10, 13, 19, 36, 55, tzinfo=TZ), "13/10/2026 19:36:54 Port 9 link down"),
        (datetime(2026, 10, 13, 19, 36, 56, tzinfo=TZ), "13/10/2026 19:36:55 Port 3 link down"),
        (datetime(2026, 10, 13, 19, 36, 56, tzinfo=TZ), "13/10/2026 19:36:55 Port 19 link down"),
    ]:
        rows.append((t, sw, text))
    for i in range(3):
        t = now - timedelta(hours=3, minutes=-10 * i)
        rows.append((t, sw, f"{t.strftime('%d/%m/%Y %H:%M:%S')} Port 7 link down"))
        rows.append((t + timedelta(seconds=4), sw, f"{(t + timedelta(seconds=4)).strftime('%d/%m/%Y %H:%M:%S')} Port 7 link up, 1Gbps FULL duplex"))
    write(logs / f"syslog-{sw}.log", rows)

    # pfSense: the real lines from this morning, plus an sshguard block.
    pf, host = "10.42.11.1", "ecthelion.cmpbll.casa"
    t0 = datetime(2026, 10, 22, 10, 22, 25, tzinfo=TZ)
    rows = [
        (t0, host, "syslogd restart"),
        (t0, host, "sshguard[85704] Now monitoring attacks."),
        (t0, host, "nginx 2026/10/22 10:22:25 [error] 415#101160: send() failed (54: Connection reset by peer) while logging to syslog, server: unix:/var/run/log"),
        (t0 + timedelta(minutes=3), host, 'sshguard[85704]: Attack from "203.0.113.9" on service ssh with danger 10.'),
    ]
    for i in range(6):
        rows.append((t0 + timedelta(seconds=35 + 60 * i), host, "/usr/sbin/cron[31397] (root) CMD (/usr/bin/nice -n20 /usr/local/share/pfSense-pkg-node_exporter/interface-collector.py)"))
    rows.append((t0 + timedelta(seconds=36), host, "kea-dhcp4[74856] INFO  [kea-dhcp4.leases.0x3375dba79010] DHCP4_LEASE_OFFER [hwtype=1 dc:da:0c:b6:d8:68], cid=[01:dc:da:0c:b6:d8:68], tid=0x4bb5f646: lease 10.42.11.9 will be offered"))
    write(logs / f"syslog-{pf}.log", rows)

    # Tasmota plug: telemetry every 10 s for an hour, uptime resetting once.
    tp, name = "10.42.11.43", "EZPlug-Octoprint"
    rows = []
    for i in range(360):
        t = now - timedelta(seconds=10 * (360 - i))
        uptime = 740000 + 10 * i if i < 200 else 40 + 10 * (i - 200)
        rows.append((t, name, f'ESP-MQT: tele/{name}/STATE = {{"Time":"x","Uptime":"8T13:48:23","UptimeSec":{uptime},"Heap":30}}'))
    write(logs / f"syslog-{tp}.log", rows)

    # A source with no entry in sources.yml, and a configured one that wrote long ago.
    write(logs / "syslog-10.42.11.99.log", [(now - timedelta(minutes=5), "stranger", "hello from an unlisted device")])
    write(logs / "syslog-10.42.11.77.log", [(now - timedelta(hours=30), "10.42.11.77", "last words")])
