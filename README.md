# <img src="app/static/logo.png" alt="" width="64"> loglook

![Build Status](https://img.shields.io/github/actions/workflow/status/ccmpbll/loglook/docker.yml) ![Tests](https://img.shields.io/github/actions/workflow/status/ccmpbll/loglook/tests.yml) ![Docker Image Size](https://img.shields.io/docker/image-size/ccmpbll/loglook/latest) ![Docker Pulls](https://img.shields.io/docker/pulls/ccmpbll/loglook.svg) ![License](https://img.shields.io/badge/License-MIT-blue.svg)

A small, read-only service for looking at the syslog files your syslog server already writes - created for use with the syslog server built into Unraid - and at your Docker containers' logs. It lets a
script (an n8n workflow, an AI agent) or you, in a browser, ask "what did the switch say in the last
24 hours" or "what has the web container logged since lunch" without reading gigabytes of rotated files.

It does not parse or judge anything device by device. It finds a time window in the files (across the
live file and the rotated copies), filters it, and returns the lines, the lines grouped into patterns,
or counts per captured value. What counts as noise or a problem is up to whatever calls it.

## Features

- Reads `syslog-<ip>.log` files by **time**, not file age: a window is found from each line's
  timestamp across `syslog-<ip>.log`, `.log.1`, `.log.2` and so on, so a quiet device that never
  rotates and a chatty one that rotates every two weeks both work.
- Three views of any window: the **lines**, **top patterns** (MACs, IPs, hex and numbers replaced so
  repeats collapse into one row with a count), and **count by captured value** (a regex with a capture
  group, for example per MAC).
- Filters: contains text, matches a regex, excludes a regex. Windows can end earlier (`ago`), so you can
  compare today with each previous day.
- A **web UI**: a log viewer (the three views, matches highlighted), a Sources page (is logging alive:
  last line seen, quiet and unnamed sources, where you name devices), API tokens, your account.
- A read-only **JSON API** behind bearer tokens. Nothing in it changes anything.

## Running

```
docker run -d --name loglook -p 8000:8000 \
  -v /mnt/user/syslog:/logs:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ./config:/config -v ./data:/data \
  ccmpbll/loglook:latest
```

or use `docker-compose.yml`. Open <http://localhost:8000>, create the admin account (first run only).
Everything that is logging is readable straight away: devices by their IP, containers as
`docker:<name>`. Naming a device (on **Sources**, each unnamed one has a **Name it** button) is optional
and only makes the name nicer and lets you flag silence.
Serve it over HTTPS (a reverse proxy) and set `LOGLOOK_SECURE_COOKIES=true`.

### Container logs

Container logs are read from Docker's API with read-only requests (list containers, read a container's
logs). Mount the Docker socket, as above, and containers appear with no other setup. Leave out the
socket mount (or set `LOGLOOK_DOCKER_URL=off`) for syslog only.

A mounted socket gives whatever can use it full control of Docker, and `:ro` does not change that (it
only stops the socket file being replaced). loglook sends only the two read requests, but if you would
rather it could not do more, connect through a socket proxy that allows only reads, and let it talk to
that instead of mounting the socket:

```
LOGLOOK_DOCKER_URL=http://socket-proxy:2375
```

The proxy needs to allow `GET /containers/json` and `GET /containers/<id>/logs` from loglook (for
[wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy) that is `SP_ALLOW_GET` and adding
`loglook` to `SP_ALLOWFROM`), and loglook has to share a Docker network with it.

How far back a container goes is up to Docker's own log rotation (on Unraid, Settings > Docker, log
rotation: the default is small), not loglook. Every result carries `first_line`, the time of the oldest
line it read: on a busy container, a `first_line` much later than `window.start` means older lines are gone.
Containers are read by name, so a container that is updated keeps its name; its old log goes with the old container.

### Sources

Each source IP gets a name (used in the API and the pages) and, optionally, a time after which silence
is flagged (`15m`, `24h`, `2d`). Add, rename, change or remove them on the Sources page, which also
holds the timezone: syslog lines carry no zone, so they are read as local time in the one you choose
(default `America/New_York`), and the year is inferred. A device that has not sent anything yet can be
added by its IP.

The page keeps this in `./config/sources.yml` (mount the Config folder, writable, not just the file).
You never need to open it, but it is plain YAML (`tz:` and a `sources:` map of IP to `name` and optional
`quiet_after`) and a hand edit is picked up.

Saving from the page rewrites the file, so comments you add by hand are lost. If an edit stops parsing,
the last good one stays in use, the Sources page shows the error, and changes are paused until the file
is fixed or deleted.

## API

Create a token on the Tokens page; it is shown once and only a hash is stored. Send it as
`Authorization: Bearer <token>`. Every token is read-only.

Every query takes `source` (a name from the Sources page), `hours` (window length, default 24, from 0.0833 (5 minutes) up to 336)
and `ago` (how many hours before now the window ends, default 0), so day *k* back is
`hours=24&ago=24*k`. Filters: `q` (contains, any case), `include` and `exclude` (regular expressions).

```
GET /v1/health                        "ok", or "degraded" if sources.yml or Docker has a problem
GET /v1/sources                       every source: last line, quiet or not, lines in the last hour, unmapped
GET /v1/lines?source=&limit=          the most recent matching lines, oldest first (up to 500)
GET /v1/top?source=&top=              lines grouped into patterns: count, first, last, an example
GET /v1/count?source=&pattern=        matches of a regex counted per captured value
GET /healthz                          no token; for container health checks
```

```
curl -H "Authorization: Bearer $TOKEN" \
  'https://loglook.example.com/v1/count?source=wifi-ap&pattern=STA%20([0-9a-f:]{17})%20IEEE&hours=24'
```

Results are bounded in lines, bytes and time, and say so: `truncated` means something was left out, `scan_cut` means the read itself stopped early (time or line limit). Regular expressions have a time
budget per line, so a pattern that backtracks badly is refused instead of hanging the service. Log text
is untrusted: control characters are stripped, and the pages escape everything they show.

## Security

- The log folder is mounted read-only and nothing in the API writes anywhere. Docker is only ever asked to list containers and read their logs; with a read-only socket proxy that is all it is allowed to do.
- With Docker connected, every token and every login can read the logs of **every** container, and those often hold secrets (URLs with keys, auth errors). Treat a token like one that can read all of them, or set `LOGLOOK_DOCKER_URL=off`.
- The pages (cookie login) and the API (bearer tokens) are separate: a token cannot open a page, and a
  signed-in browser is not accepted on `/v1`.
- Only the SHA-256 of a token is stored. Tokens can be disabled, given an expiry, or deleted at any time;
  each of those, and every API call (with the token name), is written to the container log.
- API docs and the schema are not served.
- After 10 wrong passwords within 10 minutes, logins pause for a few minutes. Changing the password signs out every other browser. Logging out only clears that browser's cookie, so keep `LOGLOOK_SECRET_KEY` private (or change it to end every session).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LOGLOOK_LOG_DIR` | `/logs` | the syslog folder (read-only is fine) |
| `LOGLOOK_DOCKER_URL` | the mounted socket | `http://socket-proxy:2375`, `unix:///path`, or `off`; empty uses `/var/run/docker.sock` if it is mounted |
| `LOGLOOK_CONFIG` | `/config/sources.yml` | where the Sources page keeps device names and the timezone |
| `LOGLOOK_DATA_DIR` | `/data` | the admin login and tokens (`loglook.db`), the session key |
| `LOGLOOK_SECRET_KEY` | generated | signs the session cookie |
| `LOGLOOK_SECURE_COOKIES` | off | mark the cookie Secure (use behind HTTPS) |

## Data

`./data` holds `loglook.db` (the admin account and the tokens) and `secret_key`. Losing it only means creating the account and tokens again.

## Development

```
python3 -m venv .venv && .venv/bin/pip install -r requirements-test.txt
./tests/run_all.sh
```

Each file in `tests/` is a standalone script that builds a syslog folder from real log lines and checks
the reader, the queries, the tokens, the API and the pages. CI runs the same script.

## License

MIT
