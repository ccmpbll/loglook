"""Self-check for tokens, the /v1 API and the admin pages.

  1. Tokens: only the hash is stored, the plaintext is shown once; disabled and expired tokens are
     refused; last-used is stamped; names are validated; changes go to the log.
  2. /v1 is read-only JSON behind a bearer token and nothing else (a cookie login does not work
     there, a token does not open a page, no docs or schema are served).
  3. The pages: first-run setup, login with return-to that never leaves the site, password change,
     the Sources page flags unmapped and quiet sources, and the viewer shows the same data as the API,
     highlights matches, and escapes whatever the logs contain.

Run directly: python3 tests/test_api_and_ui.py
"""
import shutil
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _fixtures as fx  # noqa: E402

data, logs, cfg = fx.make_env()

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from app.database import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import ApiToken, User, utcnow  # noqa: E402
from app.services import clock, tokens  # noqa: E402

clock.now = lambda: fx.NOW
cfg.write_text(fx.SOURCES_YML)
fx.build_logs(logs)
init_db()

client = TestClient(app)  # an API caller
admin = TestClient(app)  # a signed-in browser
anon = TestClient(app, follow_redirects=False)


def H(token):
    return {"Authorization": f"Bearer {token}"}


def test_tokens():
    row, plain = tokens.create("n8n", "the sweep", 30)
    assert plain.startswith("loglook_") and len(plain) > 40
    with Session(engine) as s:
        stored = s.exec(select(ApiToken)).all()
    assert len(stored) == 1 and plain not in (stored[0].token_hash + stored[0].name + stored[0].note) and stored[0].token_hash == tokens.hash_token(plain), "only the hash is kept"
    got, reason = tokens.authenticate(plain)
    assert got and got.name == "n8n" and reason == ""
    assert tokens.authenticate(plain + "x")[0] is None and tokens.authenticate("")[1] == "unknown token"
    with Session(engine) as s:
        assert s.get(ApiToken, row.id).last_used_at is not None, "last use is stamped"
    first = None
    with Session(engine) as s:
        first = s.get(ApiToken, row.id).last_used_at
    clock.now = lambda: fx.NOW + timedelta(seconds=30)
    tokens.authenticate(plain)
    with Session(engine) as s:
        assert s.get(ApiToken, row.id).last_used_at == first, "not rewritten on every call"
    clock.now = lambda: fx.NOW + timedelta(minutes=5)
    tokens.authenticate(plain)
    with Session(engine) as s:
        assert s.get(ApiToken, row.id).last_used_at > first, "refreshed once a minute has passed"
    clock.now = lambda: fx.NOW
    tokens.toggle(row.id)
    assert tokens.authenticate(plain)[1] == "token disabled"
    tokens.toggle(row.id)
    with Session(engine) as s:
        t = s.get(ApiToken, row.id)
        t.expires_at = utcnow() - timedelta(days=1)
        s.add(t)
        s.commit()
    assert tokens.authenticate(plain)[1] == "token expired"
    for bad in ("", "a b", "x" * 41, "bad/name", "n8n"):
        try:
            tokens.create(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted name {bad!r}")
    for days in (0, -1, tokens.MAX_EXPIRY_DAYS + 1):
        try:
            tokens.create("short", "", days)
        except ValueError:
            continue
        raise AssertionError(f"accepted expiry {days}")
    tokens.delete_token(row.id)
    assert tokens.authenticate(plain)[0] is None


def test_api():
    _, plain = tokens.create("claude", "ad hoc questions")
    for path in ("/v1/health", "/v1/sources", "/v1/lines?source=switch", "/v1/top?source=switch", "/v1/count?source=switch&pattern=x"):
        r = client.get(path)
        assert r.status_code == 401 and "WWW-Authenticate" in r.headers, path
        assert client.get(path, headers=H("loglook_nope")).status_code == 401
        assert client.get(path, headers={"Authorization": "Basic abc"}).status_code == 401
    assert client.get("/healthz").json() == {"status": "ok"}, "the container check needs no token"
    for hidden in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(hidden).status_code == 404, f"{hidden} is not served"

    r = client.get("/v1/health", headers=H(plain)).json()
    assert r["status"] == "ok" and r["sources"] == 5 and r["config_error"] is None

    r = client.get("/v1/sources", headers=H(plain)).json()
    assert r["quiet"] == ["silent-box"] and r["unmapped"] == ["10.42.11.99"]
    names = {s["name"]: s for s in r["sources"]}
    assert names["ruckus-ap"]["quiet"] is False and names["switch"]["quiet"] is None

    r = client.get("/v1/lines?source=ruckus-ap&q=status=fail", headers=H(plain)).json()
    assert r["matched"] == 1 and r["lines"][0]["text"].startswith("mping")
    r = client.get("/v1/lines?source=ruckus-ap&q=disassociated&limit=3&exclude=" + fx.MAC_BUSY, headers=H(plain)).json()
    assert r["returned"] == 3 and r["matched"] == 5
    assert client.get("/v1/lines?source=nope", headers=H(plain)).status_code == 404
    assert client.get("/v1/lines?source=switch&include=(", headers=H(plain)).status_code == 400
    for bad in ("hours=0", "hours=5000", "ago=-1", "ago=99999", "limit=0", "limit=501"):
        assert client.get(f"/v1/lines?source=switch&{bad}", headers=H(plain)).status_code == 422, bad

    r = client.get("/v1/top?source=ruckus-ap&top=2", headers=H(plain)).json()
    assert len(r["top"]) == 2 and r["top"][0]["count"] >= r["top"][1]["count"] and r["window"]["hours"] == 24
    pat = "STA%20(%5B0-9a-f:%5D%7B17%7D)%20IEEE"
    r = client.get(f"/v1/count?source=ruckus-ap&pattern={pat}", headers=H(plain)).json()
    assert r["top"][0] == {"value": fx.MAC_BUSY, "count": 500}
    yesterday = client.get(f"/v1/count?source=ruckus-ap&pattern={pat}&ago=24", headers=H(plain)).json()
    assert yesterday["top"][0]["count"] < 200 and yesterday["window"]["ago"] == 24
    assert client.get("/v1/count?source=ruckus-ap&pattern=", headers=H(plain)).status_code == 400
    for method in ("post", "put", "delete", "patch"):
        assert getattr(client, method)("/v1/lines?source=switch", headers=H(plain)).status_code == 405, "nothing in /v1 changes anything"

    # a bad edit to sources.yml: the API keeps working from the last good one
    import time
    time.sleep(0.01)
    cfg.write_text("sources: [broken\n")
    h = client.get("/v1/health", headers=H(plain)).json()
    assert h["status"] == "degraded" and "not valid YAML" in h["config_error"]
    assert client.get("/v1/lines?source=switch", headers=H(plain)).status_code == 200
    time.sleep(0.01)
    cfg.write_text(fx.SOURCES_YML)


def test_the_two_planes_stay_apart():
    _, plain = tokens.create("probe")
    for method, path in (("get", "/tokens"), ("get", "/logs"), ("get", "/sources"), ("get", "/account"), ("post", "/tokens"), ("post", "/tokens/1/delete"), ("post", "/tokens/1/toggle"), ("post", "/account/password")):
        r = getattr(anon, method)(path, headers=H(plain))
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), f"{path}: a token is not a login"
    assert admin.get("/v1/health").status_code == 401, "a signed-in browser is not accepted on /v1"


def test_setup_login_password():
    r = anon.get("/login")
    assert r.status_code == 303 and r.headers["location"] == "/setup", "no user yet: go to setup"
    assert anon.get("/tokens").headers["location"].startswith("/login")
    assert "Create account" in anon.get("/setup").text
    for form, msg in (({"username": " ", "password": "longenough", "password_confirm": "longenough"}, "Enter a username"), ({"username": "a", "password": "short", "password_confirm": "short"}, "at least 8"), ({"username": "a", "password": "longenough", "password_confirm": "different1"}, "do not match")):
        r = anon.post("/setup", data=form)
        assert r.status_code == 400 and msg in r.text, msg
    with Session(engine) as s:
        assert s.exec(select(User)).first() is None
    r = admin.post("/setup", data={"username": "chris", "password": "correct-horse", "password_confirm": "correct-horse"}, follow_redirects=False)
    assert r.status_code == 303 and admin.get("/account").status_code == 200, "setup signs you in"
    assert anon.get("/setup").headers["location"] == "/login", "setup is closed once there is a user"
    r = anon.post("/setup", data={"username": "evil", "password": "correct-horse", "password_confirm": "correct-horse"})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    with Session(engine) as s:
        assert [u.username for u in s.exec(select(User)).all()] == ["chris"], "a second admin cannot be created through setup"
        assert "correct-horse" not in s.exec(select(User)).first().password_hash

    r = anon.get("/tokens/../tokens?x=1")
    r = anon.get("/logs?source=switch")
    assert r.headers["location"] == "/login?next=%2Flogs%3Fsource%3Dswitch", r.headers["location"]
    r = anon.post("/login", data={"username": "chris", "password": "wrong", "next": "/logs"})
    assert r.status_code == 400 and "Invalid" in r.text and 'name="next" value="/logs"' in r.text
    r = anon.post("/login", data={"username": "chris", "password": "correct-horse", "next": "/logs?source=switch"})
    assert r.status_code == 303 and r.headers["location"] == "/logs?source=switch"
    for evil in ("https://evil.example", "//evil.example", "/\\evil.example", "evil", "/ok\r\nX-Injected: 1"):
        r = TestClient(app, follow_redirects=False).post("/login", data={"username": "chris", "password": "correct-horse", "next": evil})
        assert r.status_code == 303 and r.headers["location"] == "/", f"{evil!r} -> {r.headers['location']}"

    r = admin.post("/account/password", data={"current_password": "nope", "new_password": "another-pass1", "new_password_confirm": "another-pass1"}, follow_redirects=True)
    assert "Current password is incorrect" in r.text
    r = admin.post("/account/password", data={"current_password": "correct-horse", "new_password": "short", "new_password_confirm": "short"}, follow_redirects=True)
    assert "at least 8" in r.text
    r = admin.post("/account/password", data={"current_password": "correct-horse", "new_password": "another-pass1", "new_password_confirm": "another-pass1"}, follow_redirects=True)
    assert "Password updated" in r.text
    assert anon.post("/login", data={"username": "chris", "password": "correct-horse"}).status_code == 400, "the old password no longer works"
    assert anon.post("/login", data={"username": "chris", "password": "another-pass1"}).status_code == 303
    r = admin.post("/logout", follow_redirects=False)
    assert r.status_code == 303 and admin.get("/account", follow_redirects=False).status_code == 303
    admin.post("/login", data={"username": "chris", "password": "another-pass1"})


def test_tokens_page():
    import logging

    logged = []
    handler = logging.Handler()
    handler.emit = lambda record: logged.append(record.getMessage())
    logging.getLogger("loglook").addHandler(handler)
    logging.getLogger("loglook").setLevel(logging.INFO)
    r = admin.post("/tokens", data={"name": "sweep", "note": "nightly", "expires_days": "30"})
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    plain = r.text.split('<pre id="new-token">')[1].split("</pre>")[0]
    assert plain.startswith("loglook_") and tokens.authenticate(plain)[0].name == "sweep"
    listing = admin.get("/tokens")
    assert "sweep" in listing.text and plain not in listing.text, "shown once, never again"
    assert admin.post("/tokens", data={"name": "sweep"}).status_code == 400
    assert "whole number" in admin.post("/tokens", data={"name": "x1", "expires_days": "soon"}).text
    assert "Name must be" in admin.post("/tokens", data={"name": "bad name"}).text
    with Session(engine) as s:
        tid = s.exec(select(ApiToken).where(ApiToken.name == "sweep")).first().id
    admin.post(f"/tokens/{tid}/toggle")
    assert tokens.authenticate(plain)[1] == "token disabled"
    admin.post(f"/tokens/{tid}/delete")
    assert tokens.authenticate(plain)[0] is None
    assert [m.split(" token")[0] for m in logged] == ["admin chris created", "admin chris toggled", "admin chris deleted"], logged
    assert "sweep" in logged[0] and "expires in 30 days" in logged[0]
    logging.getLogger("loglook").removeHandler(handler)


def test_sources_page():
    page = admin.get("/sources").text
    assert "10.42.11.99" in page and "unmapped" in page and "silent-box" in page and "Quiet for longer than expected" in page
    assert "writing logs with no entry in sources.yml: 10.42.11.99" in page
    assert 'href="/logs?source=ruckus-ap"' in page


def test_viewer():
    r = admin.get("/logs?source=ruckus-ap&q=status=fail")
    assert r.status_code == 200 and "<mark>status=fail</mark>" in r.text and "1 matched" in r.text
    assert "Menu" in r.text and 'class="active"' in r.text
    r = admin.get("/logs?source=ruckus-ap&include=No%20free%20worker&q=ThreadLimit")
    assert "<mark>No free worker</mark>" in r.text and "<mark>ThreadLimit</mark>" in r.text
    default = admin.get("/logs")
    assert default.status_code == 200 and "pfsense" in default.text and "lines read" in default.text, "no source given: the first one is shown"
    r = admin.get("/logs?source=ruckus-ap&view=top&exclude=disassociated|status=succ|LogoutAdmin")
    assert r.status_code == 200 and "mping" in r.text and "appweb" in r.text
    r = admin.get("/logs?source=ruckus-ap&view=count&pattern=STA%20(%5B0-9a-f:%5D%7B17%7D)")
    assert fx.MAC_BUSY in r.text and "500" in r.text and "505 lines counted" in r.text
    assert "Enter a pattern" in admin.get("/logs?source=ruckus-ap&view=count").text
    r = admin.get("/logs?source=ruckus-ap&include=(")
    assert r.status_code == 400 and "not a valid regular expression" in r.text
    r = admin.get("/logs?source=nope&hours=999999&ago=-5")
    assert r.status_code == 200, "an unknown source falls back; silly numbers are clamped"
    assert admin.get("/logs?source=switch&hours=abc").status_code == 422, "a non-number is refused, not a crash"

    # whatever the logs contain is escaped, never rendered
    (logs / "syslog-10.9.9.7.log").write_text(f"{fx.stamp(fx.LOCAL_NOW - timedelta(minutes=2))} h <img src=x onerror=alert(1)> and <script>alert(2)</script> ok\n")
    import time
    time.sleep(0.01)
    cfg.write_text(fx.SOURCES_YML + "  10.9.9.7:    {name: nasty}\n")
    (logs / "syslog-10.9.9.7.log").write_text(f"{fx.stamp(fx.LOCAL_NOW - timedelta(minutes=2))} h <img src=x onerror=alert(1)> ok <script>alert(2)</script>\n")
    plain_view = admin.get("/logs?source=nasty")
    assert "<script>alert" not in plain_view.text and "&lt;script&gt;alert(2)&lt;/script&gt;" in plain_view.text, "escaped when nothing is highlighted"
    r = admin.get("/logs?source=nasty&q=%20ok&include=%3Cimg")
    assert "<script>alert" not in r.text and "<img src=x" not in r.text and "&lt;script&gt;alert(2)&lt;/script&gt;" in r.text and "&lt;img" in r.text, "log text is escaped"
    assert "<mark>&lt;img</mark>" in r.text
    time.sleep(0.01)
    cfg.write_text(fx.SOURCES_YML)


def test_login_pauses_after_too_many_wrong_passwords():
    from app.routers import auth as auth_router
    auth_router._failures.clear()
    other = TestClient(app, follow_redirects=False)
    for _ in range(auth_router.MAX_FAILURES):
        assert other.post("/login", data={"username": "chris", "password": "wrong"}).status_code == 400
    r = other.post("/login", data={"username": "chris", "password": "another-pass1"})
    assert r.status_code == 429 and "Too many" in r.text, "even the right password waits"
    assert other.get("/account").status_code == 303
    clock.now = lambda: fx.NOW + timedelta(minutes=11)
    try:
        assert other.post("/login", data={"username": "chris", "password": "another-pass1"}).status_code == 303, "the pause ends"
    finally:
        clock.now = lambda: fx.NOW
        auth_router._failures.clear()
    assert other.post("/login", data={"username": "nobody", "password": "wrong"}).status_code == 400, "an unknown name looks like a wrong password"


def test_changing_the_password_ends_other_sessions():
    a, b = TestClient(app, follow_redirects=False), TestClient(app, follow_redirects=False)
    for c in (a, b):
        assert c.post("/login", data={"username": "chris", "password": "another-pass1"}).status_code == 303
        assert c.get("/account").status_code == 200
    a.post("/account/password", data={"current_password": "another-pass1", "new_password": "third-pass-12", "new_password_confirm": "third-pass-12"})
    assert a.get("/account").status_code == 200, "the session that changed it stays in"
    assert b.get("/account").status_code == 303, "the other one is signed out"
    a.post("/account/password", data={"current_password": "third-pass-12", "new_password": "another-pass1", "new_password_confirm": "another-pass1"})
    admin.post("/login", data={"username": "chris", "password": "another-pass1"})


def test_odd_numbers_do_not_crash_the_pages():
    assert admin.get("/logs?source=switch&hours=nan&ago=nan").status_code == 200
    assert admin.get("/logs?source=switch&hours=inf").status_code == 200
    page = admin.post("/tokens", data={"name": "huge", "expires_days": "9" * 5000})
    assert page.status_code == 400 and "between 1 and" in page.text
    assert "whole number" in admin.post("/tokens", data={"name": "huge", "expires_days": "1e3"}).text


def main():
    test_tokens()
    test_api()
    test_the_two_planes_stay_apart()
    test_setup_login_password()
    test_tokens_page()
    test_sources_page()
    test_viewer()
    test_login_pauses_after_too_many_wrong_passwords()
    test_changing_the_password_ends_other_sessions()
    test_odd_numbers_do_not_crash_the_pages()
    print("OK: tokens are hashed and read-only, /v1 and the pages stay apart, the viewer escapes what it shows.")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(data.parent, ignore_errors=True)
