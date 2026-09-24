"""Token lifecycle, password change/reset, API keys, sign-out-everywhere."""

import jwt

from conftest import scan_payload


def test_access_token_is_short_lived_and_typed(client, auth, app):
    H, session = auth()
    payload = jwt.decode(session["token"], app.config["SECRET_KEY"], algorithms=["HS256"])
    assert payload["typ"] == "access"
    assert payload["exp"] - payload["iat"] == app.config["JWT_EXPIRY_HOURS"] * 3600
    assert session["expires_in"] == app.config["JWT_EXPIRY_HOURS"] * 3600


def test_refresh_rotates_and_old_token_dies(client, auth):
    H, session = auth()
    r = client.post("/api/auth/refresh", json={"refresh_token": session["refresh_token"]})
    assert r.status_code == 200
    new = r.get_json()
    assert new["refresh_token"] != session["refresh_token"]
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {new['token']}"}).status_code == 200
    # The used refresh token is now revoked.
    assert client.post("/api/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": "garbage"}).status_code == 401


def test_logout_revokes_refresh_token(client, auth):
    H, session = auth()
    assert client.post("/api/auth/logout", json={"refresh_token": session["refresh_token"]}).status_code == 200
    assert client.post("/api/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401


def test_logout_all_invalidates_access_tokens(client, auth):
    H, session = auth()
    assert client.get("/api/auth/me", headers=H).status_code == 200
    assert client.post("/api/auth/logout-all", headers=H).status_code == 200
    r = client.get("/api/auth/me", headers=H)
    assert r.status_code == 401 and r.get_json()["code"] == "token_revoked"
    assert client.post("/api/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401


def test_change_password(client, auth):
    H, _ = auth(password="password123")
    assert client.post("/api/auth/password", json={"current_password": "wrong", "new_password": "newpassword9"}, headers=H).status_code == 401
    assert client.post("/api/auth/password", json={"current_password": "password123", "new_password": "short"}, headers=H).status_code == 400
    r = client.post("/api/auth/password", json={"current_password": "password123", "new_password": "newpassword9"}, headers=H)
    assert r.status_code == 200
    fresh = r.get_json()
    # Old access token is dead, the fresh one works, new password logs in.
    assert client.get("/api/auth/me", headers=H).status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {fresh['token']}"}).status_code == 200
    assert client.post("/api/auth/login", json={"email": "a@t.io", "password": "password123"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "a@t.io", "password": "newpassword9"}).status_code == 200


def test_forgot_and_reset_password(client, auth):
    auth(email="a@t.io", password="password123")
    # Unknown address: same 200, no token.
    r = client.post("/api/auth/forgot", json={"email": "nobody@t.io"})
    assert r.status_code == 200 and "dev_reset_token" not in r.get_json()
    # Known address in development without SMTP: token is surfaced.
    r = client.post("/api/auth/forgot", json={"email": "a@t.io"})
    token = r.get_json().get("dev_reset_token")
    assert token
    assert client.post("/api/auth/reset", json={"token": "bad", "password": "newpassword9"}).status_code == 400
    assert client.post("/api/auth/reset", json={"token": token, "password": "short"}).status_code == 400
    r = client.post("/api/auth/reset", json={"token": token, "password": "newpassword9"})
    assert r.status_code == 200 and "token" in r.get_json()
    # Single use.
    assert client.post("/api/auth/reset", json={"token": token, "password": "another999"}).status_code == 400
    assert client.post("/api/auth/login", json={"email": "a@t.io", "password": "newpassword9"}).status_code == 200


def test_reset_token_not_leaked_in_production(auth, app):
    from conftest import make_app
    prod = make_app(IS_PRODUCTION=True, ENV="production")
    c = prod.test_client()
    c.post("/api/auth/register", json={"email": "p@t.io", "name": "P", "password": "password123"})
    r = c.post("/api/auth/forgot", json={"email": "p@t.io"})
    assert r.status_code == 200 and "dev_reset_token" not in r.get_json()


def test_api_keys(client, auth, project):
    H, _, proj = project
    assert client.post("/api/auth/api-keys", json={"name": ""}, headers=H).status_code == 400
    r = client.post("/api/auth/api-keys", json={"name": "ci"}, headers=H)
    assert r.status_code == 201
    body = r.get_json()
    key = body["key"]
    assert key.startswith("pwp_") and body["hint"].startswith("pwp_")
    listed = client.get("/api/auth/api-keys", headers=H).get_json()
    assert len(listed) == 1 and "key" not in listed[0]

    # The key authenticates on both header forms and tags scans as trigger=api.
    KH = {"X-API-Key": key}
    assert client.get("/api/auth/me", headers=KH).get_json()["auth"] == "api_key"
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {key}"}).status_code == 200
    r = client.post("/api/scan", json=scan_payload(proj["id"]), headers=KH)
    assert r.status_code == 200 and r.get_json()["trigger"] == "api"
    # Account management is refused for API keys.
    assert client.post("/api/auth/api-keys", json={"name": "x"}, headers=KH).status_code == 403
    assert client.post("/api/auth/password", json={}, headers=KH).status_code == 403

    assert client.delete(f"/api/auth/api-keys/{body['id']}", headers=H).status_code == 200
    assert client.get("/api/auth/me", headers=KH).status_code == 401
    assert client.get("/api/auth/me", headers={"X-API-Key": "pwp_nope"}).status_code == 401


def test_api_key_isolation(client, auth):
    HA, _ = auth("a@t.io")
    HB, _ = auth("b@t.io")
    kid = client.post("/api/auth/api-keys", json={"name": "a"}, headers=HA).get_json()["id"]
    assert client.delete(f"/api/auth/api-keys/{kid}", headers=HB).status_code == 404
