from datetime import timedelta

import jwt
import pytest
from fastapi.testclient import TestClient

from jwks_server.app import AUTH_PATH, JWKS_PATH, MOCK_SUBJECT, TOKEN_TTL
from jwks_server.keys import KeyStore

from .conftest import FakeClock


def _public_key_for(client: TestClient, kid: str):
    """Look up ``kid`` in the JWKS document, as a real verifier would."""
    keys = client.get(JWKS_PATH).json()["keys"]
    match = next((jwk for jwk in keys if jwk["kid"] == kid), None)
    return None if match is None else jwt.PyJWK(match).key


def _verify(token: str, key) -> dict:
    """Verify signature and ``exp``. ``iat`` is skipped because the fake clock may run ahead."""
    return jwt.decode(token, key, algorithms=["RS256"], options={"verify_iat": False})


def test_jwks_serves_only_unexpired_keys(client: TestClient, store: KeyStore):
    response = client.get(JWKS_PATH)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")

    kids = [jwk["kid"] for jwk in response.json()["keys"]]
    assert kids == [key.kid for key in store.unexpired_keys()]
    assert store.expired_key().kid not in kids


def test_auth_returns_token_verifiable_with_jwks(client: TestClient):
    response = client.post(AUTH_PATH)
    assert response.status_code == 200

    token = response.text
    kid = jwt.get_unverified_header(token)["kid"]
    key = _public_key_for(client, kid)
    assert key is not None

    claims = _verify(token, key)
    assert claims["sub"] == MOCK_SUBJECT


def test_auth_token_header_contains_kid_and_alg(client: TestClient, store: KeyStore):
    header = jwt.get_unverified_header(client.post(AUTH_PATH).text)
    assert header["alg"] == "RS256"
    assert header["kid"] == store.active_key().kid


def test_auth_token_is_not_expired(client: TestClient, clock: FakeClock):
    token = client.post(AUTH_PATH).text
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert claims["exp"] > int(clock().timestamp())
    assert claims["exp"] - claims["iat"] <= TOKEN_TTL.total_seconds()


def test_auth_accepts_a_body_and_ignores_it(client: TestClient):
    response = client.post(AUTH_PATH, json={"username": "anyone", "password": "anything"})
    assert response.status_code == 200


def test_expired_param_signs_with_expired_key(
    client: TestClient, store: KeyStore, clock: FakeClock
):
    token = client.post(f"{AUTH_PATH}?expired=true").text
    header = jwt.get_unverified_header(token)
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})

    assert header["kid"] == store.expired_key().kid
    assert claims["exp"] == int(store.expired_key().expires_at.timestamp())
    assert claims["exp"] < int(clock().timestamp())

    # The key that signed it is no longer published...
    assert _public_key_for(client, header["kid"]) is None
    # ...but the signature is genuine for the expired key.
    public_key = store.expired_key().private_key.public_key()
    jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={"verify_exp": False, "verify_iat": False},
    )


def test_expired_token_is_rejected_by_a_verifier(client: TestClient, store: KeyStore):
    token = client.post(f"{AUTH_PATH}?expired=true").text
    public_key = store.expired_key().private_key.public_key()
    with pytest.raises(jwt.ExpiredSignatureError):
        _verify(token, public_key)


def test_expired_param_present_without_value(client: TestClient, store: KeyStore):
    token = client.post(f"{AUTH_PATH}?expired").text
    assert jwt.get_unverified_header(token)["kid"] == store.expired_key().kid


def test_auth_after_key_rotation_uses_new_key(
    client: TestClient, store: KeyStore, clock: FakeClock
):
    old_kid = store.active_key().kid
    clock.advance(timedelta(hours=2))

    token = client.post(AUTH_PATH).text
    new_kid = jwt.get_unverified_header(token)["kid"]
    assert new_kid != old_kid
    key = _public_key_for(client, new_kid)
    assert key is not None
    _verify(token, key)


def test_token_never_outlives_its_key(client: TestClient, store: KeyStore, clock: FakeClock):
    clock.advance(timedelta(minutes=50))  # 10 minutes of key life left
    token = client.post(AUTH_PATH).text
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    assert claims["exp"] == int(store.active_key().expires_at.timestamp())


def test_wrong_methods_are_rejected(client: TestClient):
    assert client.get(AUTH_PATH).status_code == 405
    assert client.post(JWKS_PATH).status_code == 405


def test_unknown_route_is_404(client: TestClient):
    assert client.get("/nope").status_code == 404


def test_create_app_builds_default_store():
    from jwks_server.app import create_app

    with TestClient(create_app()) as default_client:
        assert len(default_client.get(JWKS_PATH).json()["keys"]) == 1
