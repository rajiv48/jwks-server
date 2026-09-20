"""FastAPI application exposing the JWKS and authentication endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

from jwks_server.keys import KeyRecord, KeyStore

JWKS_PATH = "/.well-known/jwks.json"  # idiomatic well-known JWKS URI (RFC 8615)
AUTH_PATH = "/auth"
TOKEN_TTL = timedelta(minutes=30)
MOCK_SUBJECT = "userABC"  # authentication is mocked for this project
ALGORITHM = "RS256"


def issue_token(record: KeyRecord, now: datetime, *, expired: bool) -> str:
    """Sign a JWT with ``record``; the ``kid`` header lets verifiers find the key.

    A normal token never outlives the key that signed it. An "expired" token
    uses the key's own (past) expiry as its ``exp`` claim.
    """
    if expired:
        exp = record.expires_at
        iat = exp - TOKEN_TTL
    else:
        iat = now
        exp = min(now + TOKEN_TTL, record.expires_at)

    claims = {
        "sub": MOCK_SUBJECT,
        "iat": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(
        claims,
        record.private_key,
        algorithm=ALGORITHM,
        headers={"kid": record.kid},
    )


def create_app(store: KeyStore | None = None) -> FastAPI:
    """Build the application. A custom ``store`` can be injected for testing."""
    key_store = store if store is not None else KeyStore()
    app = FastAPI(title="JWKS Server", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get(JWKS_PATH)
    def jwks() -> dict[str, list[dict[str, str]]]:
        """Serve the public keys that have not expired, in JWKS format."""
        return {"keys": [key.to_jwk() for key in key_store.unexpired_keys()]}

    @app.post(AUTH_PATH, response_class=PlainTextResponse)
    def auth(request: Request) -> str:
        """Mock-authenticate the caller and return a signed JWT.

        If the ``expired`` query parameter is present (with any value, or none)
        the token is signed with the expired key and carries an expired ``exp``.
        No request body or credentials are inspected.
        """
        expired = "expired" in request.query_params
        record = key_store.expired_key() if expired else key_store.active_key()
        return issue_token(record, key_store.now(), expired=expired)

    return app
