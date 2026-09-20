"""Shared fixtures. RSA generation is slow, so the store is built once per test."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from jwks_server.app import create_app
from jwks_server.keys import KeyStore


class FakeClock:
    """A controllable clock so expiry and rotation can be tested deterministically."""

    def __init__(self) -> None:
        self.current = datetime.now(UTC).replace(microsecond=0)

    def __call__(self) -> datetime:
        return self.current

    def advance(self, delta: timedelta) -> None:
        self.current += delta


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(clock: FakeClock) -> KeyStore:
    return KeyStore(lifetime=timedelta(hours=1), clock=clock)


@pytest.fixture
def client(store: KeyStore) -> TestClient:
    return TestClient(create_app(store))
