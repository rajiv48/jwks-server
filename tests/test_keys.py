import base64
from datetime import UTC, datetime, timedelta

from jwks_server.keys import KeyRecord, KeyStore, generate_key, utcnow

from .conftest import FakeClock


def _b64url_to_int(value: str) -> int:
    padded = value + "=" * (-len(value) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(padded), "big")


def test_utcnow_is_timezone_aware():
    assert utcnow().tzinfo is not None


def test_generate_key_has_unique_kid_and_2048_bit_modulus():
    expiry = datetime(2030, 1, 1, tzinfo=UTC)
    first, second = generate_key(expiry), generate_key(expiry)
    assert first.kid != second.kid
    assert first.private_key.key_size == 2048
    assert first.expires_at == expiry


def test_is_expired_boundary():
    expiry = datetime(2030, 1, 1, tzinfo=UTC)
    record = KeyRecord(kid="k", private_key=generate_key(expiry).private_key, expires_at=expiry)
    assert not record.is_expired(expiry - timedelta(seconds=1))
    assert record.is_expired(expiry)


def test_to_jwk_matches_public_numbers_and_hides_private_material():
    record = generate_key(datetime(2030, 1, 1, tzinfo=UTC))
    jwk = record.to_jwk()
    numbers = record.private_key.public_key().public_numbers()

    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == record.kid
    assert _b64url_to_int(jwk["n"]) == numbers.n
    assert _b64url_to_int(jwk["e"]) == numbers.e
    assert "=" not in jwk["n"]
    assert not {"d", "p", "q", "dp", "dq", "qi"} & jwk.keys()


def test_store_starts_with_one_valid_and_one_expired_key(store: KeyStore, clock: FakeClock):
    valid = store.unexpired_keys()
    assert len(valid) == 1
    assert valid[0].expires_at > clock()
    assert store.expired_key().expires_at <= clock()
    assert store.expired_key().kid != valid[0].kid


def test_active_key_is_the_unexpired_key(store: KeyStore):
    assert store.active_key().kid == store.unexpired_keys()[0].kid


def test_now_uses_injected_clock(store: KeyStore, clock: FakeClock):
    assert store.now() == clock()


def test_key_expires_and_store_rotates(store: KeyStore, clock: FakeClock):
    original = store.active_key()
    clock.advance(timedelta(hours=1))

    rotated = store.active_key()
    assert rotated.kid != original.kid
    assert not rotated.is_expired(clock())
    # The original key is now expired and must no longer be served.
    assert original.kid not in {key.kid for key in store.unexpired_keys()}
    assert store.expired_key().expires_at == original.expires_at


def test_unexpired_keys_never_empty_after_expiry(store: KeyStore, clock: FakeClock):
    clock.advance(timedelta(days=1))
    assert len(store.unexpired_keys()) == 1
