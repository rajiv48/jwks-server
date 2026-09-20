"""RSA key management: generation, expiry tracking and JWK serialisation."""

from __future__ import annotations

import base64
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537
DEFAULT_KEY_LIFETIME = timedelta(hours=1)

Clock = Callable[[], datetime]


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def _b64url_uint(value: int) -> str:
    """Encode a positive integer as unpadded base64url (RFC 7518 section 2)."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class KeyRecord:
    """An RSA key pair together with its key ID (``kid``) and expiry time."""

    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        """Return True if the key has reached its expiry time at ``now``."""
        return self.expires_at <= now

    def to_jwk(self) -> dict[str, str]:
        """Serialise the *public* half of the key as a JWK (RFC 7517).

        Only the modulus and exponent are exposed; the private key never
        leaves this process.
        """
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


def generate_key(expires_at: datetime) -> KeyRecord:
    """Create a new RSA key pair with a random, unique ``kid``."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
    )
    return KeyRecord(kid=uuid.uuid4().hex, private_key=private_key, expires_at=expires_at)


class KeyStore:
    """Holds every key the server has generated and answers expiry queries.

    On start-up the store creates one key that is valid for ``lifetime`` and one
    key that is already expired (used to demonstrate the "expired" flow).
    If the active key later expires while the server is running, a fresh one is
    generated on demand so the server can always issue valid tokens.
    """

    def __init__(
        self,
        lifetime: timedelta = DEFAULT_KEY_LIFETIME,
        clock: Clock = utcnow,
    ) -> None:
        """Generate the initial valid and expired keys."""
        self._lifetime = lifetime
        self._clock = clock
        self._lock = threading.Lock()
        now = clock()
        self._keys: list[KeyRecord] = [
            generate_key(now - lifetime),
            generate_key(now + lifetime),
        ]

    def now(self) -> datetime:
        """Return the store's notion of the current time."""
        return self._clock()

    def unexpired_keys(self) -> list[KeyRecord]:
        """Return all keys that have not expired (never an empty list)."""
        with self._lock:
            now = self._clock()
            self._ensure_active_locked(now)
            return [key for key in self._keys if not key.is_expired(now)]

    def active_key(self) -> KeyRecord:
        """Return the unexpired key that lives longest, rotating if needed."""
        with self._lock:
            now = self._clock()
            self._ensure_active_locked(now)
            valid = [key for key in self._keys if not key.is_expired(now)]
            return max(valid, key=lambda key: key.expires_at)

    def expired_key(self) -> KeyRecord:
        """Return the most recently expired key."""
        with self._lock:
            now = self._clock()
            expired = [key for key in self._keys if key.is_expired(now)]
            return max(expired, key=lambda key: key.expires_at)

    def _ensure_active_locked(self, now: datetime) -> None:
        """Generate a new key if none is valid. Caller must hold the lock."""
        if all(key.is_expired(now) for key in self._keys):
            self._keys.append(generate_key(now + self._lifetime))
