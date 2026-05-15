"""
key_exchange.py — ECDH key exchange and HKDF session-key derivation.

Ephemeral ECDH on P-256 gives us forward secrecy: even if the pre-shared key
is later compromised, past session keys cannot be recovered because the ECDH
private keys are discarded after the handshake.  This directly addresses the
Authentication property by ensuring both parties contribute entropy to the
session key — a passive observer who records the handshake cannot derive it.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePublicKey,
    generate_private_key,
    SECP256R1,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

from core.network_config import HKDF_INFO, HKDF_SALT


class ECDHParty:
    """One side of an ECDH key exchange (Vehicle or Controller)."""

    def __init__(self) -> None:
        # A fresh ephemeral private key per session ensures forward secrecy.
        self._private_key = generate_private_key(SECP256R1())

    def public_key_bytes(self) -> bytes:
        """Serialise the public key to DER for transmission over the wire."""
        return self._private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def derive_session_key(self, peer_public_key_bytes: bytes) -> bytes:
        """Perform ECDH then HKDF to produce a 32-byte AES-256 session key."""
        peer_key: EllipticCurvePublicKey = load_der_public_key(peer_public_key_bytes)  # type: ignore[assignment]
        shared_secret = self._private_key.exchange(ECDH(), peer_key)

        # HKDF stretches and domain-separates the raw ECDH output.
        # Without this step, the raw shared secret has non-uniform distribution
        # and is unsuitable for direct use as an AES key.
        session_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=HKDF_SALT,
            info=HKDF_INFO,
        ).derive(shared_secret)

        return session_key
