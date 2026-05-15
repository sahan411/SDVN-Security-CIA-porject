"""
rsa_signatures.py — RSA-2048 digital signatures for Non-Repudiation.

Unlike HMAC (symmetric — both parties share the key), RSA signatures use
asymmetric keys: only the holder of the private key can sign, but anyone
with the public key can verify.  This provides Non-Repudiation — the vehicle
cannot later deny sending a message because only it holds its private key.

Key size: 2048 bits is the current NIST minimum for production use through 2030.
Padding: PSS is used instead of PKCS#1 v1.5 because PSS is provably secure
         under the RSA assumption; v1.5 has known theoretical weaknesses.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


def generate_rsa_keypair(key_size: int = 2048) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate a fresh RSA key pair.  In production, load from secure storage instead."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def sign(message: bytes, private_key: RSAPrivateKey) -> str:
    """Return a base-64 encoded PSS signature over SHA-256(*message*)."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            # Maximum salt length maximises the security proof tightness.
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def verify(message: bytes, signature_b64: str, public_key: RSAPublicKey) -> bool:
    """Return True iff the signature is valid; False if it has been forged or corrupted.

    Catches InvalidSignature rather than propagating it, because callers should
    treat a bad signature as a boolean security decision, not an exception path.
    """
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def serialize_public_key(public_key: RSAPublicKey) -> str:
    """Export the public key as a PEM string for transmission or storage."""
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def load_public_key(pem: str) -> RSAPublicKey:
    """Reconstruct a public key from a PEM string received from the peer."""
    return serialization.load_pem_public_key(pem.encode())  # type: ignore[return-value]
