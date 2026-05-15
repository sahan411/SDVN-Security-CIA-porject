"""
aes_gcm_encrypt.py — AES-256-GCM authenticated encryption.

GCM mode provides both Confidentiality (ciphertext reveals nothing about
plaintext) and Integrity (the authentication tag detects any modification to
the ciphertext or associated data).  Using both properties in one primitive
is safer than combining separate encryption and MAC schemes, where ordering
mistakes (Encrypt-then-MAC vs MAC-then-Encrypt) can introduce subtle flaws.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# GCM nonce MUST be 96 bits (12 bytes) per NIST SP 800-38D recommendation.
# Any other length forces an expensive GHASH pre-computation and weakens security.
NONCE_BYTES: int = 12


def encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> tuple[str, str]:
    """Encrypt *plaintext* under *key* and return (ciphertext_b64, nonce_b64).

    *aad* (Additional Authenticated Data) is bound into the authentication tag
    but not encrypted — ideal for header fields that must be readable in transit
    (e.g. message type, sender ID) but must not be tampered with.
    """
    nonce = os.urandom(NONCE_BYTES)  # Fresh random nonce — never reuse under the same key.
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad or None)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(nonce).decode()


def decrypt(ciphertext_b64: str, nonce_b64: str, key: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate; raises InvalidTag if the ciphertext was tampered with."""
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    aesgcm = AESGCM(key)
    # AESGCM.decrypt raises cryptography.exceptions.InvalidTag automatically —
    # the caller should treat that exception as a hard security failure.
    return aesgcm.decrypt(nonce, ciphertext, aad or None)
