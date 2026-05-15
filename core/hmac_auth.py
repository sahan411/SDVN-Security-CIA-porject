"""
hmac_auth.py — HMAC-SHA256 message authentication.

Provides Integrity + Authentication at the message level.  Every packet
leaving either party carries an HMAC tag; the receiver rejects the message
before touching the payload if the tag does not match.  This stops both
accidental corruption and deliberate tampering (Integrity) and proves the
sender holds the shared HMAC key (Authentication).
"""

import hmac
import hashlib

from core.network_config import HMAC_KEY


def compute_hmac(message: bytes, key: bytes = HMAC_KEY) -> str:
    """Return hex-encoded HMAC-SHA256 of *message* under *key*."""
    tag = hmac.new(key, message, hashlib.sha256).hexdigest()
    return tag


def verify_hmac(message: bytes, expected_tag: str, key: bytes = HMAC_KEY) -> bool:
    """Return True iff the recomputed HMAC matches *expected_tag*.

    Uses hmac.compare_digest to prevent timing-oracle attacks — a plain
    string comparison leaks information about how many leading bytes match.
    """
    actual_tag = compute_hmac(message, key)
    return hmac.compare_digest(actual_tag, expected_tag)
