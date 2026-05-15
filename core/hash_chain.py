"""
hash_chain.py — Forward-secure hash chain for message ordering.

A hash chain ties each message to its predecessor: message N commits to
H(message N-1).  This means an attacker cannot silently drop or reorder
messages — any gap in the chain is immediately visible to the receiver.
This strengthens Integrity beyond what a per-message HMAC alone provides.
"""

import hashlib


class HashChain:
    """Maintains a running SHA-256 hash chain anchored to an initial seed."""

    def __init__(self, seed: bytes) -> None:
        # The seed should be derived from the session key so the chain is
        # unique per session and cannot be pre-computed by an offline attacker.
        self._current: bytes = hashlib.sha256(seed).digest()

    def advance(self) -> bytes:
        """Advance the chain by one step and return the new link value."""
        self._current = hashlib.sha256(self._current).digest()
        return self._current

    @property
    def current(self) -> bytes:
        return self._current

    @staticmethod
    def verify_link(previous: bytes, candidate: bytes) -> bool:
        """Return True iff *candidate* is the correct next link after *previous*."""
        expected_next = hashlib.sha256(previous).digest()
        # Compare in constant time to avoid leaking chain position via timing.
        import hmac as _hmac
        return _hmac.compare_digest(expected_next, candidate)
