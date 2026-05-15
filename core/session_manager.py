"""
session_manager.py — Session token lifecycle and pseudonym rotation.

Manages the per-session state that lives between the ECDH handshake and
the end of a communication session.  Pseudonym rotation (changing the
vehicle's identifier on a schedule) limits the ability of a passive
observer to correlate beacon messages to a specific physical vehicle,
protecting location privacy without breaking Authentication.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field


# Rotate the vehicle pseudonym every 5 minutes to prevent long-term tracking.
# Shorter windows improve privacy but require more frequent re-authentication.
PSEUDONYM_ROTATION_INTERVAL: float = 300.0


@dataclass
class Session:
    """All mutable state for one authenticated session between two parties."""

    session_id: str
    session_key: bytes          # 32-byte AES-256 key derived from ECDH
    peer_id: str
    created_at: float = field(default_factory=time.time)
    last_sequence: int = 0      # Highest sequence number accepted — used for replay detection
    pseudonym: str = field(default_factory=lambda: os.urandom(8).hex())

    def is_expired(self, max_age_seconds: float = 3600.0) -> bool:
        """Sessions older than max_age_seconds must re-authenticate from scratch."""
        return (time.time() - self.created_at) > max_age_seconds

    def accept_sequence(self, seq: int) -> bool:
        """Return True and advance the counter iff *seq* is strictly greater than last seen.

        Strict monotonicity means a replayed packet (same seq) or out-of-order
        delivery is rejected, preventing replay attacks.
        """
        if seq <= self.last_sequence:
            return False
        self.last_sequence = seq
        return True

    def rotate_pseudonym(self) -> str:
        """Derive a new pseudonym from the current one via hash to maintain unlinkability."""
        self.pseudonym = hashlib.sha256(self.pseudonym.encode()).hexdigest()[:16]
        return self.pseudonym


class SessionManager:
    """In-memory store of active sessions, keyed by session_id."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create_session(self, session_key: bytes, peer_id: str) -> Session:
        session_id = os.urandom(16).hex()
        session = Session(session_id=session_id, session_key=session_key, peer_id=peer_id)
        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def remove_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
