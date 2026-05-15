"""
core/session_manager.py — Authenticated Session Lifecycle Management

Security property : AUTHENTICATION + AVAILABILITY
Course concept    : Session management, key separation, replay prevention

═══════════════════════════════════════════════════════════════════════════════
WHY SESSION KEY SEPARATION MATTERS
═══════════════════════════════════════════════════════════════════════════════

After the ECDH handshake (core/key_exchange.py) produces a shared secret Z,
we derive TWO distinct keys instead of reusing one key for everything:

    K_AES  — used exclusively by AES-256-GCM for payload encryption
    K_HMAC — used exclusively by HMAC-SHA256 for message authentication

Why not reuse a single key for both?

    1. Cross-protocol weaknesses
       Cryptographic primitives make assumptions about their key's usage.
       AES-GCM treats its key as input to a block cipher; HMAC-SHA256 treats
       its key as a PRF seed.  Using the same key for both means a theoretical
       weakness in one primitive could expose the key to the other.

    2. Key wear and the "birthday bound"
       The more operations a key participates in, the more ciphertext an
       attacker can collect and analyse.  Splitting operations across two keys
       halves the exposure of each individual key.

    3. Auditability and revocation
       Two separate keys allow the AES key to be rotated independently of the
       HMAC key — useful if one subsystem is suspected compromised.

    In SIGMA-V terms, K_AES protects the METRIC payload (Confidentiality) while
    K_HMAC authenticates the SecureMessage envelope (Integrity + Authentication).
    These are separate security services and must be served by separate keys.

═══════════════════════════════════════════════════════════════════════════════
SESSION TIMEOUT AND AVAILABILITY
═══════════════════════════════════════════════════════════════════════════════

Sessions expire after SESSION_TIMEOUT_SECONDS (default 60 s).  This is short
by web-app standards but appropriate for vehicular networks because:

    • A vehicle may leave radio range without sending an explicit disconnect.
    • Stale sessions accumulate memory on the controller — a resource-exhaustion
      vector (denial of service) if sessions never expire (Availability concern).
    • Short session lifetimes limit the window an attacker has to exploit a
      compromised session key before it is discarded (limits blast radius).

After expiry the controller must re-run the ECDH handshake to establish a
fresh session, which also rotates the vehicle's pseudonym (privacy benefit).

═══════════════════════════════════════════════════════════════════════════════
SESSION ID GENERATION
═══════════════════════════════════════════════════════════════════════════════

Session IDs are 128-bit random values from the OS CSPRNG.  This ensures:

    • Unpredictability: an attacker cannot enumerate or predict valid session IDs.
    • Collision resistance: with 2^128 possible values, the probability of two
      sessions sharing an ID is negligible even across millions of vehicles.

    Do NOT use sequential integers or timestamp-based IDs — both are guessable.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Optional


# Sessions older than this are considered expired and will be rejected.
# 60 seconds matches the short-lived SIGMA-V pseudonym rotation window.
SESSION_TIMEOUT_SECONDS: float = 60.0


class SessionManager:
    """In-process store of active authenticated sessions.

    Each session record holds:
        aes_key       — 32-byte AES-256-GCM encryption key  (K_AES  from HKDF)
        hmac_key      — 32-byte HMAC-SHA256 auth key        (K_HMAC from HKDF)
        vehicle_id    — the vehicle's pseudonym at session creation time
        created_at    — Unix timestamp of session creation (float)
        message_count — number of SecureMessages exchanged in this session

    The manager intentionally stores only the derived keys (not the raw shared
    secret Z).  Once the session keys are derived, Z has no further use and
    should be garbage-collected — keeping it around only adds attack surface.
    """

    def __init__(self) -> None:
        # _sessions maps session_id (str) -> session record (dict).
        # In production this would be backed by a thread-safe store (e.g.
        # a Redis cache with TTL) to support concurrent vehicle connections.
        self._sessions: dict[str, dict] = {}

    # ── Session lifecycle ───────────────────────────────────────────────────

    def create_session(self, vehicle_id: str, shared_secret: bytes) -> str:
        """Derive session keys from *shared_secret* and register a new session.

        Args:
            vehicle_id    : The vehicle's current pseudonym (rotates per session).
                            Used for logging and ledger entries — NOT as a secret.
            shared_secret : Raw ECDH output bytes from ECDHKeyExchange.compute_shared_secret().
                            The manager derives K_AES and K_HMAC from this value
                            using HKDF, then discards the raw secret immediately.

        Returns:
            A 32-character hex session ID.  The vehicle must include this in
            every subsequent SecureMessage so the controller can look up the
            correct K_AES and K_HMAC for that conversation.

        Key derivation happens here (not in key_exchange.py) so that the
        SessionManager is the single source of truth for which keys are active.
        This makes key rotation and session revocation straightforward.
        """
        # Import here to avoid a circular-import between session_manager and
        # key_exchange at module load time.
        from core.key_exchange import ECDHKeyExchange

        # Derive the two session keys via HKDF.  We instantiate a throw-away
        # ECDHKeyExchange object purely for its derive_session_key() method —
        # no ECDH operation is performed at this point.
        ecdh = ECDHKeyExchange()
        keys = ecdh.derive_session_key(shared_secret)

        # 128-bit random session ID — see module docstring on unpredictability.
        session_id = os.urandom(16).hex()

        self._sessions[session_id] = {
            "aes_key": keys["aes_key"],       # 32 bytes — AES-256-GCM key
            "hmac_key": keys["hmac_key"],     # 32 bytes — HMAC-SHA256 key
            "vehicle_id": vehicle_id,          # pseudonym at handshake time
            "created_at": time.time(),         # Unix epoch float
            "message_count": 0,                # incremented on every received message
        }

        return session_id

    def get_session(self, session_id: str) -> Optional[dict]:
        """Return the session record for *session_id*, or None if not found.

        Args:
            session_id: The ID returned by create_session().

        Returns:
            A copy of the session dict (to prevent callers from mutating internal
            state directly) or None if the session does not exist.

        Note: this method does NOT check expiry.  Call is_session_valid() first
        if you need to enforce the timeout — separating the two concerns allows
        callers to retrieve an expired session for logging without accidentally
        rejecting it twice.
        """
        record = self._sessions.get(session_id)
        if record is None:
            return None
        # Return a shallow copy so callers cannot accidentally modify the live record.
        return dict(record)

    def increment_message_count(self, session_id: str) -> None:
        """Atomically increment the message counter for *session_id*.

        The message count serves two purposes:
            1. Observability — the controller can log how many messages a
               vehicle sent in a session (useful for anomaly detection).
            2. Rate limiting — a controller can close sessions that exceed an
               expected message frequency (flood-attack mitigation).

        Silently ignored if the session does not exist, because the caller
        (a message handler) should not crash on a lookup miss — it should
        simply reject the message via is_session_valid().
        """
        if session_id in self._sessions:
            self._sessions[session_id]["message_count"] += 1

    def is_session_valid(self, session_id: str) -> bool:
        """Return True iff the session exists AND has not exceeded its timeout.

        Args:
            session_id: The session ID to validate.

        Returns:
            True  — session is live and within SESSION_TIMEOUT_SECONDS.
            False — session does not exist, or has expired.

        Timeout check:
            age = now - created_at
            Valid iff age <= SESSION_TIMEOUT_SECONDS

            A 60-second window is tight enough to limit replay exposure but
            long enough to survive a METRIC message burst from a fast-moving
            vehicle (see module docstring for rationale).

        Expired sessions are NOT automatically removed here — close_session()
        is a deliberate controller action so that the expiry event can be
        logged to the BlockchainLedger before the record is discarded.
        """
        record = self._sessions.get(session_id)
        if record is None:
            # Unknown session ID — could be a forged or replayed session cookie.
            return False

        age = time.time() - record["created_at"]
        if age > SESSION_TIMEOUT_SECONDS:
            # Session has lived past its maximum age — reject further messages.
            # The controller should call close_session() and log this expiry.
            return False

        return True

    def close_session(self, session_id: str) -> Optional[dict]:
        """Remove *session_id* from the active store and return its final record.

        Args:
            session_id: The session to close.

        Returns:
            The final session record (useful for logging to BlockchainLedger)
            or None if the session was not found (idempotent — safe to call twice).

        Security: removing the record also removes K_AES and K_HMAC from memory.
        Python's garbage collector will overwrite the memory in due course.
        For high-security deployments, explicitly zero the key bytes before
        deletion using ctypes or a dedicated secrets library.
        """
        return self._sessions.pop(session_id, None)

    # ── Diagnostics ─────────────────────────────────────────────────────────

    def active_session_count(self) -> int:
        """Return the number of currently registered sessions (includes expired)."""
        return len(self._sessions)

    def purge_expired(self) -> list[str]:
        """Remove all sessions that have exceeded SESSION_TIMEOUT_SECONDS.

        Returns:
            List of session IDs that were purged.

        Call this periodically (e.g. on every incoming connection) to prevent
        unbounded memory growth — a stale-session accumulation is a slow-burn
        denial-of-service vector against the controller's memory.
        """
        now = time.time()
        expired = [
            sid for sid, record in self._sessions.items()
            if (now - record["created_at"]) > SESSION_TIMEOUT_SECONDS
        ]
        for sid in expired:
            self._sessions.pop(sid, None)
        return expired
