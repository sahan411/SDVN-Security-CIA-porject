"""
network_config.py — Shared network constants, message schema, and key placeholders.

Everything both parties (VehicleNode and SDNController) need to agree on before a
single packet is exchanged lives here.  Centralising this in one module means a
configuration change (e.g. moving to TLS port 443) never requires hunting across
multiple files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ── Network topology constants ──────────────────────────────────────────────────
#
# HOST is set to loopback so the demo runs entirely on one machine without
# requiring an actual network interface.  In a real SDVN deployment this would
# be the controller's management-plane IP address.
HOST: str = "127.0.0.1"

# Port 9000 is outside the IANA well-known range (0-1023) so it does not require
# elevated privileges to bind, keeping the demo runnable by a normal user account.
PORT: int = 9000

# BUFFER_SIZE caps a single recv() call.  4 KB comfortably holds any control-plane
# message in our schema; oversizing this wastes memory on every socket read.
BUFFER_SIZE: int = 4096

# Maximum number of queued incoming connections on the controller's listen socket.
# A backlog of 5 is the POSIX minimum and sufficient for a sequential demo.
SOCKET_BACKLOG: int = 5

# How long (seconds) a blocking socket call waits before raising TimeoutError.
# Prevents the demo from hanging forever if the peer crashes mid-handshake.
SOCKET_TIMEOUT: float = 10.0


# ── Message types ───────────────────────────────────────────────────────────────
#
# Using an Enum instead of raw strings eliminates an entire class of typo bugs —
# comparing MessageType.BEACON to MessageType.BEACON is always unambiguous,
# whereas comparing "beacon" to "Beacon" is not.
class MessageType(Enum):
    # Vehicle periodically announces its presence and current pseudonym so the
    # controller can maintain a live topology map without polling every node.
    BEACON = auto()

    # Telemetry payload: speed, location, queue depth — whatever the controller
    # needs to make flow-routing decisions.  This is the primary data plane message.
    METRIC = auto()

    # Initiates the ECDH handshake.  Both parties send their public key material
    # inside this message type before any METRIC data is exchanged.
    KEY_EXCHANGE = auto()

    # Notifies the controller that the vehicle wants to append an event to the
    # shared blockchain ledger (e.g. a route deviation or a suspected attack).
    LEDGER_UPDATE = auto()


# ── Wire-format message schema ──────────────────────────────────────────────────
#
# A dataclass gives us __repr__, __eq__, and type-checked fields for free without
# the overhead of a full ORM or serialisation library.  We serialise to JSON via
# dataclasses.asdict() before sending over the wire.
@dataclass
class SecureMessage:
    # Identifies which handler on the receiver should process this message.
    msg_type: MessageType

    # Base-64 encoded ciphertext (output of AES-GCM encryption).  Keeping the
    # payload opaque at this layer means network_config has zero dependency on
    # the crypto modules, so they can be swapped independently.
    payload: str

    # HMAC-SHA256 tag over (msg_type + payload + nonce), hex-encoded.
    # The receiver rejects the message before decrypting if this tag is invalid,
    # preventing padding-oracle and chosen-ciphertext attacks.
    hmac_tag: str

    # 96-bit AES-GCM nonce, base-64 encoded.  Must be unique per (key, message)
    # pair — reusing a nonce under the same key breaks GCM's security entirely.
    nonce: str

    # RSA-2048 signature over SHA-256(payload), base-64 encoded.
    # Present only on METRIC and LEDGER_UPDATE messages; None for BEACON and
    # KEY_EXCHANGE where the sender identity is not yet established.
    signature: Optional[str] = None

    # Monotonically increasing counter that the receiver uses to detect replayed
    # packets.  The controller rejects any message whose sequence number is not
    # strictly greater than the last accepted value from that vehicle.
    sequence_number: int = 0

    # Wall-clock timestamp (Unix epoch, seconds) set by the sender.
    # Used together with sequence_number for replay detection; a message older
    # than REPLAY_WINDOW_SECONDS is rejected even if the sequence number is fresh.
    timestamp: float = field(default_factory=lambda: __import__("time").time())

    # Sender identifier — the vehicle's pseudonym or the controller's node ID.
    # Pseudonyms rotate on a schedule defined in session_manager.py to limit
    # the linkability of beacon messages (privacy against passive observers).
    sender_id: str = "unknown"


# ── Replay-attack prevention window ────────────────────────────────────────────
#
# Any message whose timestamp falls outside this window relative to the receiver's
# clock is silently dropped.  30 seconds balances tolerance for clock skew
# (vehicular networks can have significant GPS-disciplined clock drift) against
# the window an attacker has to replay a captured packet.
REPLAY_WINDOW_SECONDS: float = 30.0


# ── Shared secret key placeholders ─────────────────────────────────────────────
#
# WARNING: These values are DEVELOPMENT PLACEHOLDERS only.
#
# In production they would be provisioned by a secure key management service
# (e.g. HashiCorp Vault, AWS KMS) and injected at runtime via environment
# variables — never hard-coded in source and never committed to version control.
#
# The placeholder bytes are intentionally obvious (not random) so that a code
# reviewer immediately recognises them as stubs rather than accidentally treating
# them as real keys.

# 256-bit pre-shared key used to bootstrap HMAC authentication before the ECDH
# session key is established.  Both parties must hold this value out-of-band.
# In a real SDVN deployment this would be provisioned during vehicle registration.
PRE_SHARED_KEY: bytes = os.environb.get(
    b"SDVN_PSK",
    b"PLACEHOLDER_32_BYTE_KEY_REPLACE_ME!"  # exactly 32 bytes — AES-256 compatible
)

# 256-bit key used exclusively for HMAC operations on BEACON messages.
# Separating it from PRE_SHARED_KEY follows the principle of key separation:
# a compromise of the HMAC key does not compromise AES confidentiality.
HMAC_KEY: bytes = os.environb.get(
    b"SDVN_HMAC_KEY",
    b"PLACEHOLDER_HMAC_KEY_32_BYTES!!"   # exactly 32 bytes
)

# Human-readable label for the ECDH key-derivation function (HKDF info parameter).
# Including a domain-specific label prevents key material derived for one protocol
# from being misused in a different context (domain separation).
HKDF_INFO: bytes = b"sdvn-v1-session-key"

# Salt fed into HKDF.  Should be a fresh random value per session in production;
# using a fixed salt here simplifies the demo without breaking correctness.
HKDF_SALT: bytes = b"sdvn-demo-salt-2025"
