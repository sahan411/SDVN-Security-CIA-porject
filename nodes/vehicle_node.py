"""
nodes/vehicle_node.py — Vehicle Node: Secure Communication Client

Security properties demonstrated:
    CONFIDENTIALITY    — AES-256-GCM encrypts every payload
    INTEGRITY          — HMAC-SHA256 + hash chain on every message
    AUTHENTICATION     — ECDH session keys prove mutual identity
    NON-REPUDIATION    — RSA-2048 signature on every METRIC message

Protocol flow:
    1. TCP connect to Controller
    2. ECDH KEY_EXCHANGE  → derive K_AES and K_HMAC
    3. send_beacon()      → HMAC + AES-GCM
    4. send_metric()      → hash chain + RSA sign + HMAC + AES-GCM
    5. close()
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import time
from typing import Optional

from colorama import Fore, Style, init as colorama_init

from core.aes_gcm_encrypt import decrypt, encrypt
from core.hash_chain import HashChain
from core.hmac_auth import generate_hmac
from core.key_exchange import ECDHKeyExchange
from core.network_config import HOST, PORT
from core.rsa_signatures import generate_keypair, serialize_public_key, sign

colorama_init(autoreset=True)


# ── Wire-level framing helpers ────────────────────────────────────────────────
# Messages are length-prefixed:  [4-byte big-endian uint32 length][JSON bytes]
# A length prefix is more robust than newline-delimited JSON because JSON values
# may legally contain newlines, which would break a delimiter-based parser.

def _send_msg(sock: socket.socket, data: dict) -> None:
    """Serialise *data* to JSON and send it with a 4-byte length prefix."""
    payload = json.dumps(data).encode("utf-8")
    # >I = big-endian unsigned 32-bit integer — safe for messages up to 4 GB
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_msg(sock: socket.socket) -> dict:
    """Read one length-prefixed JSON message from *sock* and return it as a dict."""
    raw_len = _recv_exactly(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    return json.loads(_recv_exactly(sock, length).decode("utf-8"))


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Block until exactly *n* bytes are read; raises ConnectionError on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Controller closed the connection unexpectedly.")
        buf += chunk
    return buf


# ── Vehicle Node ──────────────────────────────────────────────────────────────

class VehicleNode:
    """Represents one vehicle in the SDVN network.

    Each VehicleNode independently generates ephemeral ECDH and RSA key material
    so that two VehicleNode instances cannot share or impersonate each other's
    cryptographic identity — even if they run in the same process during a demo.
    """

    def __init__(self, vehicle_id: str, host: str = HOST, port: int = PORT) -> None:
        """Initialise crypto components before any network connection is made.

        Args:
            vehicle_id : Human-readable pseudonym (e.g. "V001").
                         In a real SIGMA-V deployment this rotates on a schedule
                         to limit linkability of beacon messages.
            host       : Controller's IP address.
            port       : Controller's listening port.
        """
        self.vehicle_id = vehicle_id
        self.host = host
        self.port = port

        # TCP socket — created here but not connected until connect() is called.
        # Using SOCK_STREAM (TCP) guarantees ordered, reliable delivery, which the
        # hash-chain integrity check depends on (gaps in delivery break the chain).
        self._sock: Optional[socket.socket] = None

        # ── Session state (populated during perform_key_exchange()) ──────────
        self._session_id: Optional[str] = None
        self._aes_key:    Optional[bytes] = None   # K_AES  — 32 bytes
        self._hmac_key:   Optional[bytes] = None   # K_HMAC — 32 bytes

        # ── ECDH — ephemeral per session ─────────────────────────────────────
        # A fresh ECDHKeyExchange object is created here.  After the handshake
        # the private scalar d is held inside this object and discarded when the
        # object is garbage-collected, providing forward secrecy.
        self._ecdh = ECDHKeyExchange()

        # ── Hash chain — integrity + ordering ────────────────────────────────
        # Initialised during key exchange (seed = session AES key) so the chain
        # is unique per session and cannot be pre-computed by an offline attacker.
        self._hash_chain = HashChain()
        self._chain_position: int = 0   # how many messages have been added so far

        # ── RSA keypair — non-repudiation ────────────────────────────────────
        # Long-lived within a session: the vehicle signs every METRIC message with
        # its private key.  The controller stores the matching public key (received
        # during KEY_EXCHANGE) and uses it to verify signatures — proving the
        # vehicle cannot later deny having sent a specific metric payload.
        self._rsa_private_key, self._rsa_public_key = generate_keypair()

        # ── Sequence counter — replay prevention ──────────────────────────────
        # Monotonically increasing per-session.  The controller rejects any message
        # whose sequence number is not strictly greater than the last accepted value.
        self._sequence: int = 0

        print(f"{Fore.CYAN}[VEHICLE {vehicle_id}]{Style.RESET_ALL} Initialised — RSA-2048 keypair generated.")

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Open a TCP connection to the controller.

        Must be called before perform_key_exchange() or any send_* method.
        """
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Socket timeout prevents the vehicle from blocking forever if the
        # controller crashes mid-protocol — an important availability safeguard.
        self._sock.settimeout(10.0)
        self._sock.connect((self.host, self.port))

        print(f"{Fore.CYAN}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"TCP connected → {self.host}:{self.port}")

    # ── Key exchange ──────────────────────────────────────────────────────────

    def perform_key_exchange(self) -> None:
        """Execute the ECDH handshake and derive session keys.

        After this method returns, self._aes_key and self._hmac_key are set and
        the hash chain is initialised.  All subsequent messages are protected
        by these session keys.

        Protocol (Eq 3.42–3.45 in SIGMA-V FYP):
            Vehicle → Controller : {msg_type=KEY_EXCHANGE,
                                    vehicle_id,
                                    ecdh_public_key (DER/b64),
                                    rsa_public_key  (DER/b64)}

            Controller → Vehicle : {msg_type=KEY_EXCHANGE_RESPONSE,
                                    session_id,
                                    ecdh_public_key (DER/b64)}
        """
        # ── Step 1: Generate ephemeral ECDH keypair (Eq 3.42) ─────────────
        # d_V ← random scalar ; Q_V = d_V · G
        # "Ephemeral" means a fresh keypair every session — the private scalar
        # d_V is discarded after the shared secret is computed, giving forward secrecy.
        self._ecdh.generate_keypair()
        ecdh_pub_bytes = self._ecdh.get_public_key_bytes()

        # ── Step 2: Serialise the vehicle's RSA public key for transmission ──
        # The controller must store this to verify future RSA signatures.
        # Sending it during the authenticated handshake binds the RSA identity
        # to the ECDH-established session — preventing public-key substitution attacks.
        rsa_pub_bytes = serialize_public_key(self._rsa_public_key)

        # ── Step 3: Send KEY_EXCHANGE to controller ───────────────────────
        _send_msg(self._sock, {
            "msg_type": "KEY_EXCHANGE",
            "vehicle_id": self.vehicle_id,
            "ecdh_public_key": base64.b64encode(ecdh_pub_bytes).decode(),
            "rsa_public_key":  base64.b64encode(rsa_pub_bytes).decode(),
        })
        print(f"{Fore.YELLOW}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"KEY_EXCHANGE sent — ECDH public key transmitted.")

        # ── Step 4: Receive controller's ECDH public key (Eq 3.43) ───────
        response = _recv_msg(self._sock)
        assert response["msg_type"] == "KEY_EXCHANGE_RESPONSE", (
            f"Unexpected response: {response.get('msg_type')}"
        )
        self._session_id = response["session_id"]
        ctrl_ecdh_pub = base64.b64decode(response["ecdh_public_key"])

        # ── Step 5: Compute shared secret Z = d_V · Q_C (Eq 3.44) ────────
        # Both parties compute the same Z without ever transmitting it.
        # An eavesdropper who sees Q_V and Q_C cannot compute Z because the
        # Elliptic Curve Discrete Logarithm Problem is computationally infeasible.
        shared_secret = self._ecdh.compute_shared_secret(ctrl_ecdh_pub)

        # ── Step 6: Derive K_AES and K_HMAC via HKDF (Eq 3.45) ──────────
        # HKDF stretches Z into two independent 32-byte keys.
        # Using separate keys for AES and HMAC enforces key separation:
        # a weakness exploited against HMAC cannot leak the AES key.
        keys = self._ecdh.derive_session_key(shared_secret)
        self._aes_key  = keys["aes_key"]
        self._hmac_key = keys["hmac_key"]

        # ── Step 7: Initialise hash chain ────────────────────────────────
        # Seed = aes_key.hex() — session-unique, unknown to any third party.
        # This anchors the chain to THIS session so a recorded chain from a
        # previous session cannot be spliced in by a replay attacker.
        self._hash_chain.initialize(self._aes_key.hex())

        print(f"{Fore.GREEN}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"✅ Session {self._session_id[:12]}… established.")
        print(f"{Fore.GREEN}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"✅ Session keys derived (K_AES + K_HMAC via HKDF-SHA256).")
        print(f"{Fore.GREEN}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"✅ Hash chain initialised (seed = session AES key).")

    # ── Messaging ─────────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        """Increment and return the per-session sequence counter."""
        self._sequence += 1
        return self._sequence

    def send_beacon(self, position: tuple, velocity: float) -> None:
        """Broadcast an HMAC-authenticated, AES-GCM encrypted BEACON.

        BEACON messages announce the vehicle's presence and kinematics so the
        controller can maintain a live topology map without polling each node.

        Security stack applied:
            HMAC-SHA256    — proves sender identity + detects payload tampering
            AES-256-GCM    — hides position/velocity from passive observers

        Args:
            position : (latitude, longitude) in decimal degrees.
            velocity : Speed in km/h.
        """
        assert self._aes_key and self._hmac_key, \
            "perform_key_exchange() must complete before sending messages."

        seq = self._next_seq()

        # ── Construct inner plaintext payload ──────────────────────────────
        payload = {
            "vehicle_id": self.vehicle_id,
            "position":   list(position),   # list is JSON-serialisable; tuple is not
            "velocity":   velocity,
            "sequence":   seq,
            "timestamp":  time.time(),
        }
        # sort_keys=True ensures deterministic serialisation — the HMAC tag
        # depends on exact byte order, so both sides must agree on field order.
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")

        # ── Security Step 1: HMAC for Authentication + Integrity ──────────
        # HMAC-SHA256(K_HMAC, payload_bytes) proves:
        # (a) AUTH:      only a party holding K_HMAC (derived from the ECDH
        #                session) could have produced this tag — proving our identity.
        # (b) INTEGRITY: any single-bit flip in payload_bytes produces a
        #                completely different tag, catching in-transit tampering.
        hmac_tag = generate_hmac(self._hmac_key, payload_bytes)

        # ── Security Step 2: AES-GCM Encryption for Confidentiality ───────
        # The msg_type and session_id are passed as AAD (Additional Authenticated
        # Data): they are readable in transit (needed for routing) but bound into
        # the GCM authentication tag — any modification to the header is detected.
        aad = f"BEACON:{self._session_id}".encode()
        bundle = encrypt(self._aes_key, payload_bytes, additional_data=aad)

        # ── Transmit ───────────────────────────────────────────────────────
        _send_msg(self._sock, {
            "msg_type":   "BEACON",
            "session_id": self._session_id,
            "ciphertext": base64.b64encode(bundle["ciphertext"]).decode(),
            "nonce":      base64.b64encode(bundle["nonce"]).decode(),
            "hmac_tag":   hmac_tag,
            "aad":        base64.b64encode(aad).decode(),
            "sequence":   seq,
        })
        print(f"{Fore.YELLOW}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"BEACON #{seq} sent — pos={position}, vel={velocity} km/h.")

    def send_metric(self, metric_data: dict) -> None:
        """Send a fully secured METRIC telemetry message.

        METRIC messages carry sensor readings (speed, GPS, queue depth, etc.)
        to inform the controller's flow-routing decisions.

        Full security stack applied (in order):
            1. Hash chain    — integrity + ordering of the message sequence
            2. RSA signature — non-repudiation (vehicle cannot deny this payload)
            3. HMAC-SHA256   — session authentication + integrity of signed content
            4. AES-256-GCM   — confidentiality of all metric values

        Args:
            metric_data : Arbitrary dict of telemetry fields
                          e.g. {"speed_kmh": 72, "gps": [51.50, -0.12], "fuel_pct": 64}
        """
        assert self._aes_key and self._hmac_key, \
            "perform_key_exchange() must complete before sending messages."

        seq = self._next_seq()
        current_position = self._chain_position

        # ── Construct inner plaintext payload ──────────────────────────────
        payload = {
            "vehicle_id": self.vehicle_id,
            "sequence":   seq,
            "timestamp":  time.time(),
            "data":       metric_data,
        }
        payload_json  = json.dumps(payload, sort_keys=True)
        payload_bytes = payload_json.encode("utf-8")

        # ── Security Step 1: Hash Chain for Integrity + Ordering ──────────
        # chain_link = SHA256(payload_json_bytes || previous_chain_link)
        # Every message commits to all prior messages through the chain.
        # The controller maintains a parallel chain and compares links:
        #   • A DROPPED message breaks the chain (position mismatch).
        #   • A REORDERED message produces a wrong link (SHA-256 avalanche).
        #   • A TAMPERED payload produces a different link (SHA-256 changes completely).
        chain_link = self._hash_chain.add(payload_json)
        self._chain_position += 1

        # ── Security Step 2: RSA Signature for Non-Repudiation ────────────
        # sign(private_key, payload_bytes) → raw signature bytes
        # Only the vehicle holds its RSA private key, so a valid signature
        # over payload_bytes is cryptographic proof that THIS vehicle authored
        # this exact metric payload.  If the vehicle later denies sending it,
        # the controller presents (payload_bytes, signature, vehicle_public_key)
        # and any third party can verify the claim independently.
        # We sign the PLAINTEXT (not ciphertext) so the signature covers the
        # semantic content — Sign-then-Encrypt ordering.
        raw_signature = sign(self._rsa_private_key, payload_bytes)

        # ── Security Step 3: HMAC over payload + chain link ───────────────
        # Including chain_link in the HMAC input binds the authentication tag
        # to this specific position in the message sequence.
        # Without this, an attacker could replace the chain_link field with a
        # value from a different position while leaving the HMAC valid.
        hmac_input = payload_bytes + chain_link.encode()
        hmac_tag   = generate_hmac(self._hmac_key, hmac_input)

        # ── Security Step 4: AES-GCM Encryption ───────────────────────────
        # Pack all security artefacts into the inner bundle before encryption.
        # After AES-GCM the entire bundle — payload, chain link, and RSA sig —
        # is opaque ciphertext.  The GCM authentication tag additionally covers
        # the AAD (msg_type + session_id), making the header tamper-proof too.
        inner = json.dumps({
            "payload":        payload_json,
            "chain_link":     chain_link,
            "chain_position": current_position,
            "signature":      base64.b64encode(raw_signature).decode(),
        }).encode("utf-8")

        aad        = f"METRIC:{self._session_id}".encode()
        enc_bundle = encrypt(self._aes_key, inner, additional_data=aad)

        # ── Transmit ───────────────────────────────────────────────────────
        _send_msg(self._sock, {
            "msg_type":   "METRIC",
            "session_id": self._session_id,
            "ciphertext": base64.b64encode(enc_bundle["ciphertext"]).decode(),
            "nonce":      base64.b64encode(enc_bundle["nonce"]).decode(),
            "hmac_tag":   hmac_tag,
            "aad":        base64.b64encode(aad).decode(),
            "sequence":   seq,
        })
        print(f"{Fore.YELLOW}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"METRIC #{seq} sent — chain pos={current_position}, "
              f"link={chain_link[:12]}…")

    # ── Teardown ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Gracefully shut down the TCP connection."""
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Already closed by the remote end — safe to ignore.
            self._sock.close()
            self._sock = None
        print(f"{Fore.CYAN}[VEHICLE {self.vehicle_id}]{Style.RESET_ALL} "
              f"Disconnected — session closed.")
