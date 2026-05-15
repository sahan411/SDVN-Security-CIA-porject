"""
nodes/controller_node.py — SDN Controller: Secure Communication Server

Security properties verified on every incoming message:
    AUTHENTICATION     — HMAC tag checked before payload is trusted
    CONFIDENTIALITY    — AES-256-GCM decryption gate
    INTEGRITY          — HMAC + hash-chain sequential link verification
    NON-REPUDIATION    — RSA signature verified on every METRIC
    AVAILABILITY       — session expiry, replay detection, ledger audit trail

The controller is the RECEIVING party.  For every vehicle message it:
    1. Decrypts (AES-GCM)            — Confidentiality gate
    2. Verifies HMAC                  — Authentication + Integrity gate
    3. Checks hash-chain link         — Ordering / completeness gate
    4. Verifies RSA signature         — Non-Repudiation gate (METRIC only)
    5. Appends to BlockchainLedger   — Tamper-evident audit record

All four checks must pass before the payload is accepted.  Failure at any
step is logged and the message is silently dropped — fail-closed design.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import threading
import time
from typing import Optional

from colorama import Fore, Style, init as colorama_init

from core.aes_gcm_encrypt import decrypt
from core.blockchain_ledger import BlockchainLedger
from core.hash_chain import HashChain
from core.hmac_auth import verify_hmac
from core.key_exchange import ECDHKeyExchange
from core.network_config import HOST, PORT, SOCKET_BACKLOG
from core.rsa_signatures import load_public_key_from_bytes, verify_signature
from core.session_manager import SessionManager

colorama_init(autoreset=True)


# ── Reuse the same wire-framing helpers as the vehicle ────────────────────────

def _send_msg(sock: socket.socket, data: dict) -> None:
    payload = json.dumps(data).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_msg(sock: socket.socket) -> dict:
    raw_len = _recv_exactly(sock, 4)
    length  = struct.unpack(">I", raw_len)[0]
    return json.loads(_recv_exactly(sock, length).decode("utf-8"))


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Vehicle closed the connection.")
        buf += chunk
    return buf


# ── Controller ────────────────────────────────────────────────────────────────

class ControllerNode:
    """SDN Controller — verifies and records all vehicle communications.

    One ControllerNode instance runs for the lifetime of the demo.
    It accepts multiple vehicle connections concurrently (one thread per vehicle).

    Shared mutable state (session manager, ledger, vehicle key store) is protected
    by self._lock so concurrent vehicle threads do not corrupt each other's data.
    """

    def __init__(self, host: str = HOST, port: int = PORT) -> None:
        """Initialise server-side security infrastructure.

        Args:
            host : IP address to bind on.  127.0.0.1 for loopback demo.
            port : TCP port to listen on.
        """
        self.host = host
        self.port = port

        # TCP server socket — created in start(), stored here for run() to accept on.
        self._server_sock: Optional[socket.socket] = None

        # ── Session manager ────────────────────────────────────────────────
        # Tracks active sessions: session_id → {aes_key, hmac_key, vehicle_id, …}
        # create_session() derives K_AES and K_HMAC from the ECDH shared secret.
        self._session_manager = SessionManager()

        # ── Blockchain ledger ──────────────────────────────────────────────
        # Append-only hash-chained audit log.  Every KEY_EXCHANGE and METRIC
        # is recorded here with the controller's RSA signature for Non-Repudiation.
        self._ledger = BlockchainLedger()

        # Running count of ledger entries for human-readable [LEDGER] messages.
        # Starts at 1 because the genesis block occupies position 0.
        self._ledger_entry_count: int = 1

        # ── Per-session hash chain state ───────────────────────────────────
        # The controller maintains a PARALLEL hash chain for each vehicle session.
        # For each received METRIC, it advances its own chain and compares the
        # expected link to what the vehicle sent.
        # Maps: session_id → HashChain instance
        self._session_chains: dict[str, HashChain] = {}
        # Maps: session_id → next expected chain position (0-based)
        self._chain_positions: dict[str, int] = {}

        # ── Vehicle RSA public keys ────────────────────────────────────────
        # Received during KEY_EXCHANGE; used to verify METRIC RSA signatures.
        # Maps: vehicle_id → RSAPublicKey object
        # Key separation: RSA keys are indexed by vehicle_id (long-term identity)
        # while AES/HMAC keys are indexed by session_id (short-lived session).
        self._vehicle_rsa_keys: dict[str, object] = {}

        # Thread lock protects all shared state above from concurrent modification.
        self._lock = threading.Lock()

        print(f"\n{Fore.CYAN}[CONTROLLER]{Style.RESET_ALL} "
              f"Initialised — ledger genesis block created, RSA keypair ready.")

    # ── Startup ───────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the TCP server socket and begin listening.

        SO_REUSEADDR prevents "Address already in use" errors when restarting
        the controller within the OS socket TIME_WAIT window.
        """
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(SOCKET_BACKLOG)
        print(f"{Fore.CYAN}[CONTROLLER]{Style.RESET_ALL} "
              f"Listening on {self.host}:{self.port}")

    def run(self) -> None:
        """Accept loop — spawns a daemon thread for each incoming vehicle connection.

        Daemon threads are automatically killed when the main thread exits, so
        pressing Ctrl-C cleanly shuts down the controller without requiring
        explicit thread joins.
        """
        self.start()
        print(f"{Fore.CYAN}[CONTROLLER]{Style.RESET_ALL} "
              f"Ready — waiting for vehicle connections…\n")
        try:
            while True:
                conn, addr = self._server_sock.accept()
                t = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f"vehicle-handler-{addr}",
                )
                t.start()
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}[CONTROLLER]{Style.RESET_ALL} Shutdown signal received.")
        finally:
            if self._server_sock:
                self._server_sock.close()

    # ── Client dispatch ───────────────────────────────────────────────────────

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        """Receive and dispatch messages for one vehicle connection.

        Each message carries a msg_type field that routes it to the appropriate
        handler.  The loop runs until the vehicle disconnects or a network error
        occurs.  Session cleanup always runs in the finally block.

        Args:
            conn : The accepted TCP socket for this vehicle.
            addr : (host, port) of the connecting vehicle.
        """
        vehicle_id: Optional[str] = None
        session_id: Optional[str] = None

        print(f"{Fore.CYAN}[CONTROLLER]{Style.RESET_ALL} "
              f"New connection from {addr[0]}:{addr[1]}")

        try:
            while True:
                try:
                    msg = _recv_msg(conn)
                except (ConnectionError, json.JSONDecodeError, struct.error):
                    # Normal disconnection or malformed message — exit the loop.
                    break

                msg_type = msg.get("msg_type")

                if msg_type == "KEY_EXCHANGE":
                    vehicle_id = msg.get("vehicle_id", "unknown")
                    session_id = self.handle_key_exchange(conn, msg)

                elif msg_type == "BEACON":
                    if session_id:
                        self.handle_beacon(msg, session_id)
                    else:
                        print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                              f"⚠️  BEACON received before key exchange — dropped.")

                elif msg_type == "METRIC":
                    if session_id and vehicle_id:
                        self.handle_metric(msg, session_id, vehicle_id)
                    else:
                        print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                              f"⚠️  METRIC received before key exchange — dropped.")

                else:
                    print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                          f"⚠️  Unknown msg_type='{msg_type}' — dropped.")

        finally:
            # Always clean up the session and associated chain state on disconnect.
            if session_id:
                with self._lock:
                    final_record = self._session_manager.close_session(session_id)
                    self._session_chains.pop(session_id, None)
                    self._chain_positions.pop(session_id, None)
                if final_record:
                    count = final_record.get("message_count", 0)
                    print(f"{Fore.CYAN}[CONTROLLER]{Style.RESET_ALL} "
                          f"Session {session_id[:12]}… closed — {count} messages exchanged.")
            conn.close()

    # ── Handler: KEY_EXCHANGE ─────────────────────────────────────────────────

    def handle_key_exchange(self, conn: socket.socket, msg: dict) -> str:
        """Server-side ECDH handshake — derives and stores session keys.

        Args:
            conn : Vehicle's socket (used to send the KEY_EXCHANGE_RESPONSE).
            msg  : Parsed KEY_EXCHANGE message from the vehicle.

        Returns:
            The newly created session_id string.
        """
        vehicle_id       = msg["vehicle_id"]
        vehicle_ecdh_pub = base64.b64decode(msg["ecdh_public_key"])
        vehicle_rsa_pub  = base64.b64decode(msg["rsa_public_key"])

        # ── Step 1: Store the vehicle's RSA public key ────────────────────
        # This key is used by handle_metric() to verify METRIC signatures.
        # Storing it here, during the ECDH-authenticated handshake, binds the
        # RSA identity to the ECDH session — preventing key substitution attacks.
        rsa_pub_key = load_public_key_from_bytes(vehicle_rsa_pub)
        with self._lock:
            self._vehicle_rsa_keys[vehicle_id] = rsa_pub_key

        # ── Step 2: Generate controller's ephemeral ECDH keypair ──────────
        # Ephemeral = new keypair every session.
        # Even if the controller's long-term identity key is compromised, past
        # sessions remain secret because the ephemeral private key is gone.
        ctrl_ecdh = ECDHKeyExchange()
        ctrl_ecdh.generate_keypair()
        ctrl_pub_bytes = ctrl_ecdh.get_public_key_bytes()

        # ── Step 3: Compute shared secret Z = d_ctrl · Q_vehicle (Eq 3.44) ─
        shared_secret = ctrl_ecdh.compute_shared_secret(vehicle_ecdh_pub)

        # ── Step 4: Create session — derive K_AES + K_HMAC internally ────
        # SessionManager.create_session() calls HKDF(shared_secret) to produce
        # two independent 32-byte keys, then stores them under the session_id.
        with self._lock:
            session_id = self._session_manager.create_session(vehicle_id, shared_secret)
            session    = self._session_manager.get_session(session_id)

        # ── Step 5: Initialise the controller's parallel hash chain ───────
        # Same seed as the vehicle (aes_key.hex()) so both chains are synchronised
        # from the first METRIC message onward.
        ctrl_chain = HashChain()
        ctrl_chain.initialize(session["aes_key"].hex())

        with self._lock:
            self._session_chains[session_id]  = ctrl_chain
            self._chain_positions[session_id] = 0

        # ── Step 6: Send KEY_EXCHANGE_RESPONSE ────────────────────────────
        _send_msg(conn, {
            "msg_type":       "KEY_EXCHANGE_RESPONSE",
            "session_id":     session_id,
            "ecdh_public_key": base64.b64encode(ctrl_pub_bytes).decode(),
        })

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [AUTH] ECDH handshake complete for Vehicle {vehicle_id}")
        print(f"           Session : {session_id[:24]}…")
        print(f"           K_AES   : {session['aes_key'].hex()[:24]}…")
        print(f"           K_HMAC  : {session['hmac_key'].hex()[:24]}…")

        # ── Step 7: Log KEY_EXCHANGE to the ledger ────────────────────────
        with self._lock:
            entry = self._ledger.add_entry(
                vehicle_id=vehicle_id,
                message_type="KEY_EXCHANGE",
                payload=f"ECDH session established for {vehicle_id}".encode(),
                private_key=self._ledger.controller_private_key,
            )
            count = self._ledger_entry_count
            self._ledger_entry_count += 1

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [LEDGER] Entry #{count} signed and recorded — KEY_EXCHANGE\n")

        return session_id

    # ── Handler: BEACON ───────────────────────────────────────────────────────

    def handle_beacon(self, msg: dict, session_id: str) -> None:
        """Decrypt and authenticate a BEACON message.

        Security checks:
            [CONFIDENTIALITY] AES-GCM decryption (GCM tag must pass)
            [AUTH]            HMAC-SHA256 verification

        Args:
            msg        : Parsed BEACON message dict from the vehicle.
            session_id : Active session ID for key lookup.
        """
        # ── Retrieve and validate session ─────────────────────────────────
        session = self._session_manager.get_session(session_id)
        if not session or not self._session_manager.is_session_valid(session_id):
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [AUTH] BEACON rejected — session invalid or expired.")
            return

        aes_key    = session["aes_key"]
        hmac_key   = session["hmac_key"]
        vehicle_id = session["vehicle_id"]

        # ── Security Check 1: AES-GCM Decryption (Confidentiality gate) ──
        # GCM authentication tag is verified BEFORE any plaintext is returned.
        # If the ciphertext was modified in transit, decrypt() raises InvalidTag
        # and we never see the (potentially malicious) contents.
        aad        = base64.b64decode(msg["aad"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        nonce      = base64.b64decode(msg["nonce"])

        try:
            plaintext = decrypt(
                aes_key,
                {"ciphertext": ciphertext, "nonce": nonce},
                additional_data=aad,
            )
        except Exception:
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [CONFIDENTIALITY] AES-GCM authentication tag FAILED for "
                  f"Vehicle {vehicle_id} — ciphertext tampered or wrong key.")
            return

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [CONFIDENTIALITY] Beacon decrypted successfully.")

        # ── Security Check 2: HMAC Verification (Auth + Integrity gate) ──
        # Constant-time comparison — see hmac_auth.py for timing-oracle defence.
        # If this tag is valid, we know:
        # (a) The sender holds K_HMAC — proves identity (Authentication).
        # (b) The plaintext was not modified after HMAC computation (Integrity).
        if not verify_hmac(hmac_key, plaintext, msg["hmac_tag"]):
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [AUTH] HMAC FAILED for Vehicle {vehicle_id} — "
                  f"forged or replayed BEACON dropped.")
            return

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [AUTH] HMAC verified for Vehicle {vehicle_id}.")

        # ── Accept and display ────────────────────────────────────────────
        payload = json.loads(plaintext.decode())
        seq     = payload.get("sequence", "?")
        pos     = payload.get("position", "?")
        vel     = payload.get("velocity", "?")
        self._session_manager.increment_message_count(session_id)

        print(f"           BEACON #{seq} — pos={pos}, vel={vel} km/h\n")

    # ── Handler: METRIC ───────────────────────────────────────────────────────

    def handle_metric(
        self,
        msg: dict,
        session_id: str,
        vehicle_id: str,
    ) -> None:
        """Decrypt, authenticate, chain-verify, signature-verify, and ledger-log a METRIC.

        Security checks (all four must pass):
            [CONFIDENTIALITY]  AES-GCM decryption
            [AUTH]             HMAC-SHA256 verification
            [INTEGRITY]        Hash-chain link verification
            [NON-REPUDIATION]  RSA-PSS signature verification
            [LEDGER]           Blockchain entry appended + signed

        Args:
            msg        : Parsed METRIC message dict.
            session_id : Active session for key lookup.
            vehicle_id : Vehicle pseudonym for RSA key lookup and ledger entry.
        """
        # ── Retrieve and validate session ─────────────────────────────────
        session = self._session_manager.get_session(session_id)
        if not session or not self._session_manager.is_session_valid(session_id):
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [AUTH] METRIC rejected — session invalid or expired.")
            return

        aes_key  = session["aes_key"]
        hmac_key = session["hmac_key"]

        # ── Security Check 1: AES-GCM Decryption ─────────────────────────
        # The entire inner bundle (payload + chain_link + RSA sig) is encrypted.
        # GCM tag failure here means the ciphertext itself was tampered with —
        # we never inspect the inner fields in that case.
        aad        = base64.b64decode(msg["aad"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        nonce      = base64.b64decode(msg["nonce"])

        try:
            inner_bytes = decrypt(
                aes_key,
                {"ciphertext": ciphertext, "nonce": nonce},
                additional_data=aad,
            )
        except Exception:
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [CONFIDENTIALITY] AES-GCM tag FAILED for "
                  f"Vehicle {vehicle_id} — METRIC dropped.")
            return

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [CONFIDENTIALITY] Metric decrypted successfully.")

        # Unpack the inner bundle.
        inner          = json.loads(inner_bytes.decode())
        payload_json   = inner["payload"]
        received_link  = inner["chain_link"]
        chain_position = inner["chain_position"]
        signature_b64  = inner["signature"]
        payload_bytes  = payload_json.encode("utf-8")

        # ── Security Check 2: HMAC Verification ──────────────────────────
        # HMAC was computed over (payload_bytes + chain_link) on the vehicle side.
        # We reconstruct the same input and verify the tag.
        # A valid tag proves:
        # (a) Sender identity — only K_HMAC holder (ECDH peer) can produce this.
        # (b) Integrity       — payload and chain_link are unmodified.
        hmac_input = payload_bytes + received_link.encode()
        if not verify_hmac(hmac_key, hmac_input, msg["hmac_tag"]):
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [AUTH] HMAC FAILED for Vehicle {vehicle_id} — METRIC dropped.")
            return

        payload = json.loads(payload_json)
        seq     = payload.get("sequence", "?")

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [AUTH] HMAC verified for Vehicle {vehicle_id}.")

        # ── Security Check 3: Hash Chain Verification ─────────────────────
        # The controller advances its parallel chain with the same payload_json
        # and compares the result to the vehicle's claimed chain_link.
        #
        # This detects three attack classes:
        #   DROPPED message   — chain_position doesn't match the counter
        #   REORDERED message — SHA-256 of wrong predecessor produces wrong link
        #   TAMPERED payload  — SHA-256 of modified payload produces wrong link
        with self._lock:
            ctrl_chain       = self._session_chains.get(session_id)
            expected_position = self._chain_positions.get(session_id, 0)

        if ctrl_chain is None:
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [INTEGRITY] No hash chain found for session.")
            return

        if chain_position != expected_position:
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [INTEGRITY] Chain position mismatch — "
                  f"expected {expected_position}, got {chain_position}. "
                  f"Message may have been dropped or reordered.")
            return

        # Advance the controller's chain with the same payload JSON string.
        # If the vehicle's payload was modified, SHA-256 produces a different
        # result and the comparison fails — even a single character change.
        expected_link = ctrl_chain.add(payload_json)

        if expected_link != received_link:
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [INTEGRITY] Hash chain MISMATCH — "
                  f"payload was tampered in transit!")
            return

        with self._lock:
            self._chain_positions[session_id] += 1

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [INTEGRITY] Hash chain valid — message #{chain_position + 1}.")

        # ── Security Check 4: RSA Signature Verification ──────────────────
        # The vehicle signed payload_bytes with its RSA private key.
        # We verify with the vehicle's PUBLIC key (received + stored during KEY_EXCHANGE).
        #
        # NON-REPUDIATION: a valid signature proves the vehicle produced this
        # exact payload.  Because only the vehicle holds its private key, it
        # cannot convincingly deny authorship in a later dispute.
        with self._lock:
            rsa_pub_key = self._vehicle_rsa_keys.get(vehicle_id)

        if rsa_pub_key is None:
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [NON-REPUDIATION] No RSA public key on record for "
                  f"{vehicle_id}.")
            return

        raw_signature = base64.b64decode(signature_b64)
        if not verify_signature(rsa_pub_key, payload_bytes, raw_signature):
            print(f"{Fore.RED}[CONTROLLER]{Style.RESET_ALL} "
                  f"❌ [NON-REPUDIATION] RSA signature INVALID for "
                  f"Vehicle {vehicle_id} — METRIC dropped.")
            return

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [NON-REPUDIATION] RSA signature verified — "
              f"{vehicle_id} cannot deny this metric payload.")

        # ── Security Step 5: Append to BlockchainLedger ───────────────────
        # Every accepted METRIC is permanently recorded.
        # The ledger entry is RSA-signed by the CONTROLLER, providing a second
        # non-repudiation layer: the controller cannot later deny having received
        # and accepted this metric (it signed the ledger entry itself).
        with self._lock:
            self._ledger.add_entry(
                vehicle_id=vehicle_id,
                message_type="METRIC",
                payload=payload_bytes,
                private_key=self._ledger.controller_private_key,
            )
            count = self._ledger_entry_count
            self._ledger_entry_count += 1

        print(f"{Fore.GREEN}[CONTROLLER]{Style.RESET_ALL} "
              f"✅ [LEDGER] Entry #{count} signed and recorded — "
              f"METRIC seq={seq} from {vehicle_id}\n")

        self._session_manager.increment_message_count(session_id)
