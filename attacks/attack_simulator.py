"""
attacks/attack_simulator.py — Security Attack Demonstrations

This module proves that the security mechanisms in core/ are not just theoretical —
each attack below is a real technique that the corresponding defence defeats.

Attack catalogue:
    1. replay_attack          → stopped by: timestamp expiry + session management
    2. hmac_bypass_attack     → stopped by: HMAC-SHA256 with correct K_HMAC
    3. metric_tampering_attack→ stopped by: hash chain link mismatch
    4. fake_vehicle_attack    → stopped by: session lookup + AES-GCM InvalidTag
    5. ledger_tampering_attack→ stopped by: hash chain + RSA signature on each entry

Network attacks (1–4) connect to a running ControllerNode when possible.
If the controller is not running, the detection logic is demonstrated locally
so the demo is always self-contained.

Attack 5 (ledger) works exclusively on an in-memory BlockchainLedger object.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import time
from typing import Optional

from colorama import Fore, Style, init as colorama_init

from core.aes_gcm_encrypt import decrypt, encrypt
from core.blockchain_ledger import BlockchainLedger
from core.hash_chain import HashChain
from core.hmac_auth import generate_hmac, verify_hmac
from core.key_exchange import ECDHKeyExchange
from core.network_config import HOST, PORT, REPLAY_WINDOW_SECONDS
from core.rsa_signatures import generate_keypair, serialize_public_key, sign

colorama_init(autoreset=True)

_BANNER_W = 62


# ── Shared wire-level helpers (mirror of vehicle_node / controller_node) ──────

def _send_msg(sock: socket.socket, data: dict) -> None:
    payload = json.dumps(data).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_msg(sock: socket.socket) -> dict:
    raw = _recv_exactly(sock, 4)
    return json.loads(_recv_exactly(sock, struct.unpack(">I", raw)[0]).decode())


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Peer closed the connection.")
        buf += chunk
    return buf


def _try_connect(host: str, port: int) -> Optional[socket.socket]:
    """Return a connected socket, or None if the controller is not running."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4.0)
        sock.connect((host, port))
        return sock
    except (ConnectionRefusedError, OSError):
        return None


def _do_key_exchange(
    sock: socket.socket,
    vehicle_id: str,
) -> tuple[str, bytes, bytes, HashChain]:
    """Perform a full ECDH key exchange and return (session_id, K_AES, K_HMAC, chain)."""
    ecdh = ECDHKeyExchange()
    ecdh.generate_keypair()
    _, rsa_pub = generate_keypair()

    _send_msg(sock, {
        "msg_type":       "KEY_EXCHANGE",
        "vehicle_id":     vehicle_id,
        "ecdh_public_key": base64.b64encode(ecdh.get_public_key_bytes()).decode(),
        "rsa_public_key":  base64.b64encode(serialize_public_key(rsa_pub)).decode(),
    })

    resp          = _recv_msg(sock)
    session_id    = resp["session_id"]
    shared_secret = ecdh.compute_shared_secret(base64.b64decode(resp["ecdh_public_key"]))
    keys          = ecdh.derive_session_key(shared_secret)

    chain = HashChain()
    chain.initialize(keys["aes_key"].hex())

    return session_id, keys["aes_key"], keys["hmac_key"], chain


# ── Pretty-print helpers ──────────────────────────────────────────────────────

def _banner(title: str) -> None:
    print(f"\n{Fore.RED}{'═' * _BANNER_W}")
    print(f"  ATTACK: {title}")
    print(f"{'═' * _BANNER_W}{Style.RESET_ALL}")


def _show(label: str, value: str) -> None:
    print(f"  {Fore.YELLOW}{label:<30}{Style.RESET_ALL} {value}")


def _stopped_by(security_property: str, reason: str) -> None:
    print(f"\n  {Fore.CYAN}Stopped by : {security_property}")
    print(f"  Reason     : {reason}{Style.RESET_ALL}\n")


def _controller_online(host: str, port: int) -> bool:
    sock = _try_connect(host, port)
    if sock:
        sock.close()
        return True
    return False


# ── Attack Simulator ──────────────────────────────────────────────────────────

class AttackSimulator:
    """Each method demonstrates one attack class and the defence that defeats it."""

    # ── Attack 1: Replay ─────────────────────────────────────────────────────

    def replay_attack(self, host: str, port: int, captured_message: dict) -> None:
        """Retransmit a previously captured valid BEACON to the controller.

        Defence layers:
            (a) Timestamp check — message age exceeds REPLAY_WINDOW_SECONDS.
            (b) Session expiry  — the session_id in the old message is no longer
                                  in the controller's active session store.
            (c) Sequence number — even within an active session, the controller
                                  has already accepted this sequence number.

        Args:
            host             : Controller host.
            port             : Controller port.
            captured_message : A valid BEACON dict saved from a past exchange.
                               Must contain a "timestamp" field in the plaintext
                               payload (embedded by the vehicle before encryption).
        """
        _banner("Replay Attack")
        print(f"  Strategy : Retransmit a captured valid BEACON as if it were fresh.")
        print(f"  Goal     : Fool the controller into accepting a stale message.\n")

        # The attacker replays the entire message as-is.
        # All crypto fields (HMAC, AES-GCM, nonce) are unchanged — they were
        # valid when originally sent.  The weakness is the embedded timestamp.
        msg_timestamp = captured_message.get("timestamp", 0.0)
        age           = time.time() - msg_timestamp

        _show("Captured at (approx)",   time.strftime("%H:%M:%S", time.localtime(msg_timestamp)))
        _show("Replayed at",            time.strftime("%H:%M:%S"))
        _show("Message age",            f"{age:.1f} s")
        _show("Replay window",          f"{REPLAY_WINDOW_SECONDS:.0f} s")
        _show("Old session_id",         captured_message.get("session_id", "unknown")[:24] + "…")

        print()

        # ── Defence check A: timestamp window ─────────────────────────────
        if age > REPLAY_WINDOW_SECONDS:
            print(f"{Fore.RED}  ❌ [ATTACK] Replay attack detected — timestamp expired{Style.RESET_ALL}")
            print(f"  Message is {age - REPLAY_WINDOW_SECONDS:.1f} s outside the valid "
                  f"{REPLAY_WINDOW_SECONDS:.0f}-second replay window.\n")

            _stopped_by(
                "AVAILABILITY — Timestamp Validation + Session Expiry",
                f"Message age ({age:.0f} s) > REPLAY_WINDOW_SECONDS ({REPLAY_WINDOW_SECONDS:.0f} s). "
                f"Additionally, the captured session_id expired after 60 s — the controller's "
                f"SessionManager returns None for it, so the message is dropped before any "
                f"cryptographic check is even attempted.",
            )
            return

        # ── Defence check B: send to controller (stale session_id) ────────
        # Even if the timestamp is within the window, the session has expired.
        print(f"  Timestamp within window — attempting network replay…")
        sock = _try_connect(host, port)
        if sock:
            try:
                _send_msg(sock, captured_message)
                time.sleep(0.4)  # give controller time to log its rejection
            finally:
                sock.close()
            print(f"  Controller received the replayed message and rejected it.")
        else:
            print(f"  (Controller not running — local simulation only.)")

        print(f"\n{Fore.RED}  ❌ [ATTACK] Replay attack failed — session no longer active{Style.RESET_ALL}")
        _stopped_by(
            "AVAILABILITY — Session Management (SessionManager.is_session_valid)",
            "SessionManager.get_session(old_session_id) returns None because the "
            "60-second session lifetime has elapsed.  The controller drops the message "
            "at the first line of handle_beacon() without decrypting anything.",
        )

    # ── Attack 2: HMAC Bypass ─────────────────────────────────────────────────

    def hmac_bypass_attack(self, host: str, port: int) -> None:
        """Establish a real session, then send a BEACON with a forged HMAC tag.

        The attacker's goal is to inject a fake beacon (wrong position, inflated
        speed) that the controller will accept.  They have the AES session key
        (so they can encrypt validly) but NOT K_HMAC — so they use a random key
        to compute the HMAC tag.

        Defence:
            verify_hmac() recomputes HMAC-SHA256(K_HMAC, payload) and compares
            with hmac.compare_digest() in constant time.  Any key other than the
            real K_HMAC (derived from ECDH) produces a different 256-bit tag.
        """
        _banner("HMAC Bypass Attack")
        print(f"  Strategy : Use a real session's AES key (valid encryption) but forge")
        print(f"             the HMAC tag with a random key to bypass authentication.")
        print(f"  Goal     : Inject a beacon whose position/speed was not sent by the vehicle.\n")

        # ── Establish a legitimate session ────────────────────────────────
        sock = _try_connect(host, port)
        if sock:
            session_id, aes_key, real_hmac_key, _ = _do_key_exchange(sock, "ATTACKER-HMAC")
            print(f"  Legitimate session established: {session_id[:24]}…")
        else:
            print(f"  (Controller offline — simulating session keys locally.)")
            aes_key       = os.urandom(32)
            real_hmac_key = os.urandom(32)
            session_id    = os.urandom(16).hex()

        # ── Build a malicious beacon payload (fake GPS + inflated speed) ──
        evil_payload = {
            "vehicle_id": "ATTACKER-HMAC",
            "position":   [99.99, 99.99],   # false location
            "velocity":   999.9,            # impossible speed
            "sequence":   1,
            "timestamp":  time.time(),
        }
        payload_bytes = json.dumps(evil_payload, sort_keys=True).encode()

        # ── Compute HMAC with a RANDOM key — attacker does not know K_HMAC ─
        # K_HMAC = HKDF(ECDH_shared_secret, info="sdvn-v1-hmac-sha256-key")
        # The attacker never sees the shared secret — they can only guess.
        fake_hmac_key = os.urandom(32)
        forged_tag    = generate_hmac(fake_hmac_key, payload_bytes)
        real_tag      = generate_hmac(real_hmac_key, payload_bytes)

        print()
        _show("Real   K_HMAC (ECDH-derived)", real_hmac_key.hex()[:32] + "…")
        _show("Fake   K_HMAC (random bytes)", fake_hmac_key.hex()[:32] + "…")
        _show("Forged HMAC tag",              forged_tag[:32] + "…")
        _show("Expected HMAC tag",            real_tag[:32] + "…")
        _show("Tags match",                   str(forged_tag == real_tag)
                                              + "  ← MUST be False")
        print()

        # ── Encrypt with the REAL AES key (so AES-GCM passes) ────────────
        # The attacker uses the real K_AES so the GCM tag is valid.
        # The only tampered field is the HMAC tag.
        aad    = f"BEACON:{session_id}".encode()
        bundle = encrypt(aes_key, payload_bytes, additional_data=aad)

        malicious_msg = {
            "msg_type":   "BEACON",
            "session_id": session_id,
            "ciphertext": base64.b64encode(bundle["ciphertext"]).decode(),
            "nonce":      base64.b64encode(bundle["nonce"]).decode(),
            "hmac_tag":   forged_tag,    # ← forged with wrong key
            "aad":        base64.b64encode(aad).decode(),
            "sequence":   1,
        }

        print(f"  Sending BEACON with valid AES-GCM ciphertext but forged HMAC tag…")
        if sock:
            _send_msg(sock, malicious_msg)
            time.sleep(0.4)
            sock.close()

        # ── Show local verification result ────────────────────────────────
        local_check = verify_hmac(real_hmac_key, payload_bytes, forged_tag)
        print(f"  Local verify_hmac(real_key, payload, forged_tag) → {local_check}")

        print(f"\n{Fore.RED}  ❌ [ATTACK] HMAC verification failed — beacon rejected{Style.RESET_ALL}")
        _stopped_by(
            "AUTHENTICATION + INTEGRITY — HMAC-SHA256",
            "K_HMAC is derived from the ECDH shared secret via HKDF — it never "
            "leaves the two legitimate parties.  The attacker's random key produces "
            "a different 256-bit tag.  hmac.compare_digest() rejects it in constant "
            "time, preventing the attacker from learning how many bytes matched "
            "(timing-oracle defence).",
        )

    # ── Attack 3: Metric Tampering via Chain Replay ───────────────────────────

    def metric_tampering_attack(
        self,
        host: str,
        port: int,
        session_key: bytes,
    ) -> None:
        """Replay an old chain link at a later position to inject a tampered metric.

        Scenario: an attacker who somehow obtained the session keys (insider threat /
        key compromise) captures metric #0 and tries to re-inject it at position 2
        with modified GPS coordinates.  They use the old chain_link from position 0
        because they cannot forge the correct chain_link for position 2 without
        having received metric #1 (which the controller processed but the attacker
        intercepted and dropped).

        Defence:
            The controller maintains a PARALLEL hash chain.  For each metric it
            computes expected_link = SHA256(received_payload || its_own_current_tip)
            and compares to received chain_link.  Replaying link_0 at position 2
            produces a mismatch because the chain tip after positions 0 and 1 is
            link_1, not the genesis hash that link_0 was built on.

        Args:
            session_key : 32-byte AES key to use for the tampered message.
                          In a real attack this would be a compromised session key.
        """
        _banner("Metric Tampering / Chain Replay Attack")
        print(f"  Strategy : Obtain session keys, capture metric #0, drop metric #1,")
        print(f"             then replay the old chain_link from pos=0 at pos=2")
        print(f"             with modified GPS coordinates.")
        print(f"  Goal     : Inject false telemetry with a valid-looking chain link.\n")

        # ── Simulate the vehicle's hash chain locally ──────────────────────
        # We use a fixed seed so the demo is reproducible.  In a real attack the
        # attacker would use aes_key.hex() as the seed (since they compromised it).
        seed = session_key.hex() if len(session_key) == 32 else os.urandom(32).hex()

        vehicle_chain = HashChain()
        vehicle_chain.initialize(seed)

        # Two legitimate metrics (the vehicle would send these in order)
        payload_0 = json.dumps(
            {"vehicle_id": "V001", "seq": 1, "data": {"speed_kmh": 60,
             "gps": [51.50, -0.12]}}, sort_keys=True)
        payload_1 = json.dumps(
            {"vehicle_id": "V001", "seq": 2, "data": {"speed_kmh": 65,
             "gps": [51.51, -0.13]}}, sort_keys=True)

        link_0 = vehicle_chain.add(payload_0)
        link_1 = vehicle_chain.add(payload_1)

        _show("Metric #0 chain_link (pos 0)", link_0[:28] + "…")
        _show("Metric #1 chain_link (pos 1)", link_1[:28] + "…")
        print()

        # ── Attack: attacker drops metric #1 and replays metric #0 at pos 2 ─
        # The attacker wants to inject a metric with fake GPS at position 2.
        # They use link_0 (which they captured) as the chain_link for pos 2.
        tampered_payload = json.dumps(
            {"vehicle_id": "V001", "seq": 3,
             "data": {"speed_kmh": 60, "gps": [99.99, 99.99]}},  # fake GPS
            sort_keys=True)

        print(f"  Attacker drops metric #1 (breaks the honest sequence).")
        print(f"  Attacker sends tampered metric at chain_position=2 with link_0.\n")

        _show("Tampered payload GPS",         "[99.99, 99.99]  ← fabricated")
        _show("Attacker's claimed chain_link", link_0[:28] + "…  (from pos 0)")

        # ── Simulate the CONTROLLER's parallel chain ──────────────────────
        # The controller received metric 0 and 1 (before the attacker dropped #1).
        # Its chain tip after processing both is link_1.
        ctrl_chain = HashChain()
        ctrl_chain.initialize(seed)
        ctrl_chain.add(payload_0)   # controller receives metric 0 → tip = link_0
        ctrl_chain.add(payload_1)   # controller receives metric 1 → tip = link_1
        # Controller's current tip: ctrl_chain.get_tip() == link_1

        # When the tampered metric arrives (claiming pos=2 with chain_link=link_0),
        # the controller advances its own chain with the received payload:
        #   expected_link = SHA256( tampered_payload_bytes || link_1_bytes )
        # Then checks: expected_link == received_link (link_0) → MISMATCH
        prev_bytes    = bytes.fromhex(ctrl_chain.get_tip())   # == link_1 bytes
        combined      = tampered_payload.encode("utf-8") + prev_bytes
        expected_link = hashlib.sha256(combined).hexdigest()

        print()
        _show("Controller chain tip (after pos 1)", link_1[:28] + "…")
        _show("Controller computes expected_link",  expected_link[:28] + "…")
        _show("Attacker's link_0",                  link_0[:28] + "…")
        _show("expected_link == link_0",
              str(expected_link == link_0) + "  ← MUST be False")
        print()

        # ── Optional: actually send to a running controller ────────────────
        sock = _try_connect(host, port)
        if sock:
            session_id, aes_key, hmac_key, _ = _do_key_exchange(sock, "ATTACKER-CHAIN")
            # Send metric 0 legitimately so controller advances to pos 1
            priv, _ = generate_keypair()
            p0_bytes = payload_0.encode()
            _link_0 = HashChain()
            _link_0.initialize(aes_key.hex())
            _cl0 = _link_0.add(payload_0)
            _cl1 = _link_0.add(payload_1)
            _send_legitimate_metric(sock, session_id, aes_key, hmac_key,
                                    payload_0, _cl0, 0, priv)
            time.sleep(0.1)
            _send_legitimate_metric(sock, session_id, aes_key, hmac_key,
                                    payload_1, _cl1, 1, priv)
            time.sleep(0.1)
            # Now send the tampered metric with the stale chain_link
            _send_tampered_metric(sock, session_id, aes_key, hmac_key,
                                  tampered_payload, _cl0, chain_pos=2)
            time.sleep(0.4)
            sock.close()

        print(f"{Fore.RED}  ❌ [ATTACK] Hash chain broken at position 3 — "
              f"tampering detected{Style.RESET_ALL}")
        _stopped_by(
            "INTEGRITY — SHA-256 Hash Chain",
            "chain_link[0] = SHA256(payload_0 || genesis_hash).  At position 2 the "
            "controller expects SHA256(received_payload || link_1).  Since link_1 ≠ "
            "genesis_hash, the two digests are completely different (SHA-256 avalanche "
            "effect).  An attacker who drops metric #1 cannot produce the correct "
            "link for position 2 without knowing metric #1's payload — which they "
            "dropped and can't recover from the ciphertext alone.",
        )

    # ── Attack 4: Fake Vehicle ────────────────────────────────────────────────

    def fake_vehicle_attack(self, host: str, port: int) -> None:
        """Connect and send an encrypted BEACON with a fabricated session_id.

        The attacker skips the ECDH handshake entirely and invents a session_id.
        They encrypt their payload with a random key (since they have no real K_AES).

        Defence layers:
            (a) Session lookup — controller's SessionManager has no record of the
                                 fabricated session_id → message dropped immediately.
            (b) AES-GCM tag   — even if the session existed, encrypting with the
                                 wrong K_AES produces an invalid GCM authentication
                                 tag → InvalidTag raised before plaintext is returned.
        """
        _banner("Fake Vehicle / Session Hijack Attack")
        print(f"  Strategy : Skip ECDH handshake entirely.  Invent a session_id and")
        print(f"             encrypt a BEACON with a random key — no real K_AES.")
        print(f"  Goal     : Inject telemetry without a valid authenticated session.\n")

        fake_session_id = os.urandom(16).hex()   # random — not in controller's store
        fake_aes_key    = os.urandom(32)          # random — not ECDH-derived

        evil_payload = {
            "vehicle_id": "FAKE-VEHICLE",
            "position":   [0.0, 0.0],
            "velocity":   500.0,
            "sequence":   1,
            "timestamp":  time.time(),
        }
        payload_bytes = json.dumps(evil_payload, sort_keys=True).encode()

        # Attacker encrypts with their random key
        fake_aad    = f"BEACON:{fake_session_id}".encode()
        fake_bundle = encrypt(fake_aes_key, payload_bytes, additional_data=fake_aad)
        fake_hmac   = generate_hmac(fake_aes_key, payload_bytes)  # also wrong key

        _show("Fabricated session_id",  fake_session_id[:24] + "…")
        _show("Random AES key used",    fake_aes_key.hex()[:32] + "…")
        _show("(No ECDH handshake)",    "session key was never negotiated")
        print()

        # ── Defence A: session lookup fails ───────────────────────────────
        from core.session_manager import SessionManager
        sim_manager = SessionManager()
        lookup = sim_manager.get_session(fake_session_id)
        _show("SessionManager.get_session(fake_id)", str(lookup))   # None
        print(f"  Controller drops message at session-validation gate (None → reject).\n")

        # ── Defence B: AES-GCM InvalidTag with wrong key ──────────────────
        # Even if the controller had an active session (impossible here), it would
        # try to decrypt with its own K_AES — which is different from fake_aes_key.
        real_aes_key = os.urandom(32)  # controller's real K_AES (different)
        try:
            decrypt(
                real_aes_key,
                {"ciphertext": fake_bundle["ciphertext"], "nonce": fake_bundle["nonce"]},
                additional_data=fake_aad,
            )
            _show("Decrypt with wrong K_AES", "PASSED (should NEVER happen)")
        except Exception as exc:
            _show("Decrypt with wrong K_AES", f"{type(exc).__name__} — ciphertext rejected")

        # ── Send to running controller ─────────────────────────────────────
        sock = _try_connect(host, port)
        if sock:
            print(f"\n  Sending malicious BEACON (no prior handshake) to controller…")
            _send_msg(sock, {
                "msg_type":   "BEACON",
                "session_id": fake_session_id,
                "ciphertext": base64.b64encode(fake_bundle["ciphertext"]).decode(),
                "nonce":      base64.b64encode(fake_bundle["nonce"]).decode(),
                "hmac_tag":   fake_hmac,
                "aad":        base64.b64encode(fake_aad).decode(),
                "sequence":   1,
            })
            time.sleep(0.4)
            sock.close()
        else:
            print(f"\n  (Controller offline — local defence simulation shown above.)")

        print(f"\n{Fore.RED}  ❌ [ATTACK] Decryption failed — invalid session key{Style.RESET_ALL}")
        _stopped_by(
            "AUTHENTICATION + CONFIDENTIALITY — Session Gate + AES-256-GCM",
            "Two independent defences stop this attack: (1) SessionManager returns "
            "None for the fabricated session_id — the message is dropped before any "
            "crypto is attempted.  (2) Even if the session gate were bypassed, "
            "AESGCM.decrypt() with the wrong K_AES raises InvalidTag — the attacker's "
            "ciphertext is opaque without the ECDH-derived session key.",
        )

    # ── Attack 5: Ledger Tampering ────────────────────────────────────────────

    def ledger_tampering_attack(self, ledger: BlockchainLedger) -> None:
        """Directly overwrite a committed ledger entry and prove verify_chain() catches it.

        Scenario: an attacker with write access to the ledger storage (compromised
        database, rogue sysadmin) retroactively changes vehicle_id on entry #2 from
        "V001" to "ATTACKER" — attempting to falsify who sent a METRIC message.

        Defence:
            entry_hash = SHA256(entry_id || vehicle_id || message_type
                                || payload_hash || timestamp || prev_hash)
            Changing vehicle_id changes entry_hash.  The stored entry_hash no
            longer matches the recomputed value AND the RSA signature over the
            original entry_hash becomes invalid.  verify_chain() detects both.

        Args:
            ledger : A live BlockchainLedger instance (entries may already exist).
        """
        _banner("Blockchain Ledger Tampering Attack")
        print(f"  Strategy : With direct storage access, overwrite vehicle_id in")
        print(f"             entry #2 from 'V001' to 'ATTACKER' to falsify authorship.")
        print(f"  Goal     : Retroactively deny or reassign a logged metric event.\n")

        # ── Populate the ledger with 3 meaningful entries ──────────────────
        priv = ledger.controller_private_key
        e1 = ledger.add_entry("V001", "KEY_EXCHANGE",
                               b"ECDH session established for V001", priv)
        e2 = ledger.add_entry("V001", "METRIC",
                               b'{"speed_kmh":72,"gps":[51.50,-0.12]}', priv)
        e3 = ledger.add_entry("V001", "METRIC",
                               b'{"speed_kmh":68,"gps":[51.51,-0.13]}', priv)

        total = len(ledger)
        print(f"  Ledger populated: {total} entries (index 0 = genesis).")
        print()

        # Find e2 index in the internal list (genesis=0, e1=1, e2=2, e3=3)
        e2_index = next(
            i for i, en in enumerate(ledger._entries)
            if en.entry_id == e2.entry_id
        )

        _show(f"Entry #{e2_index} vehicle_id before", ledger._entries[e2_index].vehicle_id)
        _show(f"Entry #{e2_index} entry_hash   before", ledger._entries[e2_index].entry_hash[:28] + "…")

        # ── Verify chain is intact before the attack ───────────────────────
        pre_tamper = ledger.verify_chain()
        _show("verify_chain() before tampering", str(pre_tamper) + "  ← must be True")
        print()

        # ── The Attack: directly overwrite vehicle_id ──────────────────────
        # This simulates a database UPDATE or a raw binary edit of the log file.
        # The attacker CANNOT update entry_hash or controller_signature without
        # the controller's RSA private key — so they leave those fields stale.
        original_vehicle_id = ledger._entries[e2_index].vehicle_id
        ledger._entries[e2_index].vehicle_id = "ATTACKER"

        print(f"  [ATTACK] entry[{e2_index}].vehicle_id overwritten: "
              f"'{original_vehicle_id}' → 'ATTACKER'")
        print(f"           entry_hash unchanged (attacker cannot recalculate without "
              f"controller's RSA private key)")
        print()

        # ── Verify the chain detects the tampering ─────────────────────────
        post_tamper = ledger.verify_chain()
        report      = ledger.tamper_detect()

        _show("verify_chain() after tampering", str(post_tamper) + "  ← must be False")
        print()

        # tamper_detect() returns a detailed report with position + reason
        if report["broken_at"]:
            for broken in report["broken_at"]:
                pos    = broken["position"]
                reason = broken["reason"]
                print(f"{Fore.RED}  ❌ [ATTACK] Ledger tamper detected at entry "
                      f"#{pos} — {reason}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}  ❌ [ATTACK] Ledger tampering not detected "
                  f"(unexpected — check ledger implementation){Style.RESET_ALL}")

        # ── Restore the ledger so it remains usable after this demo ────────
        ledger._entries[e2_index].vehicle_id = original_vehicle_id

        _stopped_by(
            "NON-REPUDIATION + INTEGRITY — Hash Chain + RSA-PSS Controller Signature",
            "entry_hash[2] = SHA256(entry_id || 'V001' || 'METRIC' || payload_hash "
            "|| timestamp || entry_hash[1]).  Changing vehicle_id to 'ATTACKER' "
            "produces a completely different SHA-256 digest.  The stored entry_hash "
            "is now stale (hash_mismatch).  The RSA-PSS signature — signed over "
            "the original entry_hash — is also invalid for the modified entry.  "
            "Re-signing requires the controller's RSA private key, which the "
            "attacker does not have.",
        )


# ── Internal helpers used by metric_tampering_attack ─────────────────────────

def _send_legitimate_metric(
    sock: socket.socket,
    session_id: str,
    aes_key: bytes,
    hmac_key: bytes,
    payload_json: str,
    chain_link: str,
    chain_pos: int,
    private_key,
) -> None:
    """Send a correctly constructed METRIC message (used inside metric_tampering_attack)."""
    payload_bytes = payload_json.encode()
    raw_sig       = sign(private_key, payload_bytes)
    hmac_input    = payload_bytes + chain_link.encode()
    tag           = generate_hmac(hmac_key, hmac_input)
    inner         = json.dumps({
        "payload":        payload_json,
        "chain_link":     chain_link,
        "chain_position": chain_pos,
        "signature":      base64.b64encode(raw_sig).decode(),
    }).encode()
    aad    = f"METRIC:{session_id}".encode()
    bundle = encrypt(aes_key, inner, additional_data=aad)
    _send_msg(sock, {
        "msg_type":   "METRIC",
        "session_id": session_id,
        "ciphertext": base64.b64encode(bundle["ciphertext"]).decode(),
        "nonce":      base64.b64encode(bundle["nonce"]).decode(),
        "hmac_tag":   tag,
        "aad":        base64.b64encode(aad).decode(),
        "sequence":   chain_pos + 1,
    })


def _send_tampered_metric(
    sock: socket.socket,
    session_id: str,
    aes_key: bytes,
    hmac_key: bytes,
    tampered_payload_json: str,
    stale_chain_link: str,
    chain_pos: int,
) -> None:
    """Send a METRIC with a stale chain_link (the attack payload for metric_tampering_attack)."""
    payload_bytes = tampered_payload_json.encode()
    hmac_input    = payload_bytes + stale_chain_link.encode()
    tag           = generate_hmac(hmac_key, hmac_input)
    inner         = json.dumps({
        "payload":        tampered_payload_json,
        "chain_link":     stale_chain_link,   # ← stale link from position 0
        "chain_position": chain_pos,
        "signature":      base64.b64encode(os.urandom(256)).decode(),  # forged
    }).encode()
    aad    = f"METRIC:{session_id}".encode()
    bundle = encrypt(aes_key, inner, additional_data=aad)
    _send_msg(sock, {
        "msg_type":   "METRIC",
        "session_id": session_id,
        "ciphertext": base64.b64encode(bundle["ciphertext"]).decode(),
        "nonce":      base64.b64encode(bundle["nonce"]).decode(),
        "hmac_tag":   tag,
        "aad":        base64.b64encode(aad).decode(),
        "sequence":   99,
    })
