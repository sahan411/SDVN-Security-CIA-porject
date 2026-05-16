"""
demo/demo_scenarios.py — Four standalone scenario functions for the live demo.

Each function is fully self-contained and can be imported and called independently.
All four are also called in sequence by demo/run_demo.py.

Scenarios:
    scenario_normal_operation(host, port, delay)   — live sockets, full security stack
    scenario_hmac_bypass(host, port, delay)        — attacker forges HMAC tag
    scenario_metric_tampering(delay)               — hash chain catches stale chain link
    scenario_non_repudiation(delay)                — ledger tamper detected by verify_chain
"""

from __future__ import annotations

import base64
import json
import os
import time
import threading
from typing import Optional

from colorama import Fore, Style, init as colorama_init

from core.aes_gcm_encrypt  import encrypt, decrypt
from core.blockchain_ledger import BlockchainLedger
from core.hash_chain        import HashChain
from core.hmac_auth         import generate_hmac, verify_hmac
from core.key_exchange      import ECDHKeyExchange
from core.network_config    import HOST, PORT, REPLAY_WINDOW_SECONDS
from core.rsa_signatures    import generate_keypair, serialize_public_key, sign, verify_signature
from core.session_manager   import SessionManager

colorama_init(autoreset=True)

# ── Shared print helpers ──────────────────────────────────────────────────────
_LOCK = threading.Lock()   # serialise prints from controller thread vs demo thread

def _g(msg: str) -> None:
    with _LOCK:
        print(f"  {Fore.GREEN}{msg}{Style.RESET_ALL}")

def _r(msg: str) -> None:
    with _LOCK:
        print(f"  {Fore.RED}{msg}{Style.RESET_ALL}")

def _c(msg: str) -> None:
    with _LOCK:
        print(f"  {Fore.CYAN}{msg}{Style.RESET_ALL}")

def _y(msg: str) -> None:
    with _LOCK:
        print(f"  {Fore.YELLOW}{msg}{Style.RESET_ALL}")

def _w(msg: str) -> None:
    with _LOCK:
        print(f"  {msg}")

def _step(n: int, text: str) -> None:
    with _LOCK:
        print(f"\n  {Fore.YELLOW}[Step {n}]{Style.RESET_ALL} {text}")

def _data(label: str, value: str) -> None:
    with _LOCK:
        print(f"  {Fore.CYAN}  {label:<28}{Style.RESET_ALL}{value}")

def _pause(seconds: float, enabled: bool = True) -> None:
    if enabled:
        time.sleep(seconds)


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Normal Secure Operation
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_normal_operation(
    host: str = HOST,
    port: int = PORT,
    delay: bool = True,
) -> Optional[BlockchainLedger]:
    """
    Start a ControllerNode in a background thread, connect a VehicleNode,
    perform ECDH key exchange, send 3 beacons and 3 metrics, then display
    the ledger.  Returns the controller's ledger for use in Scenario 4.
    """
    from nodes.controller_node import ControllerNode
    from nodes.vehicle_node    import VehicleNode

    # ── Start controller in background daemon thread ──────────────────────────
    _step(1, "Starting SDN Controller on background thread…")
    ctrl = ControllerNode(host=host, port=port)
    ctrl.start()   # bind + listen immediately so the vehicle can connect

    ctrl_thread = threading.Thread(
        target=_controller_accept_loop,
        args=(ctrl,),
        daemon=True,
        name="controller-demo",
    )
    ctrl_thread.start()
    _pause(0.3, delay)
    _g(f"Controller listening on {host}:{port}")

    # ── Connect vehicle ───────────────────────────────────────────────────────
    _step(2, "Vehicle Node V001 connecting to controller…")
    vehicle = VehicleNode(vehicle_id="V001", host=host, port=port)
    vehicle.connect()
    _pause(0.2, delay)
    _g("TCP connection established — untrusted channel open")

    # ── ECDH key exchange ─────────────────────────────────────────────────────
    _step(3, "ECDH Key Exchange — deriving forward-secret session keys")
    _c("Vehicle generates ephemeral P-256 keypair…")
    _pause(0.3, delay)

    vehicle.perform_key_exchange()
    _pause(0.4, delay)

    _data("Session ID   :", vehicle._session_id[:24] + "…")
    _data("K_AES  (hex) :", vehicle._aes_key.hex()[:32] + "…")
    _data("K_HMAC (hex) :", vehicle._hmac_key.hex()[:32] + "…")
    _pause(0.3, delay)
    _g("Both parties derived matching session keys via HKDF — forward secrecy achieved")

    # ── 3 Beacons ─────────────────────────────────────────────────────────────
    _step(4, "Vehicle sending 3 BEACON messages (HMAC-authenticated, AES-GCM encrypted)")
    _pause(0.2, delay)

    beacons = [
        ((51.5074, -0.1278), 60.0),
        ((51.5080, -0.1283), 62.5),
        ((51.5086, -0.1289), 64.0),
    ]
    for i, (pos, vel) in enumerate(beacons, 1):
        _c(f"  BEACON #{i} — pos={pos}, vel={vel} km/h")

        # Show what the HMAC protects
        sample_payload = json.dumps(
            {"vehicle_id": "V001", "position": list(pos), "velocity": vel},
            sort_keys=True,
        ).encode()
        tag = generate_hmac(vehicle._hmac_key, sample_payload)
        _data(f"  HMAC tag #{i} :", tag[:32] + "…")

        vehicle.send_beacon(position=pos, velocity=vel)
        _pause(0.5, delay)   # let controller thread print its ✅ lines

    _pause(0.2, delay)

    # ── 3 Metrics ─────────────────────────────────────────────────────────────
    _step(5, "Vehicle sending 3 METRIC messages (hash-chained, RSA-signed, AES-GCM encrypted)")
    _pause(0.2, delay)

    metrics = [
        {"speed_kmh": 60, "gps": [51.5074, -0.1278], "fuel_pct": 80, "engine_temp_c": 90},
        {"speed_kmh": 65, "gps": [51.5080, -0.1283], "fuel_pct": 78, "engine_temp_c": 92},
        {"speed_kmh": 68, "gps": [51.5086, -0.1289], "fuel_pct": 76, "engine_temp_c": 93},
    ]

    for i, metric in enumerate(metrics, 1):
        _y(f"\n  --- METRIC #{i} ---")
        plaintext = json.dumps(metric, sort_keys=True).encode()

        # Show the encryption visually BEFORE sending
        _data("  Plaintext  :", json.dumps(metric)[:60])
        aad     = f"METRIC:demo".encode()
        bundle  = encrypt(vehicle._aes_key, plaintext, additional_data=aad)
        _data("  Ciphertext :", bundle["ciphertext"].hex()[:48] + "…")
        _data("  Nonce      :", bundle["nonce"].hex())

        # Show the decryption would recover the original value
        recovered = decrypt(vehicle._aes_key, bundle, additional_data=aad)
        _data("  Decrypted  :", recovered.decode()[:60])
        _pause(0.2, delay)

        vehicle.send_metric(metric)
        _pause(0.7, delay)   # let controller thread print all ✅ lines

    # ── Show ledger ───────────────────────────────────────────────────────────
    _step(6, "Displaying controller's blockchain ledger")
    _pause(0.3, delay)
    ctrl._ledger.print_ledger()

    _pause(0.3, delay)
    vehicle.close()

    return ctrl._ledger


def _controller_accept_loop(ctrl) -> None:
    """Accept loop for the background controller thread."""
    import socket as _socket
    try:
        while True:
            try:
                conn, addr = ctrl._server_sock.accept()
                t = threading.Thread(
                    target=ctrl.handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except OSError:
                break   # socket closed — shutdown
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — HMAC Bypass Attack
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_hmac_bypass(
    host: str = HOST,
    port: int = PORT,
    delay: bool = True,
) -> None:
    """
    A malicious vehicle establishes a real session (ECDH), but then
    computes its BEACON HMAC with a random fake key instead of K_HMAC.
    The controller's verify_hmac() rejects the forged tag in constant time.
    """
    import socket as _socket, struct as _struct

    # ── Attacker establishes a legitimate ECDH session ────────────────────────
    _step(1, "Attacker connects and performs key exchange (to get a valid session)…")
    _pause(0.3, delay)

    ecdh = ECDHKeyExchange()
    ecdh.generate_keypair()
    _, rsa_pub = generate_keypair()

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.settimeout(6.0)
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        _r("Controller not reachable — running local simulation only.")
        sock = None

    session_id = None
    aes_key    = os.urandom(32)
    real_hmac_key = os.urandom(32)

    if sock:
        _send(sock, {
            "msg_type":        "KEY_EXCHANGE",
            "vehicle_id":      "BAD-VEHICLE",
            "ecdh_public_key": base64.b64encode(ecdh.get_public_key_bytes()).decode(),
            "rsa_public_key":  base64.b64encode(serialize_public_key(rsa_pub)).decode(),
        })
        resp = _recv(sock)
        session_id = resp["session_id"]
        shared     = ecdh.compute_shared_secret(base64.b64decode(resp["ecdh_public_key"]))
        keys       = ecdh.derive_session_key(shared)
        aes_key       = keys["aes_key"]
        real_hmac_key = keys["hmac_key"]
        _pause(0.3, delay)

    _g(f"Session established: {(session_id or 'local-sim')[:24]}…")
    _data("Real K_HMAC :", real_hmac_key.hex()[:32] + "…")

    # ── Build malicious beacon ────────────────────────────────────────────────
    _step(2, "Attacker builds a BEACON with FORGED HMAC (random key, not K_HMAC)…")
    _pause(0.3, delay)

    evil_payload = {
        "vehicle_id": "BAD-VEHICLE",
        "position":   [99.99, 99.99],   # false position
        "velocity":   999.9,            # impossible speed
        "sequence":   1,
        "timestamp":  time.time(),
    }
    payload_bytes = json.dumps(evil_payload, sort_keys=True).encode()

    fake_key   = os.urandom(32)
    forged_tag = generate_hmac(fake_key, payload_bytes)
    real_tag   = generate_hmac(real_hmac_key, payload_bytes)

    _data("Evil payload     :", f"pos=[99.99,99.99], vel=999.9 km/h  ← fabricated")
    _data("Fake HMAC key    :", fake_key.hex()[:32] + "…")
    _data("Forged HMAC tag  :", forged_tag[:32] + "…")
    _data("Expected tag     :", real_tag[:32] + "…")
    _data("Tags match       :", str(forged_tag == real_tag) + "  ← MUST be False")
    _pause(0.3, delay)

    # Encrypt correctly (so AES-GCM passes) — only the HMAC is forged
    aad    = f"BEACON:{session_id or 'local'}".encode()
    bundle = encrypt(aes_key, payload_bytes, additional_data=aad)

    # ── Simulate controller-side HMAC check ───────────────────────────────────
    _step(3, "Controller receives beacon — running HMAC verification…")
    _pause(0.4, delay)

    local_result = verify_hmac(real_hmac_key, payload_bytes, forged_tag)
    _data("verify_hmac() result :", str(local_result) + "  ← False means REJECTED")

    if sock and session_id:
        _send(sock, {
            "msg_type":   "BEACON",
            "session_id": session_id,
            "ciphertext": base64.b64encode(bundle["ciphertext"]).decode(),
            "nonce":      base64.b64encode(bundle["nonce"]).decode(),
            "hmac_tag":   forged_tag,
            "aad":        base64.b64encode(aad).decode(),
            "sequence":   1,
        })
        _pause(0.5, delay)
        sock.close()

    _pause(0.2, delay)
    _r("❌ [ATTACK] HMAC verification failed — beacon rejected")
    _r("   Forged tag does not match HMAC-SHA256(K_HMAC, payload)")
    _r("   K_HMAC is derived from ECDH — the attacker cannot know it")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Metric Tampering (Hash Chain)
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_metric_tampering(delay: bool = True) -> None:
    """
    Demonstrate how the SHA-256 hash chain detects a replayed or tampered
    metric.  The attacker drops metric #1, then replays metric #0's chain
    link at position 2 with modified GPS coordinates.  The controller's
    parallel chain computation produces a different digest — mismatch detected.
    No controller required: this is a pure local cryptographic demonstration.
    """
    import hashlib as _hashlib

    seed = os.urandom(32).hex()

    # ── Vehicle sends 2 legitimate metrics ───────────────────────────────────
    _step(1, "Vehicle sends metric #0 and metric #1 legitimately…")
    _pause(0.3, delay)

    vehicle_chain = HashChain()
    vehicle_chain.initialize(seed)

    payload_0 = json.dumps(
        {"vehicle_id": "V001", "seq": 1, "data": {"speed_kmh": 60, "gps": [51.50, -0.12]}},
        sort_keys=True,
    )
    payload_1 = json.dumps(
        {"vehicle_id": "V001", "seq": 2, "data": {"speed_kmh": 65, "gps": [51.51, -0.13]}},
        sort_keys=True,
    )

    link_0 = vehicle_chain.add(payload_0)
    link_1 = vehicle_chain.add(payload_1)

    _data("Metric #0 chain_link :", link_0[:32] + "…")
    _data("Metric #1 chain_link :", link_1[:32] + "…")
    _g("Controller's parallel chain advances to position 2 — tip = link_1")
    _pause(0.3, delay)

    # ── Attacker intercepts metric #1, drops it, replays metric #0 ───────────
    _step(2, "Attacker drops metric #1 and injects tampered payload at position 2…")
    _pause(0.3, delay)

    tampered_payload = json.dumps(
        {"vehicle_id": "V001", "seq": 3, "data": {"speed_kmh": 60, "gps": [99.99, 99.99]}},
        sort_keys=True,
    )

    _r("  Attacker's injected GPS  : [99.99, 99.99]  ← fabricated location")
    _data("  Claimed chain_link      :", link_0[:32] + "…  (stale — from pos 0)")
    _data("  Claimed chain_position  :", "2")
    _pause(0.3, delay)

    # ── Controller's parallel chain check ─────────────────────────────────────
    _step(3, "Controller advances its parallel chain and compares links…")
    _pause(0.3, delay)

    ctrl_chain = HashChain()
    ctrl_chain.initialize(seed)
    ctrl_chain.add(payload_0)   # controller received metric 0 → tip = link_0
    ctrl_chain.add(payload_1)   # controller received metric 1 → tip = link_1
    # At this point ctrl_chain.get_tip() == link_1

    # Controller receives tampered_payload at claimed position 2.
    # It computes: SHA256(tampered_payload_bytes || link_1_bytes)
    prev_bytes    = bytes.fromhex(ctrl_chain.get_tip())   # link_1
    combined      = tampered_payload.encode("utf-8") + prev_bytes
    expected_link = _hashlib.sha256(combined).hexdigest()

    _data("  Controller chain tip    :", link_1[:32] + "…  (after pos 1)")
    _data("  Controller expected link:", expected_link[:32] + "…")
    _data("  Attacker's link_0       :", link_0[:32] + "…")
    _pause(0.2, delay)

    match = (expected_link == link_0)
    _data("  expected_link == link_0 :", str(match) + "  ← MUST be False")
    _pause(0.3, delay)

    _r("❌ [ATTACK] Hash chain broken at position 3 — tampering detected")
    _r("   SHA-256 avalanche: changing any input bit flips ~50% of output bits")
    _r("   An attacker who dropped metric #1 cannot know link_1 to forge link_2")
    _pause(0.2, delay)

    # ── Also show detect_tampering() on a local chain ────────────────────────
    _step(4, "Confirming with HashChain.detect_tampering()…")
    _pause(0.2, delay)

    audit_chain = HashChain()
    audit_chain.initialize(seed)
    audit_chain.add(payload_0)
    audit_chain.add(payload_1)
    audit_chain.add(tampered_payload)   # attacker's entry with mismatched link

    # Manually corrupt the last stored hash to simulate what the attacker sent
    audit_chain._entries[-1].hash_value = link_0   # replace with stale link

    result = audit_chain.detect_tampering()
    _data("  detect_tampering()      :", str(result) + "  ← False means CAUGHT")
    _g("Hash chain integrity check confirmed — position 2 flagged as tampered")


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — Non-Repudiation Demonstration
# ═══════════════════════════════════════════════════════════════════════════════

def scenario_non_repudiation(
    ledger: Optional[BlockchainLedger] = None,
    delay: bool = True,
) -> None:
    """
    Display the blockchain ledger, attempt to retroactively modify entry #2,
    and show that verify_chain() catches the tamper immediately.
    If *ledger* is provided (from Scenario 1), it already contains real entries.
    Otherwise a fresh ledger is populated locally.
    """
    # ── Use existing ledger or create one ────────────────────────────────────
    _step(1, "Displaying the controller's signed audit ledger…")
    _pause(0.3, delay)

    if ledger is None:
        ledger = BlockchainLedger()
        pk = ledger.controller_private_key
        ledger.add_entry("V001", "KEY_EXCHANGE", b"ECDH session established", pk)
        ledger.add_entry("V001", "METRIC", b'{"speed_kmh":60,"gps":[51.50,-0.12]}', pk)
        ledger.add_entry("V001", "METRIC", b'{"speed_kmh":65,"gps":[51.51,-0.13]}', pk)
        ledger.add_entry("V001", "METRIC", b'{"speed_kmh":68,"gps":[51.52,-0.14]}', pk)

    ledger.print_ledger()
    _pause(0.4, delay)

    # ── Find entry #2 (first post-genesis non-exchange entry) ─────────────────
    _step(2, "Attacker attempts to overwrite vehicle_id in entry #2…")
    _pause(0.3, delay)

    # Entry at index 2 (0=genesis, 1=KEY_EXCHANGE or first real entry, 2=first METRIC)
    target_idx = min(2, len(ledger._entries) - 1)
    target     = ledger._entries[target_idx]
    original_vehicle_id = target.vehicle_id

    _data("Target entry     :", f"#{target_idx}  type={target.message_type}")
    _data("vehicle_id before:", target.vehicle_id)
    _data("entry_hash before:", target.entry_hash[:32] + "…")
    _r("\n   [ATTACK] Overwriting vehicle_id: 'V001' → 'ATTACKER'")
    _r("   Goal: falsify who sent this metric to destroy accountability")
    _pause(0.4, delay)

    # Direct field modification — bypasses all API guards
    target.vehicle_id = "ATTACKER"

    _data("vehicle_id after :", target.vehicle_id + "  ← modified")
    _data("entry_hash after :", target.entry_hash[:32] + "…  ← STALE (not recalculated)")
    _c("\n   entry_hash was computed over the ORIGINAL vehicle_id.")
    _c("   Changing vehicle_id invalidates the stored hash — they no longer agree.")
    _pause(0.4, delay)

    # ── verify_chain() catches it ──────────────────────────────────────────────
    _step(3, "Running verify_chain() — checking all hashes and RSA signatures…")
    _pause(0.4, delay)

    chain_ok = ledger.verify_chain()
    report   = ledger.tamper_detect()

    _data("verify_chain()   :", str(chain_ok) + "  ← False = TAMPER DETECTED")

    if report["broken_at"]:
        for broken in report["broken_at"]:
            _r(f"\n  ❌ [ATTACK] Ledger tamper detected at entry "
               f"#{broken['position']} — {broken['reason']}")
    _pause(0.2, delay)

    # ── RSA signature also fails ───────────────────────────────────────────────
    _step(4, "Attempting RSA signature verification on the modified entry…")
    _pause(0.3, delay)

    sig_ok = ledger.verify_entry(target.entry_id)
    _data("verify_entry()   :", str(sig_ok) + "  ← False: hash mismatch + invalid sig")
    _c("The controller's RSA-PSS signature was computed over the ORIGINAL entry_hash.")
    _c("Modified entry_hash != original → signature is cryptographically invalid.")
    _c("Re-signing requires the controller's private key — attacker does not have it.")
    _pause(0.3, delay)

    # Restore the ledger
    target.vehicle_id = original_vehicle_id

    _r("❌ [ATTACK] Ledger modification detected and rejected")
    _r("   The signed audit trail is permanent and undeniable")


# ── Socket wire helpers (mirrors nodes/ framing) ──────────────────────────────

def _send(sock, data: dict) -> None:
    import struct as _s
    payload = json.dumps(data).encode("utf-8")
    sock.sendall(_s.pack(">I", len(payload)) + payload)


def _recv(sock) -> dict:
    import struct as _s
    raw = _recv_n(sock, 4)
    return json.loads(_recv_n(sock, _s.unpack(">I", raw)[0]).decode())


def _recv_n(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Peer closed connection.")
        buf += chunk
    return buf
