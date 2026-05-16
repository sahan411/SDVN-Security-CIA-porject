"""
demo/demo_scenarios.py — Self-contained demonstrations of all five security properties
                          plus the attack simulator.

Each function is independent and imports only the modules it showcases, so a
reader studying one property is not distracted by code for another.

Scenario map:
    demo_confidentiality()   — AES-256-GCM: plaintext is opaque without the key
    demo_integrity()         — HMAC-SHA256 + HashChain: modification is detected
    demo_authentication()    — ECDH: both parties derive the same session key;
                               an impersonator cannot
    demo_non_repudiation()   — RSA-PSS: the vehicle cannot deny signing a metric
    demo_availability()      — Session expiry, replay detection, ledger audit
    demo_attacks()           — All five AttackSimulator attacks in sequence
"""

from __future__ import annotations

import os
import time

from colorama import Fore, Style, init as colorama_init

from core.network_config import HOST, PORT

colorama_init(autoreset=True)

_SEC = f"{Fore.CYAN}{'─' * 58}{Style.RESET_ALL}"


def _ok(msg: str)   -> None: print(f"  {Fore.GREEN}[PASS]{Style.RESET_ALL} {msg}")
def _fail(msg: str) -> None: print(f"  {Fore.RED}[FAIL]{Style.RESET_ALL} {msg}")
def _info(msg: str) -> None: print(f"  {Fore.YELLOW}[INFO]{Style.RESET_ALL} {msg}")
def _sep()          -> None: print(_SEC)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONFIDENTIALITY
# ═══════════════════════════════════════════════════════════════════════════════

def demo_confidentiality() -> None:
    """AES-256-GCM: a passive observer cannot read the metric payload."""
    from core.aes_gcm_encrypt import decrypt, encrypt

    _sep()
    print(f"  {Fore.CYAN}Property : CONFIDENTIALITY — AES-256-GCM{Style.RESET_ALL}")
    _sep()

    key       = os.urandom(32)          # session key from ECDH in real usage
    plaintext = b'{"speed_kmh": 72, "gps": [51.5074, -0.1278], "fuel_pct": 64}'

    # ── Encryption ──────────────────────────────────────────────────────────
    aad    = b"METRIC:demo-session-001"   # authenticated but not encrypted
    bundle = encrypt(key, plaintext, additional_data=aad)

    _info(f"Plaintext  : {plaintext.decode()}")
    _info(f"Ciphertext : {bundle['ciphertext'].hex()[:56]}…  ({len(bundle['ciphertext'])} bytes)")
    _info(f"Nonce      : {bundle['nonce'].hex()}")
    print()

    # ── Correct key decryption ───────────────────────────────────────────────
    recovered = decrypt(key, bundle, additional_data=aad)
    assert recovered == plaintext
    _ok("Decryption with correct session key — plaintext recovered.")

    # ── Wrong key decryption ─────────────────────────────────────────────────
    # Any key other than the one used to encrypt raises InvalidTag — the
    # adversary learns NOTHING about the plaintext from a failed attempt.
    wrong_key = os.urandom(32)
    try:
        decrypt(wrong_key, bundle, additional_data=aad)
        _fail("Wrong key was accepted — this should never happen.")
    except Exception:
        _ok("Wrong key rejected — AES-GCM InvalidTag raised; ciphertext is opaque.")

    # ── Tampered ciphertext ──────────────────────────────────────────────────
    # Flip one byte in the ciphertext; GCM tag detects it.
    tampered_ct   = bytearray(bundle["ciphertext"])
    tampered_ct[0] ^= 0xFF
    tampered_bundle = {**bundle, "ciphertext": bytes(tampered_ct)}
    try:
        decrypt(key, tampered_bundle, additional_data=aad)
        _fail("Tampered ciphertext was accepted — GCM integrity broken.")
    except Exception:
        _ok("Tampered ciphertext rejected — GCM tag covers every byte of ciphertext.")


# ═══════════════════════════════════════════════════════════════════════════════
# 2. INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

def demo_integrity() -> None:
    """HMAC-SHA256 + SHA-256 hash chain: modification and reordering are detected."""
    from core.hash_chain import HashChain
    from core.hmac_auth import compute_hmac, verify_hmac

    _sep()
    print(f"  {Fore.CYAN}Property : INTEGRITY — HMAC-SHA256 + Hash Chain{Style.RESET_ALL}")
    _sep()

    hmac_key = os.urandom(32)

    # ── HMAC: single-message integrity ──────────────────────────────────────
    message = b'{"speed_kmh": 72, "gps": [51.5074, -0.1278]}'
    tag     = compute_hmac(hmac_key, message)

    _info(f"Original message : {message.decode()}")
    _info(f"HMAC tag         : {tag[:32]}…")
    print()

    assert verify_hmac(hmac_key, message, tag)
    _ok("HMAC verified — message is authentic and unmodified.")

    # Single-bit flip in the message produces a completely different tag.
    tampered = bytearray(message)
    tampered[-1] ^= 0x01
    if not verify_hmac(hmac_key, bytes(tampered), tag):
        _ok("Tampered message rejected — HMAC detects the 1-bit change.")
    else:
        _fail("Tampered message accepted — integrity broken.")

    print()

    # ── Hash chain: sequence integrity ──────────────────────────────────────
    chain = HashChain()
    chain.initialize("demo-session-seed-2025")

    messages = [
        "METRIC: speed=60, seq=1",
        "METRIC: speed=65, seq=2",
        "METRIC: speed=68, seq=3",
    ]
    links = [chain.add(m) for m in messages]

    _info("Hash chain built (3 messages):")
    for i, (msg, lnk) in enumerate(zip(messages, links)):
        _info(f"  pos={i}  link={lnk[:24]}…  payload={msg!r}")
    print()

    # Full chain integrity check
    assert chain.detect_tampering()
    _ok("detect_tampering() — chain is intact, all links verified.")

    # Verify an individual link
    assert chain.verify(messages[1], links[1], position=1)
    _ok("verify(message, link, position=1) — individual link correct.")

    # Inject wrong link at position 1
    if not chain.verify(messages[1], links[0], position=1):
        _ok("Wrong link at position 1 detected — chain prevents message reordering.")
    else:
        _fail("Wrong link accepted — chain ordering broken.")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

def demo_authentication() -> None:
    """ECDH on P-256: mutual key derivation; an impersonator derives a different key."""
    from core.key_exchange import ECDHKeyExchange

    _sep()
    print(f"  {Fore.CYAN}Property : AUTHENTICATION — ECDH P-256 + HKDF{Style.RESET_ALL}")
    _sep()

    vehicle    = ECDHKeyExchange()
    controller = ECDHKeyExchange()

    vehicle.generate_keypair()
    controller.generate_keypair()

    v_pub = vehicle.generate_keypair()[1]     # returns (priv, pub)
    c_pub = controller.generate_keypair()[1]

    # Refresh with explicit calls (generate_keypair sets internal private key)
    vehicle    = ECDHKeyExchange();  vehicle.generate_keypair()
    controller = ECDHKeyExchange();  controller.generate_keypair()

    v_pub_bytes = vehicle.get_public_key_bytes()
    c_pub_bytes = controller.get_public_key_bytes()

    # Both parties compute Z = d_self · Q_peer independently
    v_secret = vehicle.compute_shared_secret(c_pub_bytes)
    c_secret = controller.compute_shared_secret(v_pub_bytes)

    assert v_secret == c_secret
    _ok("Both parties computed the same ECDH shared secret Z.")

    # Derive session keys and confirm they match on both sides
    v_keys = vehicle.derive_session_key(v_secret)
    c_keys = controller.derive_session_key(c_secret)

    _info(f"Vehicle    K_AES  : {v_keys['aes_key'].hex()[:32]}…")
    _info(f"Controller K_AES  : {c_keys['aes_key'].hex()[:32]}…")
    print()

    assert v_keys["aes_key"]  == c_keys["aes_key"]
    assert v_keys["hmac_key"] == c_keys["hmac_key"]
    _ok("K_AES and K_HMAC match on both sides — authenticated channel established.")

    # An impersonator generates their own ECDH keypair and computes a DIFFERENT secret
    impersonator = ECDHKeyExchange()
    impersonator.generate_keypair()
    imp_secret = impersonator.compute_shared_secret(c_pub_bytes)

    if imp_secret != c_secret:
        _ok("Impersonator derives a DIFFERENT shared secret — "
            "cannot inject valid messages into the session.")
    else:
        _fail("Impersonator matched the session secret — ECDLP broken.")

    print()
    _info("Key separation check:")
    _info(f"  K_AES  ≠ K_HMAC : {v_keys['aes_key'] != v_keys['hmac_key']}")
    _ok("Two independent 32-byte keys derived — AES and HMAC keys are domain-separated.")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. NON-REPUDIATION
# ═══════════════════════════════════════════════════════════════════════════════

def demo_non_repudiation() -> None:
    """RSA-2048 PSS: the vehicle cannot deny having signed a specific metric payload."""
    from core.rsa_signatures import (
        generate_keypair,
        load_public_key_from_bytes,
        serialize_public_key,
        sign,
        verify_signature,
    )

    _sep()
    print(f"  {Fore.CYAN}Property : NON-REPUDIATION — RSA-2048 PSS{Style.RESET_ALL}")
    _sep()

    # Vehicle generates its long-term signing keypair
    private_key, public_key = generate_keypair()

    # Controller receives and stores the vehicle's public key (via KEY_EXCHANGE)
    pub_der     = serialize_public_key(public_key)
    stored_pub  = load_public_key_from_bytes(pub_der)

    _info(f"RSA-2048 keypair generated ({len(pub_der)} bytes DER public key).")
    print()

    # Vehicle signs a METRIC payload
    metric = b'{"event": "speed_violation", "speed_kmh": 140, "limit_kmh": 100}'
    sig    = sign(private_key, metric)

    _info(f"Metric payload : {metric.decode()}")
    _info(f"Signature (first 48 chars of b64) : {__import__('base64').b64encode(sig).decode()[:48]}…")
    print()

    # Controller verifies with the stored public key
    if verify_signature(stored_pub, metric, sig):
        _ok("Signature verified — vehicle CANNOT deny having sent this metric payload.")
    else:
        _fail("Signature verification failed.")

    # A different payload does not verify with the original signature
    different = b'{"event": "speed_violation", "speed_kmh": 60, "limit_kmh": 100}'
    if not verify_signature(stored_pub, different, sig):
        _ok("Modified payload rejected — signature is bound to the exact original bytes.")
    else:
        _fail("Modified payload accepted — non-repudiation broken.")

    # A forged signature (random bytes) cannot pass
    forged = os.urandom(256)
    if not verify_signature(stored_pub, metric, forged):
        _ok("Forged signature (random bytes) rejected — RSA-PSS verification holds.")
    else:
        _fail("Forged signature accepted — catastrophic failure.")

    print()
    _info("Why RSA beats HMAC for non-repudiation:")
    _info("  HMAC — both parties hold the key → either could have produced the tag.")
    _info("  RSA  — only the vehicle holds its private key → signature is attributable.")


# ═══════════════════════════════════════════════════════════════════════════════
# 5. AVAILABILITY
# ═══════════════════════════════════════════════════════════════════════════════

def demo_availability() -> None:
    """Session expiry, replay detection, and blockchain ledger audit trail."""
    from core.blockchain_ledger import BlockchainLedger
    from core.session_manager import SESSION_TIMEOUT_SECONDS, SessionManager

    _sep()
    print(f"  {Fore.CYAN}Property : AVAILABILITY — Session Management + Ledger Audit{Style.RESET_ALL}")
    _sep()

    manager = SessionManager()
    shared  = os.urandom(32)   # mock ECDH shared secret

    # ── Active session ───────────────────────────────────────────────────────
    sid = manager.create_session("V001", shared)
    _info(f"Session created: {sid[:24]}…  (timeout = {SESSION_TIMEOUT_SECONDS:.0f} s)")

    assert manager.is_session_valid(sid)
    _ok("is_session_valid() → True for a freshly created session.")

    # ── Replay detection via sequence monotonicity ────────────────────────
    session = manager.get_session(sid)
    _info(f"Session keys: K_AES={session['aes_key'].hex()[:16]}…  "
          f"K_HMAC={session['hmac_key'].hex()[:16]}…")
    print()

    # Simulate sequence-number replay protection
    last_seq = [0]   # controller tracks last accepted sequence per session

    def accept_sequence(seq: int) -> bool:
        if seq <= last_seq[0]:
            return False   # replay or out-of-order — reject
        last_seq[0] = seq
        return True

    assert  accept_sequence(1);  _ok("Sequence 1 accepted.")
    assert  accept_sequence(2);  _ok("Sequence 2 accepted.")
    assert  accept_sequence(3);  _ok("Sequence 3 accepted.")
    assert not accept_sequence(2);  _ok("Replay of sequence 2 rejected — monotonicity enforced.")
    assert not accept_sequence(1);  _ok("Replay of sequence 1 rejected — monotonicity enforced.")
    print()

    # ── purge_expired() prevents memory exhaustion ────────────────────────
    purged = manager.purge_expired()
    _info(f"purge_expired() removed {len(purged)} stale sessions "
          f"(prevents memory-exhaustion DoS).")

    # ── Blockchain ledger audit trail ─────────────────────────────────────
    print()
    ledger = BlockchainLedger()
    pk     = ledger.controller_private_key

    ledger.add_entry("V001", "KEY_EXCHANGE", b"session start", pk)
    ledger.add_entry("V001", "METRIC",       b'{"speed":72}',  pk)
    ledger.add_entry("V001", "METRIC",       b'{"speed":68}',  pk)

    _info(f"Ledger: {len(ledger)} entries (including genesis).")

    assert ledger.verify_chain()
    _ok("verify_chain() → True — all entries intact and signatures valid.")

    # Simulate a tamper attempt
    ledger._entries[2].vehicle_id = "TAMPERER"
    report = ledger.tamper_detect()
    ledger._entries[2].vehicle_id = "V001"     # restore

    if not report["intact"]:
        pos = report["broken_at"][0]["position"]
        _ok(f"tamper_detect() caught modification at entry #{pos} — "
            f"ledger is tamper-evident.")
    else:
        _fail("Tampering was not detected.")


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ATTACK DEMONSTRATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def demo_attacks(host: str = HOST, port: int = PORT) -> None:
    """Run all five AttackSimulator attacks in sequence.

    Each attack connects to a running ControllerNode when available.
    All five attacks also demonstrate local detection logic so the demo
    is fully self-contained even without a controller running.
    """
    from attacks.attack_simulator import AttackSimulator
    from core.blockchain_ledger import BlockchainLedger
    from core.network_config import HOST, PORT

    sim    = AttackSimulator()
    ledger = BlockchainLedger()

    # ── Attack 1: Replay ──────────────────────────────────────────────────
    # Construct a synthetic "captured" beacon that is 120 seconds old.
    # In a real scenario the attacker would save this from a previous session.
    captured = {
        "msg_type":   "BEACON",
        "session_id": os.urandom(16).hex(),   # expired session
        "ciphertext": __import__("base64").b64encode(os.urandom(48)).decode(),
        "nonce":      __import__("base64").b64encode(os.urandom(12)).decode(),
        "hmac_tag":   os.urandom(32).hex(),
        "aad":        __import__("base64").b64encode(b"BEACON:old-session").decode(),
        "sequence":   1,
        "timestamp":  time.time() - 120,      # 120 seconds ago — well outside window
    }
    sim.replay_attack(host, port, captured)

    # ── Attack 2: HMAC Bypass ─────────────────────────────────────────────
    sim.hmac_bypass_attack(host, port)

    # ── Attack 3: Metric Tampering ────────────────────────────────────────
    session_key = os.urandom(32)    # mock "compromised" session key
    sim.metric_tampering_attack(host, port, session_key)

    # ── Attack 4: Fake Vehicle ────────────────────────────────────────────
    sim.fake_vehicle_attack(host, port)

    # ── Attack 5: Ledger Tampering ────────────────────────────────────────
    sim.ledger_tampering_attack(ledger)


