"""
demo_scenarios.py — One function per security property, each self-contained.

Each function imports only the specific core module it showcases so that a
reader studying one property is not distracted by code belonging to another.
"""

from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)  # Ensures ANSI codes work on Windows terminals


def _ok(msg: str) -> None:
    print(f"{Fore.GREEN}[PASS]{Style.RESET_ALL} {msg}")


def _fail(msg: str) -> None:
    print(f"{Fore.RED}[FAIL]{Style.RESET_ALL} {msg}")


def _info(msg: str) -> None:
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")


# ── Confidentiality ─────────────────────────────────────────────────────────────

def demo_confidentiality() -> None:
    """AES-256-GCM: plaintext is unrecoverable without the session key."""
    from core.aes_gcm_encrypt import encrypt, decrypt

    key = b"\x00" * 32  # Placeholder key — real key comes from ECDH
    plaintext = b'{"speed": 72, "location": "51.5074N,0.1278W"}'

    ciphertext_b64, nonce_b64 = encrypt(plaintext, key)
    _info(f"Plaintext : {plaintext.decode()}")
    _info(f"Ciphertext: {ciphertext_b64[:48]}...")

    recovered = decrypt(ciphertext_b64, nonce_b64, key)
    assert recovered == plaintext
    _ok("Decryption with correct key succeeded — plaintext recovered.")

    # Show that a wrong key produces an authentication failure, not garbled data.
    wrong_key = b"\xff" * 32
    try:
        decrypt(ciphertext_b64, nonce_b64, wrong_key)
        _fail("Wrong key accepted — this should never happen.")
    except Exception:
        _ok("Wrong key rejected by AES-GCM authentication tag — ciphertext is opaque.")


# ── Integrity ───────────────────────────────────────────────────────────────────

def demo_integrity() -> None:
    """HMAC-SHA256: a single flipped bit in the payload is detected."""
    from core.hmac_auth import compute_hmac, verify_hmac

    message = b"METRIC: speed=72 location=51.5074N"
    tag = compute_hmac(message)
    _info(f"Original HMAC tag: {tag[:32]}...")

    assert verify_hmac(message, tag)
    _ok("HMAC verified for original message.")

    # Simulate a bit-flip (MITM or storage corruption)
    tampered = message[:-1] + bytes([message[-1] ^ 0x01])
    if not verify_hmac(tampered, tag):
        _ok("Tampered message rejected — integrity check caught the modification.")
    else:
        _fail("Tampered message accepted — integrity broken.")


# ── Authentication ──────────────────────────────────────────────────────────────

def demo_authentication() -> None:
    """ECDH: both parties derive the same session key; an impersonator cannot."""
    from core.key_exchange import ECDHParty

    vehicle = ECDHParty()
    controller = ECDHParty()

    vehicle_pub = vehicle.public_key_bytes()
    controller_pub = controller.public_key_bytes()

    vehicle_key = vehicle.derive_session_key(controller_pub)
    controller_key = controller.derive_session_key(vehicle_pub)

    _info(f"Vehicle session key   : {vehicle_key.hex()[:32]}...")
    _info(f"Controller session key: {controller_key.hex()[:32]}...")

    if vehicle_key == controller_key:
        _ok("Both parties derived the same session key — authenticated channel established.")
    else:
        _fail("Key mismatch — authentication failed.")

    # Impersonator cannot derive the same key without the vehicle's private key
    impersonator = ECDHParty()
    impersonator_key = impersonator.derive_session_key(controller_pub)
    if impersonator_key != controller_key:
        _ok("Impersonator derived a different key — cannot inject messages into the session.")
    else:
        _fail("Impersonator derived matching key — this should be cryptographically impossible.")


# ── Non-Repudiation ─────────────────────────────────────────────────────────────

def demo_non_repudiation() -> None:
    """RSA-PSS: the vehicle cannot deny sending a signed METRIC message."""
    from core.rsa_signatures import generate_rsa_keypair, sign, verify

    private_key, public_key = generate_rsa_keypair()
    message = b'{"event": "speed_violation", "speed": 140, "limit": 100}'

    signature_b64 = sign(message, private_key)
    _info(f"Signature (first 48 chars): {signature_b64[:48]}...")

    if verify(message, signature_b64, public_key):
        _ok("Signature verified — vehicle cannot repudiate this message.")

    # A forged signature (random bytes) must not verify
    import base64, os
    forged = base64.b64encode(os.urandom(256)).decode()
    if not verify(message, forged, public_key):
        _ok("Forged signature rejected — non-repudiation holds against forgery.")
    else:
        _fail("Forged signature accepted — non-repudiation broken.")


# ── Availability ────────────────────────────────────────────────────────────────

def demo_availability() -> None:
    """Replay detection: a re-sent packet with a stale sequence number is dropped."""
    from core.session_manager import Session
    import os, time

    session = Session(
        session_id=os.urandom(8).hex(),
        session_key=os.urandom(32),
        peer_id="vehicle-001",
    )

    # Legitimate first message
    assert session.accept_sequence(1), "First message should be accepted"
    _ok("Sequence 1 accepted.")

    # Legitimate second message
    assert session.accept_sequence(2), "Second message should be accepted"
    _ok("Sequence 2 accepted.")

    # Replay: attacker retransmits sequence 1
    if not session.accept_sequence(1):
        _ok("Replayed sequence 1 rejected — replay attack blocked.")
    else:
        _fail("Replayed packet accepted — availability compromised.")

    # Chain integrity check for the ledger
    from core.blockchain_ledger import BlockchainLedger
    ledger = BlockchainLedger()
    ledger.append("KEY_EXCHANGE", {"peer": "vehicle-001"})
    ledger.append("METRIC_RECEIVED", {"speed": 72})

    if ledger.verify_chain():
        _ok(f"Blockchain ledger intact — {len(ledger)} blocks, chain unbroken.")
    else:
        _fail("Ledger chain broken — audit trail compromised.")
