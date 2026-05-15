"""
core/key_exchange.py — ECDH Key Exchange + HKDF Session-Key Derivation

Security property : AUTHENTICATION + CONFIDENTIALITY (key establishment)
Course concept    : Elliptic Curve Diffie-Hellman (ECDH) + Key Derivation Function

═══════════════════════════════════════════════════════════════════════════════
MATHEMATICAL INTUITION — What the shared secret is
═══════════════════════════════════════════════════════════════════════════════

ECDH works over a cyclic group of points on an elliptic curve.  Let G be the
public generator point and n be the group order (both fixed by the curve spec).

    Vehicle  generates:   d_V  ∈ [1, n-1]   (private scalar — random)
                          Q_V  = d_V · G     (public point)       ← Eq 3.42

    Controller generates: d_C  ∈ [1, n-1]   (private scalar — random)
                          Q_C  = d_C · G     (public point)       ← Eq 3.43

    Both parties exchange their public points Q_V and Q_C over the channel.

    Vehicle  computes:    Z = d_V · Q_C  =  d_V · (d_C · G)      ← Eq 3.44
    Controller computes:  Z = d_C · Q_V  =  d_C · (d_V · G)

    Because scalar multiplication on an elliptic curve is associative and
    commutative, both sides arrive at the same point Z.  An eavesdropper who
    sees Q_V and Q_C cannot compute Z without solving the Elliptic Curve
    Discrete Logarithm Problem (ECDLP) — believed computationally infeasible
    for 256-bit curves at current computing power.

    Session keys are then derived from Z via HKDF:                 ← Eq 3.45
        K_AES  = HKDF(Z, salt, info="aes-key")
        K_HMAC = HKDF(Z, salt, info="hmac-key")

═══════════════════════════════════════════════════════════════════════════════
WHY ECDH GIVES FORWARD SECRECY
═══════════════════════════════════════════════════════════════════════════════

Forward secrecy (also called Perfect Forward Secrecy, PFS) means that
compromising a long-term key does NOT compromise past session keys.

Without ECDH (static RSA key transport):
    • The vehicle encrypts a session key K under the controller's RSA public key.
    • An attacker records all ciphertext today.
    • Years later, the attacker obtains the controller's RSA private key.
    • Every past session can now be decrypted — catastrophic retroactive exposure.

With ephemeral ECDH:
    • d_V and d_C are generated fresh for EVERY session and discarded immediately
      after Z is computed.
    • Even if the controller's long-term identity key is later compromised, the
      attacker cannot recover Z because d_C no longer exists anywhere.
    • Past sessions remain confidential — forward secrecy is achieved.

In SIGMA-V, vehicle pseudonyms rotate and sessions are short-lived, so ECDH's
ephemeral key property is a natural fit for the threat model.

═══════════════════════════════════════════════════════════════════════════════
WHY HKDF — NOT THE RAW ECDH OUTPUT
═══════════════════════════════════════════════════════════════════════════════

The raw ECDH shared secret Z is the x-coordinate of an elliptic-curve point.
It has several properties that make it unsuitable as a direct AES or HMAC key:

    1. Non-uniform distribution: curve points are not uniformly distributed
       over all bit strings, so Z has subtle statistical biases.
    2. Single use only: we need TWO independent keys (AES + HMAC) from one Z.
    3. No domain separation: without a label, the same Z could accidentally be
       reused as a key in a different protocol context.

HKDF (RFC 5869) solves all three problems in two steps:
    Extract: PRK = HMAC-SHA256(salt, Z)     → uniform pseudorandom key material
    Expand : K   = HMAC-SHA256(PRK, info || counter)  → any length, any purpose

    Different `info` strings ("aes-key", "hmac-key") produce independent,
    domain-separated keys even though they share the same PRK.

Curve choice — P-256 (secp256r1):
    • 128-bit security level (equivalent to RSA-3072).
    • Standardised by NIST FIPS 186-4; widely supported in TLS 1.3 and SIGMA-V.
    • 32-byte private keys vs 256-byte RSA-2048 keys — critical for low-latency
      vehicular communication where handshake overhead matters.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)


# ── HKDF domain-separation labels ───────────────────────────────────────────
# These byte strings are the `info` parameter passed to HKDF Expand.
# Using distinct labels for each derived key guarantees that K_AES and K_HMAC
# are cryptographically independent even though they share the same PRK.
_HKDF_INFO_AES: bytes = b"sdvn-v1-aes-256-gcm-key"
_HKDF_INFO_HMAC: bytes = b"sdvn-v1-hmac-sha256-key"

# Default HKDF salt — should be a fresh random value per session in production.
# A fixed salt is used here so the demo is reproducible without a separate
# salt-exchange sub-protocol.  The salt does NOT need to be secret.
_DEFAULT_SALT: bytes = b"sdvn-demo-2025-ecdh-salt"


class ECDHKeyExchange:
    """One party's side of an ephemeral ECDH handshake.

    Typical usage (both Vehicle and Controller instantiate one of these):

        # --- Vehicle side ---
        vehicle_ecdh = ECDHKeyExchange()
        vehicle_ecdh.generate_keypair()
        v_pub_bytes = vehicle_ecdh.get_public_key_bytes()   # send to Controller

        # --- Controller side ---
        ctrl_ecdh = ECDHKeyExchange()
        ctrl_ecdh.generate_keypair()
        c_pub_bytes = ctrl_ecdh.get_public_key_bytes()      # send to Vehicle

        # --- Both sides compute the same shared secret ---
        v_secret = vehicle_ecdh.compute_shared_secret(c_pub_bytes)
        c_secret = ctrl_ecdh.compute_shared_secret(v_pub_bytes)
        assert v_secret == c_secret                          # always True

        # --- Both sides derive the same session keys ---
        v_keys = vehicle_ecdh.derive_session_key(v_secret)
        c_keys = ctrl_ecdh.derive_session_key(c_secret)
        # v_keys["aes_key"] == c_keys["aes_key"]  and
        # v_keys["hmac_key"] == c_keys["hmac_key"]  — both True
    """

    def __init__(self) -> None:
        # Private key is None until generate_keypair() is called.
        # This explicit None makes it obvious if the object is used before
        # the keypair is generated (AttributeError rather than silent wrong key).
        self._private_key: Optional[EllipticCurvePrivateKey] = None

    # ── Public interface ────────────────────────────────────────────────────

    def generate_keypair(self) -> tuple:
        """Generate an ephemeral P-256 key pair for this session.

        Returns:
            (private_key, public_key) — both are cryptography library objects.
            The private key MUST be discarded (object goes out of scope) as soon
            as derive_session_key() has been called.  Retaining it defeats
            forward secrecy.

        Corresponds to Eq 3.42 / 3.43 in SIGMA-V FYP:
            d  ← random scalar in [1, n-1]
            Q  = d · G   (ephemeral public key)

        Why P-256 (secp256r1)?
            Standardised by NIST FIPS 186-4, mandatory in TLS 1.3, and the
            curve assumed throughout the SIGMA-V specification.  128-bit
            security with 32-byte keys — fast enough for real-time V2I latency.
        """
        # generate_private_key uses the OS CSPRNG — never seed it manually.
        self._private_key = generate_private_key(SECP256R1())
        public_key = self._private_key.public_key()
        return self._private_key, public_key

    def get_public_key_bytes(self) -> bytes:
        """Serialise the ephemeral public key to DER bytes for transmission.

        Returns:
            DER-encoded SubjectPublicKeyInfo bytes (compact, unambiguous binary
            format — no base-64 overhead, no PEM header parsing required).

        The public key is safe to send in plaintext because the ECDLP makes
        it computationally infeasible to recover the private scalar d from Q.

        Raises:
            RuntimeError: if generate_keypair() has not been called yet.
        """
        if self._private_key is None:
            raise RuntimeError("Call generate_keypair() before get_public_key_bytes().")
        return self._private_key.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """Perform the ECDH operation to derive the raw shared secret Z.

        Args:
            peer_public_key_bytes: DER-encoded public key received from the peer
                                   (output of the peer's get_public_key_bytes()).

        Returns:
            The x-coordinate of the shared curve point Z, as raw bytes.
            This is the ECDH shared secret (Eq 3.44 in SIGMA-V FYP):
                Z = d_self · Q_peer

        Important: Do NOT use the returned bytes directly as a key.
            Pass them to derive_session_key() which applies HKDF to produce
            uniformly random, domain-separated key material (Eq 3.45).

        Raises:
            RuntimeError : if generate_keypair() has not been called yet.
            ValueError   : if peer_public_key_bytes is not a valid DER public key.
        """
        if self._private_key is None:
            raise RuntimeError("Call generate_keypair() before compute_shared_secret().")

        # Deserialise the peer's public key from DER bytes.
        peer_public_key: EllipticCurvePublicKey = load_der_public_key(peer_public_key_bytes)  # type: ignore[assignment]

        # exchange() performs the scalar multiplication d_self · Q_peer and
        # returns the x-coordinate of the resulting point as raw bytes.
        # This is the standard ECDH operation defined in NIST SP 800-56A.
        shared_secret = self._private_key.exchange(ECDH(), peer_public_key)
        return shared_secret

    def derive_session_key(
        self,
        shared_secret: bytes,
        salt: Optional[bytes] = None,
    ) -> dict:
        """Apply HKDF to produce two independent session keys from the shared secret.

        Corresponds to Eq 3.45 in SIGMA-V FYP:
            K_AES  = HKDF(Z, salt, info="sdvn-v1-aes-256-gcm-key")
            K_HMAC = HKDF(Z, salt, info="sdvn-v1-hmac-sha256-key")

        Args:
            shared_secret: Raw bytes from compute_shared_secret().
            salt         : Optional random bytes to bind the derived keys to
                           this specific session (prevents pre-computation attacks
                           across sessions).  If None, _DEFAULT_SALT is used.

        Returns:
            A dict with:
                "aes_key"  — 32 bytes: AES-256-GCM encryption key
                "hmac_key" — 32 bytes: HMAC-SHA256 authentication key

        Why two separate HKDF calls?
            Using one key for both AES and HMAC violates the principle of key
            separation — a cryptanalytic weakness in HMAC could leak bits of
            the AES key, or vice versa.  HKDF with distinct `info` labels
            produces keys that are provably independent (see module docstring).

        Why HKDF instead of SHA256(shared_secret)?
            See module docstring — the raw ECDH output has non-uniform
            distribution and must be "extracted" before use as key material.
        """
        effective_salt = salt if salt is not None else _DEFAULT_SALT

        # HKDF Extract+Expand for the AES-GCM encryption key.
        # A fresh HKDF instance is required for each derivation because the
        # Expand step is stateful (internal counter increments).
        aes_key = HKDF(
            algorithm=SHA256(),
            length=32,          # 256 bits — matches AES-256 key size
            salt=effective_salt,
            info=_HKDF_INFO_AES,
        ).derive(shared_secret)

        # Separate HKDF instance with a different `info` label produces an
        # independent key — even though the same shared_secret and salt are used.
        hmac_key = HKDF(
            algorithm=SHA256(),
            length=32,          # 256 bits — matches SHA-256 output size
            salt=effective_salt,
            info=_HKDF_INFO_HMAC,
        ).derive(shared_secret)

        return {
            "aes_key": aes_key,
            "hmac_key": hmac_key,
        }
