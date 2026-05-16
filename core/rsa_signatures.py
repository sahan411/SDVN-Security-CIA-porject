"""
core/rsa_signatures.py — RSA-2048 Digital Signatures

Security property : NON-REPUDIATION
Course concept    : Asymmetric digital signatures / public-key cryptography

How RSA signatures give Non-Repudiation
-----------------------------------------
Unlike HMAC (symmetric — both parties share the same key, so either could have
produced a valid tag), RSA signatures use an asymmetric key pair:

    Private key (secret) ─── held ONLY by the signer (e.g. the Vehicle Node)
    Public key  (public) ─── distributed freely to all verifiers

Because ONLY the Vehicle Node holds the private key, a valid signature on a
METRIC message can ONLY have been produced by the Vehicle Node.  If the vehicle
later denies sending a message, the controller can present:
    (a) The message,
    (b) The signature, and
    (c) The vehicle's public key

...and any third party can verify the signature independently.  This is
Non-Repudiation — the signer cannot convincingly deny the act of signing.

Why signing != encrypting
--------------------------
Both RSA signing and RSA encryption use the same mathematical operation
(modular exponentiation), but they use the keys in opposite directions and
serve completely different purposes:

    Encryption : sender uses RECEIVER'S public key  -> only receiver can decrypt
    Signing    : sender uses SENDER'S  private key  -> anyone can verify with public key

Confusing the two leads to serious vulnerabilities.  This module uses
ONLY the signing direction and never calls any encryption primitive.

Padding scheme: PSS vs PKCS#1 v1.5
-------------------------------------
This module uses RSA-PSS (Probabilistic Signature Scheme) rather than the
older PKCS#1 v1.5 padding:

  • PKCS#1 v1.5 has deterministic structure that enables Bleichenbacher-style
    chosen-ciphertext attacks and has known theoretical weaknesses.
  • PSS is provably secure in the random-oracle model; each signature includes
    a random salt, making two signatures of the same message look different
    (preventing replay-based chosen-message attacks).

Key size: 2048-bit RSA
  NIST SP 800-57 mandates ≥ 2048-bit RSA for security through 2030.
  This module defaults to 2048 bits; use 4096 for longer-lived keys.

"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.exceptions import InvalidSignature


def generate_keypair(key_size: int = 2048) -> tuple:
    """Generate a fresh RSA key pair for signing and verification.

    Args:
        key_size: RSA modulus size in bits.  Must be ≥ 2048 per NIST guidance.
                  Use 4096 for long-lived certificate authority keys.

    Returns:
        A (private_key, public_key) tuple.
        • private_key — RSAPrivateKey: kept SECRET by the signing party.
        • public_key  — RSAPublicKey : distributed to all verifying parties.

    Key generation note:
        Public exponent 65537 (0x10001) is the standard choice — it is prime,
        has a low Hamming weight (fast exponentiation), and avoids the small-
        exponent attacks that affect e=3 or e=17.

    In production:
        Keys should be generated once, stored in a HSM or secure vault, and
        loaded at runtime.  Never regenerate a key pair on every program start —
        verifiers would lose the ability to verify old signatures.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard safe exponent — see docstring note
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key: RSAPrivateKey, data: bytes) -> bytes:
    """Produce an RSA-PSS digital signature over SHA-256(*data*).

    Args:
        private_key : The signer's RSAPrivateKey.  This key must NEVER leave
                      the signing party — it is what makes the signature unique
                      and non-repudiable.
        data        : The raw bytes to sign.  For SDVN this is the serialised
                      SecureMessage payload before encryption, so the signature
                      covers the original plaintext semantics.

    Returns:
        Raw signature bytes (256 bytes for RSA-2048).  Base-64 encode these
        before embedding in JSON or transmitting over a text channel.

    PSS parameters:
        • MGF1-SHA256 : the mask generation function; using the same hash as
                        the message digest is the standard configuration.
        • MAX_LENGTH  : the salt is as long as the hash output (32 bytes for
                        SHA-256).  Maximum salt length maximises the tightness
                        of the PSS security proof.

    Why sign the plaintext (not the ciphertext)?
        Signing plaintext before encryption (Sign-then-Encrypt) allows the
        receiver to verify authorship after decryption.  The alternative
        (Encrypt-then-Sign) would let an attacker strip and replace the
        signature while leaving the ciphertext intact.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            # MAX_LENGTH = len(hash_output) = 32 bytes for SHA-256
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),  # Hash algorithm applied to *data* before signing
    )
    return signature


def verify_signature(public_key: RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS signature produced by sign().

    Args:
        public_key : The signer's RSAPublicKey.  Any party can hold this —
                     it is safe to distribute.  Only the matching private key
                     could have produced a valid signature.
        data       : The original bytes that were signed.
        signature  : The raw signature bytes returned by sign().

    Returns:
        True  — signature is authentic; data was signed by the private-key holder.
        False — signature is invalid; data may have been forged or tampered with.

    Security note — fail-closed:
        InvalidSignature is caught and converted to False rather than propagating,
        so callers cannot accidentally bypass the check in an exception handler.
        Any other unexpected exception is allowed to propagate (it indicates a
        programming error, not an adversarial condition).

    Non-repudiation implication:
        If this function returns True, the ONLY entity that could have produced
        the signature is the holder of the corresponding private key.  Combined
        with a timestamped entry in the BlockchainLedger, this constitutes a
        legally defensible audit record.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        # verify() returns None on success and raises InvalidSignature on failure.
        return True
    except InvalidSignature:
        # Signature is cryptographically invalid — reject the message.
        return False


def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Serialise *public_key* to DER-encoded SubjectPublicKeyInfo format.

    Args:
        public_key: The RSAPublicKey to serialise.

    Returns:
        DER-encoded bytes suitable for transmission over the network or storage.
        DER (Distinguished Encoding Rules) is a compact binary format; use
        serialize_public_key_pem() if a human-readable ASCII format is needed.

    Why DER for transmission?
        DER is more compact than PEM (no base-64 overhead, no header lines) and
        is unambiguously machine-parseable, making it preferable for embedding
        in a SecureMessage payload where every byte counts.

    To reconstruct on the receiver:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        public_key = load_der_public_key(received_bytes)
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key_from_bytes(der_bytes: bytes) -> RSAPublicKey:
    """Reconstruct an RSAPublicKey from DER bytes received from a peer.

    Args:
        der_bytes: The bytes produced by serialize_public_key().

    Returns:
        An RSAPublicKey ready for use in verify_signature().

    This is the companion function to serialize_public_key() and completes the
    full transmit-receive cycle required during the KEY_EXCHANGE message flow.
    """
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    # Type ignore: load_der_public_key returns a generic public key; we assert
    # it is RSA because only RSA keys are generated by this module.
    return load_der_public_key(der_bytes)  # type: ignore[return-value]


if __name__ == "__main__":
    print("=== rsa_signatures self-test ===\n")

    # Key generation — RSA-2048
    priv, pub = generate_keypair(key_size=2048)
    print("  generate_keypair     : RSA-2048 keypair generated  [OK]")

    # Sign a metric payload
    DATA = b'{"speed_kmh": 72, "gps": [51.5074, -0.1278], "vehicle_id": "V001"}'
    sig = sign(priv, DATA)
    assert len(sig) == 256, f"RSA-2048 signature must be 256 bytes, got {len(sig)}"
    print(f"  sign                 : signature = {len(sig)} bytes  [OK]")

    # Valid verification
    assert verify_signature(pub, DATA, sig), "Valid signature must verify"
    print("  verify_signature     : correct sig + data   -> ACCEPTED  [OK]")

    # Tampered data: even one character change invalidates the signature
    tampered = DATA.replace(b"72", b"99")
    assert not verify_signature(pub, tampered, sig), "Tampered data must fail"
    print("  verify_signature     : tampered data        -> REJECTED  [OK]")

    # Wrong public key: a different key pair cannot verify this signature
    _, other_pub = generate_keypair()
    assert not verify_signature(other_pub, DATA, sig), "Wrong public key must fail"
    print("  verify_signature     : wrong public key     -> REJECTED  [OK]")

    # PSS randomness: two signatures of the same message look different
    sig2 = sign(priv, DATA)
    assert sig != sig2, "PSS signatures of same message must be different (salt)"
    assert verify_signature(pub, DATA, sig2), "Second signature must still verify"
    print("  PSS randomness       : sig1 != sig2, both valid  [OK]")

    # DER serialise -> transmit -> deserialise round-trip
    der = serialize_public_key(pub)
    reconstructed = load_public_key_from_bytes(der)
    sig3 = sign(priv, DATA)
    assert verify_signature(reconstructed, DATA, sig3), "DER round-trip must verify"
    print(f"  DER round-trip       : {len(der)} bytes -> reconstruct -> verify  [OK]")

    print("\n[OK] rsa_signatures — all assertions passed")
