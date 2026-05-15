"""
core/aes_gcm_encrypt.py — AES-256-GCM Authenticated Encryption

Security property : CONFIDENTIALITY + INTEGRITY (of ciphertext)
Course concept    : Symmetric authenticated encryption with associated data (AEAD)

Why AES-GCM over AES-CBC?
--------------------------
AES-CBC (Cipher Block Chaining) provides confidentiality only — it does NOT
authenticate the ciphertext.  This opens two well-known attack classes:

  1. Padding-oracle attacks (POODLE, BEAST): an attacker who can submit crafted
     ciphertexts and observe whether the receiver accepts or rejects padding can
     decrypt the message byte by byte without knowing the key.

  2. Bit-flipping: flipping a bit in ciphertext block i produces a predictable
     flip in plaintext block i+1, letting an attacker modify fields (e.g. a
     "speed" value) even without decryption ability.

AES-GCM (Galois/Counter Mode) is an AEAD (Authenticated Encryption with
Associated Data) scheme that solves both problems in a single primitive:

  • CTR mode encryption gives confidentiality (keystream XOR'd with plaintext).
  • GHASH authentication tag covers BOTH the ciphertext AND any associated data.
  • Any modification to the ciphertext causes tag verification to fail BEFORE
    the plaintext is returned to the application — fail-closed by design.

What "authenticated encryption" means
---------------------------------------
"Authenticated" here means the decryption function is also a verification
function.  The receiver gets plaintext ONLY if:
    (a) The ciphertext was produced by someone holding the correct key, AND
    (b) The ciphertext has not been modified since encryption.

If either condition fails, decrypt() raises an exception — the attacker
learns nothing about the plaintext from a rejected decryption attempt.

Nonce uniqueness requirement  ⚠️
----------------------------------
AES-GCM's security model REQUIRES that the (key, nonce) pair is never reused.
Reusing a nonce under the same key is catastrophic:
  • XOR of two ciphertexts = XOR of two plaintexts → both plaintexts leak.
  • The authentication key H = E_K(0) is exposed, breaking all future tags.

This module generates a fresh 96-bit (12-byte) cryptographically random nonce
for every call to encrypt().  The nonce is returned alongside the ciphertext
so the receiver can use it for decryption — it is NOT secret.

Return format (dict)
---------------------
    {
        "ciphertext" : bytes  — encrypted payload (includes GCM auth tag appended
                                by the cryptography library),
        "nonce"      : bytes  — 12-byte random IV (safe to transmit in plaintext),
        "tag_length" : int    — always 16 (128-bit GCM tag, NIST recommended),
    }

The dict is designed to be JSON-serialisable after base64-encoding the bytes
fields, making it easy to embed in a SecureMessage.payload.
"""

import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# NIST SP 800-38D recommends 96-bit (12-byte) nonces for GCM.
# Any other length forces an expensive GHASH pre-computation and subtly
# reduces the security margin — always use exactly 12 bytes.
_NONCE_BYTES: int = 12

# GCM authentication tag length in bytes.  128 bits is the NIST recommended
# maximum; shorter tags (e.g. 96-bit) reduce forgery resistance proportionally.
_TAG_BYTES: int = 16


def encrypt(
    key: bytes,
    plaintext: bytes,
    additional_data: Optional[bytes] = None,
) -> dict:
    """Encrypt *plaintext* with AES-256-GCM and return the ciphertext bundle.

    Args:
        key            : 32-byte AES-256 key.  Must be kept secret.  In this
                         project the key is the session key derived from ECDH
                         (see core/key_exchange.py) — never a hard-coded value.
        plaintext      : The raw bytes to encrypt.  For SDVN this is typically
                         a JSON-serialised metric or beacon payload.
        additional_data: Optional bytes that are AUTHENTICATED but NOT encrypted.
                         Use this for header fields that must be readable in
                         transit (e.g. MessageType, sender_id, sequence_number)
                         but must not be silently modified.  If the receiver
                         passes different additional_data, decryption fails.

    Returns:
        A dict with keys:
          "ciphertext"  — bytes: encrypted payload with 16-byte GCM tag appended.
          "nonce"       — bytes: 12-byte random nonce. Include with every message.
          "tag_length"  — int : always 16; helps receivers know where tag ends.

    Raises:
        ValueError: if *key* is not exactly 16, 24, or 32 bytes.

    Nonce generation:
        os.urandom() reads from the OS CSPRNG (CryptGenRandom on Windows,
        /dev/urandom on Linux).  This is the correct source for cryptographic
        nonces — never use random.random() or time-based values.
    """
    # Validate key length early — AESGCM raises a less informative error later.
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES key must be 16, 24, or 32 bytes; got {len(key)}")

    # Generate a fresh random nonce for every encryption call.
    # Even within the same session, each message MUST use a different nonce.
    nonce = os.urandom(_NONCE_BYTES)

    aesgcm = AESGCM(key)

    # AESGCM.encrypt() appends the 16-byte authentication tag to the ciphertext.
    # The combined output is len(plaintext) + 16 bytes.
    ciphertext = aesgcm.encrypt(nonce, plaintext, additional_data)

    return {
        "ciphertext": ciphertext,   # bytes: encrypted payload + tag
        "nonce": nonce,             # bytes: must accompany ciphertext to decrypt
        "tag_length": _TAG_BYTES,   # int: documents that last 16 bytes are the GCM tag
    }


def decrypt(
    key: bytes,
    ciphertext_bundle: dict,
    additional_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt and authenticate a ciphertext bundle produced by encrypt().

    Args:
        key               : The same 32-byte AES-256 key used during encryption.
        ciphertext_bundle : The dict returned by encrypt(), containing
                            "ciphertext" and "nonce" keys.
        additional_data   : Must be identical to what was passed to encrypt().
                            Any difference causes authentication to fail — this
                            prevents an attacker from reattaching a ciphertext
                            to a different message header.

    Returns:
        The original plaintext bytes if authentication succeeds.

    Raises:
        cryptography.exceptions.InvalidTag : if the ciphertext has been tampered
            with, the key is wrong, or additional_data does not match.  The
            caller MUST treat this exception as a hard security failure and
            discard the message — never attempt partial decryption.
        KeyError  : if *ciphertext_bundle* is missing required keys.

    Fail-closed guarantee:
        AESGCM.decrypt() verifies the GCM authentication tag BEFORE returning
        any plaintext.  There is no API to skip verification — the library
        enforces authenticated decryption at the type level.
    """
    ciphertext = ciphertext_bundle["ciphertext"]
    nonce = ciphertext_bundle["nonce"]

    aesgcm = AESGCM(key)

    # decrypt() raises InvalidTag automatically if verification fails.
    # Do NOT catch this exception here — let it propagate to the caller
    # so that security decisions are made at the application layer, not buried.
    plaintext = aesgcm.decrypt(nonce, ciphertext, additional_data)
    return plaintext
