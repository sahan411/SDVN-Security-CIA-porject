"""
core/hmac_auth.py — HMAC-SHA256 Message Authentication

Security property : INTEGRITY + AUTHENTICATION
Course concept    : Hash-based Message Authentication Code (HMAC)

What this module proves
-----------------------
HMAC answers two questions simultaneously:
  1. Authentication  — "Did the claimed sender actually send this?"
                       Only a party that holds the secret key K can produce a
                       valid tag, so a valid tag proves the sender's identity.
  2. Integrity       — "Has the message been modified in transit?"
                       Any single-bit change to the message produces a
                       completely different tag (avalanche effect), so the
                       receiver detects tampering before trusting the payload.

Why HMAC instead of a plain hash?
----------------------------------
A plain SHA-256 hash of a message provides integrity but NOT authentication —
an attacker who intercepts "H(message)" can compute "H(tampered_message)" just
as easily, because SHA-256 has no secret component.  HMAC wraps the hash with
a secret key K so that only parties knowing K can generate or verify tags.

    HMAC-SHA256(K, M) = SHA256( (K ⊕ opad) || SHA256( (K ⊕ ipad) || M ) )

    where ipad = 0x36 repeated, opad = 0x5C repeated.

The double-hash construction defends against length-extension attacks that
would otherwise let an attacker append data to M without knowing K.

Visual HMAC flow
----------------

    Vehicle                                       Controller
    ─────────────────────────────────────────────────────────
    message = "speed=72,loc=51.5N"
    tag = HMAC-SHA256(PSK, message)
    ──── message + tag ─────────────────────────────────────►
                                         recompute expected_tag
                                                  = HMAC-SHA256(PSK, message)
                                         compare_digest(tag, expected_tag)
                                              ✓  tags match → message authentic
                                              ✗  tags differ → DROP + log attack

"""

import hashlib
import hmac


def generate_hmac(key: bytes, message: bytes) -> str:
    """Compute an HMAC-SHA256 tag over *message* using *key*.

    Args:
        key     : The shared secret key.  Must be kept confidential — leaking
                  it allows an attacker to forge valid tags for any message.
        message : The raw bytes to authenticate.  The entire payload should be
                  included so that field-level substitution attacks are caught.

    Returns:
        A lowercase hex-encoded string of the 32-byte (256-bit) HMAC tag.
        Hex encoding makes the tag safe to embed in JSON or HTTP headers.

    Cryptographic note:
        SHA-256 is used as the underlying hash function because it is
        collision-resistant and produces a 256-bit output, giving 128 bits
        of security against birthday attacks on the tag space.
    """
    # hmac.new() accepts a callable for the digestmod — using hashlib.sha256
    # directly (not the string "sha256") avoids a dictionary lookup internally
    # and is the recommended form in the Python docs.
    tag = hmac.new(key, message, hashlib.sha256).hexdigest()
    return tag


def verify_hmac(key: bytes, message: bytes, received_hmac: str) -> bool:
    """Verify that *received_hmac* is the correct HMAC-SHA256 tag for *message*.

    Args:
        key          : The same shared secret key used during generation.
        message      : The message bytes exactly as received (after any decoding
                       but before any parsing — parse only after verification).
        received_hmac: The hex-encoded tag received alongside the message.

    Returns:
        True  if the tag is authentic and the message is unmodified.
        False if the tag is wrong, meaning the message was forged or corrupted.

    Security note — timing safety:
        This function uses hmac.compare_digest() instead of the == operator.
        A plain == comparison short-circuits on the first differing character,
        leaking how many leading bytes of the tag match via response-time
        differences (a timing-oracle attack).  compare_digest() always inspects
        every byte in constant time, making timing-based forgery infeasible.

    Fail-safe design:
        The function returns False (reject) on any error rather than raising an
        exception, so callers cannot accidentally bypass the check in an
        exception handler.
    """
    try:
        # Recompute the expected tag from scratch under the same key.
        # We never trust the received tag directly — only compare it.
        expected_tag = generate_hmac(key, message)

        # Constant-time comparison — see Security note in docstring.
        return hmac.compare_digest(expected_tag, received_hmac)
    except Exception:
        # Any unexpected error (wrong type, zero-length key, etc.) is treated
        # as a verification failure rather than an unhandled exception.
        return False


# Alias so demo_scenarios.py can call compute_hmac() without changing the
# primary public name generate_hmac() used everywhere else.
compute_hmac = generate_hmac
