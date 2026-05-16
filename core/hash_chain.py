"""
core/hash_chain.py — SHA-256 Hash Chain

Security property : INTEGRITY (ordered message sequence)
Course concept    : Hash chain / blockchain ancestry

What a hash chain is
---------------------
A hash chain links each message to its predecessor by including the previous
hash in the current hash computation:

    H[0] = SHA256( seed )
    H[1] = SHA256( message[1] || H[0] )
    H[2] = SHA256( message[2] || H[1] )
    H[n] = SHA256( message[n] || H[n-1] )

Why hash chains detect tampering
----------------------------------
Because each link H[i] depends on ALL prior content, altering any message
at position i invalidates H[i] and every subsequent link.  An auditor who
holds the original seed can recompute the entire chain and spot the first
divergence — they do not need to trust any intermediate party.

Why order matters
------------------
The concatenation order is SHA256( message || previous_hash ).  Reversing
it or using XOR instead of concatenation weakens the construction:
  • message || prev_hash   — each new hash commits to a specific predecessor.
  • prev_hash || message   — functionally equivalent here, but the chosen
                             order mirrors Merkle–Damgård padding conventions.
  • XOR                    — commutative, so an attacker could swap two messages
                             without changing the combined value.

How this maps to SIGMA-V / SDVN
---------------------------------
In a vehicular network, the SDN Controller logs every routing decision and
metric report in a hash chain.  If a compromised node later claims it never
sent a particular METRIC message, the controller can replay the chain from
the genesis seed to prove the message was received and logged at a specific
position — supporting Non-Repudiation as well as Integrity.

"""

import hashlib
from dataclasses import dataclass, field
from typing import List


@dataclass
class _ChainEntry:
    """Internal record storing one message and its hash link."""
    message: str
    hash_value: str   # hex-encoded SHA-256 output


class HashChain:
    """Ordered, append-only SHA-256 hash chain.

    Usage:
        chain = HashChain()
        chain.initialize("shared-genesis-seed")
        h1 = chain.add("speed=72")
        h2 = chain.add("speed=68")
        assert chain.verify("speed=72", h1, position=0)
        assert chain.detect_tampering() is True   # chain is intact
    """

    def __init__(self) -> None:
        # _entries holds the ordered sequence of (message, hash) pairs.
        self._entries: List[_ChainEntry] = []
        # _genesis_hash anchors the chain; stored separately so position 0
        # can reference it as its "previous" hash without an off-by-one.
        self._genesis_hash: str = ""

    # ── Public interface ────────────────────────────────────────────────────

    def initialize(self, seed: str) -> None:
        """Anchor the chain to a deterministic genesis hash derived from *seed*.

        Args:
            seed: A shared secret string (or session ID) known to both parties.
                  The seed should be unique per session — reusing it across
                  sessions allows an attacker to splice entries from one session
                  into another.

        The genesis hash is SHA256(seed) rather than seed itself so that the
        raw seed is never stored or transmitted as part of any chain link.
        """
        self._entries.clear()
        # Hash the seed so the genesis value is a fixed-length digest —
        # uniform output regardless of how long or short the seed string is.
        self._genesis_hash = hashlib.sha256(seed.encode()).hexdigest()

    def add(self, message: str) -> str:
        """Append *message* to the chain and return its hash link.

        Args:
            message: The plaintext string to commit to the chain.
                     In SDVN this would be a serialised SecureMessage payload.

        Returns:
            Hex-encoded SHA-256 hash of (message || previous_hash).
            The caller should attach this hash to the outgoing packet so the
            receiver can independently verify the link.

        Hash construction:
            current_hash = SHA256( message.encode('utf-8') || previous_hash_bytes )

            Encoding message to UTF-8 before hashing ensures consistent byte
            representation regardless of the platform's default encoding.
            The previous hash is decoded from hex back to raw bytes so that
            the input to SHA256 is always bytes (never mixed str + bytes).
        """
        # Determine the previous hash: genesis for the very first entry,
        # otherwise the hash of the most-recently added entry.
        previous_hash_hex = (
            self._genesis_hash if not self._entries
            else self._entries[-1].hash_value
        )

        # Concatenate message bytes with the raw previous-hash bytes.
        # Using raw bytes (not the hex string) halves the input size and
        # avoids any ambiguity between the hex characters and message content.
        previous_hash_bytes = bytes.fromhex(previous_hash_hex)
        combined = message.encode("utf-8") + previous_hash_bytes
        current_hash = hashlib.sha256(combined).hexdigest()

        self._entries.append(_ChainEntry(message=message, hash_value=current_hash))
        return current_hash

    def verify(self, message: str, hash_value: str, position: int) -> bool:
        """Check that *message* at *position* produces the claimed *hash_value*.

        Args:
            message   : The message string to verify.
            hash_value: The hex-encoded hash that was reported for this position.
            position  : Zero-based index into the chain (0 = first entry added).

        Returns:
            True  if the recomputed hash matches *hash_value* exactly.
            False if there is any mismatch — the message or position is wrong.

        This method verifies a single link in isolation.  To check the entire
        chain for internal consistency use detect_tampering() instead.
        """
        if position < 0 or position >= len(self._entries):
            return False

        # Determine the previous hash for this position (same logic as add()).
        previous_hash_hex = (
            self._genesis_hash if position == 0
            else self._entries[position - 1].hash_value
        )

        previous_hash_bytes = bytes.fromhex(previous_hash_hex)
        combined = message.encode("utf-8") + previous_hash_bytes
        expected_hash = hashlib.sha256(combined).hexdigest()

        # Constant-time comparison prevents timing leaks about partial matches.
        import hmac as _hmac
        return _hmac.compare_digest(expected_hash, hash_value)

    def detect_tampering(self) -> bool:
        """Traverse the entire chain and return True iff every link is valid.

        How tampering is detected:
            For each entry at position i, recompute SHA256(message[i] || H[i-1])
            and compare it to the stored H[i].  If any entry has been modified
            (message changed, hash overwritten, or entry deleted/inserted),
            the recomputed hash will diverge from the stored value at that point
            and all subsequent positions — the first divergence is the tamper site.

        Returns:
            True  — chain is intact; no tampering detected.
            False — at least one entry is inconsistent; chain has been modified.

        This is O(n) in the number of entries.  It should be called by the
        controller after every LEDGER_UPDATE to maintain audit integrity.
        """
        if not self._entries:
            # An empty chain (only genesis) is trivially intact.
            return True

        for i, entry in enumerate(self._entries):
            # Use our own verify() to keep the recomputation logic in one place.
            if not self.verify(entry.message, entry.hash_value, i):
                return False  # Tamper detected at position i

        return True

    # ── Convenience accessors ───────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._entries)

    def get_tip(self) -> str:
        """Return the hash of the most recently added entry (the chain tip)."""
        if not self._entries:
            return self._genesis_hash
        return self._entries[-1].hash_value


if __name__ == "__main__":
    print("=== hash_chain self-test ===\n")

    chain = HashChain()
    chain.initialize("shared-genesis-seed")
    print(f"  initialize      : genesis = {chain.get_tip()[:32]}...")

    h0 = chain.add("metric-payload-0")
    h1 = chain.add("metric-payload-1")
    h2 = chain.add("metric-payload-2")
    assert len(chain) == 3, "Chain must have 3 entries"
    print(f"  add ×3          : tip = {chain.get_tip()[:32]}...")

    assert chain.verify("metric-payload-0", h0, 0), "Position 0 must verify"
    assert chain.verify("metric-payload-1", h1, 1), "Position 1 must verify"
    assert chain.verify("metric-payload-2", h2, 2), "Position 2 must verify"
    print("  verify          : all 3 positions verified  [OK]")

    assert not chain.verify("metric-payload-0", h1, 0), "Wrong hash at pos 0 must fail"
    assert not chain.verify("tampered-payload", h0, 0), "Tampered message must fail"
    print("  verify          : wrong hash / tampered msg -> REJECTED  [OK]")

    assert chain.detect_tampering() is True, "Intact chain must return True"
    print("  detect_tampering: intact chain -> True  [OK]")

    # Directly overwrite a stored hash to simulate tampering
    chain._entries[1].hash_value = "0" * 64
    assert chain.detect_tampering() is False, "Tampered chain must return False"
    print("  detect_tampering: tampered chain -> False  [OK]")

    # Verify that each link actually commits to its predecessor
    chain2 = HashChain()
    chain2.initialize("same-seed")
    chain3 = HashChain()
    chain3.initialize("same-seed")
    link_a = chain2.add("payload")
    link_b = chain3.add("payload")
    assert link_a == link_b, "Deterministic: same seed + same message -> same link"
    print("  determinism     : same seed+msg -> same hash  [OK]")

    print("\n[OK] hash_chain — all assertions passed")
