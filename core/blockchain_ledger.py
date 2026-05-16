"""
core/blockchain_ledger.py — Hash-Chained Audit Ledger with RSA Signatures

Security property : NON-REPUDIATION + INTEGRITY (tamper-evident audit trail)
Course concept    : Blockchain-style hash chaining + asymmetric signing

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT THIS MODULE IS (AND IS NOT)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This is NOT a distributed blockchain with consensus, proof-of-work, or peer
nodes.  It is a LOCAL hash-chained ledger that demonstrates two properties:

    1. Tamper evidence  — any retroactive modification to any entry is
                          immediately detectable by recomputing the chain.
    2. Non-repudiation  — the controller RSA-signs every entry, so it cannot
                          later claim an event was never recorded or that the
                          record was fabricated.

This design maps directly to the SIGMA-V audit subsystem described in the FYP.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EQUATION 3.31 — SIGMA-V FYP MAPPING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Eq 3.31 defines the ledger entry hash construction in SIGMA-V:

    H_i = SHA-256( entry_id_i
                 ‖ vehicle_id_i
                 ‖ message_type_i
                 ‖ SHA-256(payload_i)       <- payload is hashed, not stored raw
                 ‖ timestamp_i
                 ‖ H_{i-1} )               <- chain link to predecessor

    σ_i = RSA-PSS-Sign( K_ctrl_priv , H_i )   <- controller commits to H_i

    LedgerEntry_i = ( entry_id_i, vehicle_id_i, message_type_i,
                      SHA-256(payload_i), timestamp_i,
                      H_{i-1}, H_i, σ_i )

    The genesis entry uses H_0 = SHA-256("GENESIS") as its previous_hash
    since it has no predecessor.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHY THE HASH CHAIN MAKES TAMPERING DETECTABLE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Because every H_i commits to H_{i-1}, the chain forms a dependency graph:

    H_0 <- H_1 <- H_2 <- H_3 <- ... <- H_n
              ↑
     altering entry 1 changes H_1
     -> H_2 = SHA-256(... ‖ H_1) no longer matches the stored value of H_2
     -> H_3, H_4, ... all mismatch too

An auditor who recomputes the chain from the genesis hash will find the first
divergence at the tampered position without needing to trust any stored value.

Compare with a simple log (no chaining):
    • Each entry is independent — altering entry 1 does not affect entries 2..n.
    • An attacker could quietly delete or rewrite any individual entry.
    • With the hash chain, deletion leaves a broken link; rewriting requires
      recomputing every subsequent H_i (infeasible without the controller's
      private key for re-signing).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHY RSA SIGNATURES GIVE NON-REPUDIATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The controller signs H_i with its long-term RSA private key K_ctrl_priv.
Because only the controller holds K_ctrl_priv, a valid σ_i proves:

    (a) The controller computed H_i — i.e., it received and processed the event.
    (b) The controller cannot later deny having processed the event ("I never
        saw that METRIC message") because σ_i, verifiable by anyone with the
        controller's public key, is cryptographic proof of acknowledgement.

This is Non-Repudiation: the controller cannot repudiate (deny) a signed entry.

HMAC alone cannot provide this property because both parties hold the HMAC key —
the vehicle could claim the controller forged the HMAC tag.  RSA asymmetry
eliminates that ambiguity: only the controller's private key produces σ_i.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from colorama import Fore, Style, init as colorama_init

from core.rsa_signatures import generate_keypair, sign, verify_signature, serialize_public_key

colorama_init(autoreset=True)


# ── Constants ────────────────────────────────────────────────────────────────

# The genesis previous_hash — a deterministic anchor with no real predecessor.
# SHA-256("GENESIS") is used rather than "0" * 64 so the value is itself a
# valid-looking digest and cannot be confused with an all-zero error sentinel.
_GENESIS_PREV_HASH: str = hashlib.sha256(b"GENESIS").hexdigest()


# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class LedgerEntry:
    """One immutable record in the hash-chained ledger.

    Fields map directly to the terms in Eq 3.31 of the SIGMA-V FYP:

        entry_id            — unique identifier for this record (UUID4)
        vehicle_id          — pseudonym of the vehicle that generated the event
        message_type        — e.g. "BEACON", "METRIC", "KEY_EXCHANGE", "ATTACK_DETECTED"
        payload_hash        — SHA-256(raw payload bytes), hex-encoded
                              The raw payload is NOT stored — only its digest.
                              This prevents the ledger from becoming a cleartext
                              data store while still committing to the content.
        timestamp           — Unix epoch (float) when the controller logged this entry
        previous_hash       — H_{i-1}: the entry_hash of the preceding LedgerEntry,
                              or _GENESIS_PREV_HASH for the first entry.
                              This is the "chain link" that makes tampering detectable.
        entry_hash          — H_i = SHA-256(entry_id ‖ vehicle_id ‖ message_type
                                           ‖ payload_hash ‖ timestamp ‖ previous_hash)
                              Commits to ALL fields of this entry AND its predecessor.
        controller_signature— σ_i = RSA-PSS-Sign(K_ctrl_priv, entry_hash bytes)
                              The controller's non-repudiable commitment to H_i.
    """
    entry_id: str
    vehicle_id: str
    message_type: str
    payload_hash: str           # hex SHA-256 of the raw payload
    timestamp: float
    previous_hash: str          # H_{i-1}
    entry_hash: str             # H_i  (computed, then signed)
    controller_signature: str   # base-64 RSA-PSS signature over entry_hash bytes


# ── Ledger ───────────────────────────────────────────────────────────────────

class BlockchainLedger:
    """Append-only, hash-chained, RSA-signed audit ledger.

    The controller holds the only instance of this class.  Every security-
    relevant event (KEY_EXCHANGE, METRIC received, attack detected, session
    closed) is appended here as a LedgerEntry.

    Typical usage:
        ledger = BlockchainLedger()              # genesis block created
        entry = ledger.add_entry(               # append a new record
            vehicle_id="veh-pseudonym-7a3f",
            message_type="METRIC",
            payload=b'{"speed":72,"loc":"51.5N"}',
            private_key=ledger.controller_private_key,
        )
        assert ledger.verify_chain()            # True — chain intact
        ledger.print_ledger()
        ledger.export_to_json("audit_log.json")
    """

    def __init__(self) -> None:
        # The controller's long-term RSA keypair.
        # In production: loaded from a HSM or encrypted key store at startup.
        # Here: generated fresh per run for demo simplicity.
        self.controller_private_key, self.controller_public_key = generate_keypair()

        # Ordered list of entries — index 0 is the genesis, index n is the tip.
        self._entries: List[LedgerEntry] = []

        # Index for O(1) lookup by entry_id.
        self._index: Dict[str, LedgerEntry] = {}

        # Append the immutable genesis entry that anchors the chain.
        self._append_genesis()

    # ── Private helpers ──────────────────────────────────────────────────────

    def _append_genesis(self) -> None:
        """Create and store the genesis entry (position 0 in the chain).

        The genesis entry represents "ledger initialised" and has no real
        predecessor, so its previous_hash is the conventional _GENESIS_PREV_HASH.
        It is signed exactly like any other entry so verify_chain() can treat
        every entry uniformly without a special case for position 0.
        """
        entry_id = "genesis-" + hashlib.sha256(
            str(time.time()).encode()
        ).hexdigest()[:8]

        payload_hash = hashlib.sha256(b"LEDGER_GENESIS").hexdigest()
        timestamp = time.time()

        # H_0 = SHA-256(entry_id ‖ "CONTROLLER" ‖ "GENESIS" ‖ payload_hash
        #               ‖ timestamp ‖ _GENESIS_PREV_HASH)
        entry_hash = self._compute_entry_hash(
            entry_id, "CONTROLLER", "GENESIS", payload_hash,
            timestamp, _GENESIS_PREV_HASH,
        )

        # σ_0 = RSA-PSS-Sign(K_ctrl_priv, bytes.fromhex(entry_hash))
        # Signing the raw hash bytes (not the hex string) is conventional and
        # avoids encoding ambiguities between ASCII and UTF-8 representations.
        signature = sign(self.controller_private_key, bytes.fromhex(entry_hash))

        import base64
        genesis = LedgerEntry(
            entry_id=entry_id,
            vehicle_id="CONTROLLER",
            message_type="GENESIS",
            payload_hash=payload_hash,
            timestamp=timestamp,
            previous_hash=_GENESIS_PREV_HASH,
            entry_hash=entry_hash,
            controller_signature=base64.b64encode(signature).decode(),
        )
        self._entries.append(genesis)
        self._index[entry_id] = genesis

    @staticmethod
    def _compute_entry_hash(
        entry_id: str,
        vehicle_id: str,
        message_type: str,
        payload_hash: str,
        timestamp: float,
        previous_hash: str,
    ) -> str:
        """Compute H_i per Eq 3.31: SHA-256 over the canonical concatenation of all fields.

        Field ordering is fixed and documented here so that any independent
        implementation can reproduce the same hash given the same inputs.
        All fields are converted to UTF-8 bytes before concatenation to
        eliminate platform-dependent encoding differences.

        Canonical order:
            entry_id ‖ vehicle_id ‖ message_type ‖ payload_hash
            ‖ str(timestamp) ‖ previous_hash
        """
        canonical = (
            entry_id
            + vehicle_id
            + message_type
            + payload_hash
            + str(timestamp)
            + previous_hash
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _tip_hash(self) -> str:
        """Return the entry_hash of the most recently appended entry."""
        return self._entries[-1].entry_hash

    # ── Public interface ─────────────────────────────────────────────────────

    def add_entry(
        self,
        vehicle_id: str,
        message_type: str,
        payload: bytes,
        private_key,
    ) -> LedgerEntry:
        """Append a new signed, chained entry to the ledger.

        This is the core operation of the ledger and corresponds directly to
        Eq 3.31 in the SIGMA-V FYP.  Steps performed:

            1. Compute payload_hash = SHA-256(payload)
               The raw payload is never stored — only its digest.

            2. Compute H_i = SHA-256(entry_id ‖ vehicle_id ‖ message_type
                                    ‖ payload_hash ‖ timestamp ‖ H_{i-1})
               H_{i-1} is the current chain tip, linking this entry to its
               predecessor and making the chain tamper-evident.

            3. Compute σ_i = RSA-PSS-Sign(K_ctrl_priv, bytes.fromhex(H_i))
               The controller commits to H_i non-repudiably.

            4. Append the new LedgerEntry to self._entries and self._index.

        Args:
            vehicle_id  : Pseudonym of the vehicle whose event is being logged.
            message_type: One of "BEACON", "METRIC", "KEY_EXCHANGE",
                          "LEDGER_UPDATE", "SESSION_CLOSED", "ATTACK_DETECTED".
            payload     : Raw bytes of the event data (e.g. the decrypted METRIC
                          message body).  Only the SHA-256 hash is retained.
            private_key : Controller's RSA private key for signing H_i.
                          Use self.controller_private_key in the demo.

        Returns:
            The newly created and appended LedgerEntry.
        """
        import base64

        entry_id = str(uuid.uuid4())
        timestamp = time.time()

        # Step 1 — hash the payload so raw data is not stored in the ledger.
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Step 2 — compute H_i, chaining to H_{i-1} (the current tip).
        previous_hash = self._tip_hash()
        entry_hash = self._compute_entry_hash(
            entry_id, vehicle_id, message_type,
            payload_hash, timestamp, previous_hash,
        )

        # Step 3 — RSA-PSS sign H_i with the controller's private key.
        # Signing the raw hash bytes (32 bytes for SHA-256) rather than the
        # 64-character hex string is conventional practice: it is more compact
        # and avoids any possibility of hex-encoding ambiguity.
        raw_signature = sign(private_key, bytes.fromhex(entry_hash))
        signature_b64 = base64.b64encode(raw_signature).decode()

        # Step 4 — construct, store, and return the immutable entry.
        entry = LedgerEntry(
            entry_id=entry_id,
            vehicle_id=vehicle_id,
            message_type=message_type,
            payload_hash=payload_hash,
            timestamp=timestamp,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
            controller_signature=signature_b64,
        )
        self._entries.append(entry)
        self._index[entry_id] = entry
        return entry

    def verify_entry(self, entry_id: str) -> bool:
        """Verify the integrity and authenticity of one specific entry.

        Checks performed:
            (a) entry_hash is internally consistent — recomputing it from the
                stored fields yields the same value.
            (b) controller_signature is a valid RSA-PSS signature over the
                entry_hash bytes under the controller's public key.

        Args:
            entry_id: The UUID of the entry to verify.

        Returns:
            True  — both checks pass; the entry is authentic and unmodified.
            False — either check fails; the entry has been tampered with or
                    the signature is invalid.

        Note: this does NOT verify the chain link (previous_hash).  For full
        chain integrity, use verify_chain() which checks every entry in order.
        """
        import base64

        entry = self._index.get(entry_id)
        if entry is None:
            return False

        # Check (a): recompute H_i from stored fields and compare.
        expected_hash = self._compute_entry_hash(
            entry.entry_id, entry.vehicle_id, entry.message_type,
            entry.payload_hash, entry.timestamp, entry.previous_hash,
        )
        if expected_hash != entry.entry_hash:
            # The entry's own fields have been modified (e.g. vehicle_id changed).
            return False

        # Check (b): verify the RSA-PSS signature over the entry_hash bytes.
        raw_signature = base64.b64decode(entry.controller_signature)
        return verify_signature(
            self.controller_public_key,
            bytes.fromhex(entry.entry_hash),
            raw_signature,
        )

    def verify_chain(self) -> bool:
        """Traverse every entry in sequence and verify all hash links and signatures.

        Algorithm (O(n) in ledger length):
            For i = 0 to len(entries)-1:
                1. verify_entry(entries[i].entry_id)  — internal hash + RSA sig
                2. if i > 0: entries[i].previous_hash == entries[i-1].entry_hash
                   (the chain link — each entry must reference its predecessor)

        Returns:
            True  — every entry is internally valid and the chain is unbroken.
            False — at least one entry failed; the ledger has been tampered with.

        Why check previous_hash separately from verify_entry()?
            verify_entry() confirms that an entry's hash is consistent with its
            own fields, but does NOT confirm it is linked to the correct
            predecessor.  An attacker could splice entries from a different
            ledger while keeping each one internally self-consistent.
            Checking previous_hash == entries[i-1].entry_hash closes this gap.
        """
        for i, entry in enumerate(self._entries):
            # Check internal hash consistency + RSA signature.
            if not self.verify_entry(entry.entry_id):
                return False

            # Check the chain link to the predecessor (skip for genesis).
            if i > 0:
                expected_prev = self._entries[i - 1].entry_hash
                if entry.previous_hash != expected_prev:
                    # Chain broken at position i — insertion, deletion, or
                    # reordering of entries has occurred.
                    return False

        return True

    def tamper_detect(self) -> dict:
        """Scan the full chain and report the position and nature of any tampering.

        Unlike verify_chain() which returns a single bool, this method returns
        a diagnostic report identifying WHERE the chain breaks and WHY, making
        it useful for forensic analysis and demo output.

        Returns:
            A dict with:
                "intact"          — bool: True if no issues found
                "total_entries"   — int: number of entries checked
                "broken_at"       — list of dicts describing each broken link:
                    {
                      "position"   : int   (0-based index in the chain),
                      "entry_id"   : str,
                      "reason"     : str   ("hash_mismatch" | "signature_invalid"
                                           | "chain_link_broken"),
                    }
        """
        import base64

        broken: list[dict] = []

        for i, entry in enumerate(self._entries):
            # Check 1: internal hash consistency.
            expected_hash = self._compute_entry_hash(
                entry.entry_id, entry.vehicle_id, entry.message_type,
                entry.payload_hash, entry.timestamp, entry.previous_hash,
            )
            if expected_hash != entry.entry_hash:
                broken.append({
                    "position": i,
                    "entry_id": entry.entry_id,
                    "reason": "hash_mismatch",
                })
                continue  # No point checking the signature if the hash is wrong.

            # Check 2: RSA signature validity.
            raw_sig = base64.b64decode(entry.controller_signature)
            if not verify_signature(
                self.controller_public_key,
                bytes.fromhex(entry.entry_hash),
                raw_sig,
            ):
                broken.append({
                    "position": i,
                    "entry_id": entry.entry_id,
                    "reason": "signature_invalid",
                })

            # Check 3: chain link to predecessor (skip genesis).
            if i > 0:
                expected_prev = self._entries[i - 1].entry_hash
                if entry.previous_hash != expected_prev:
                    broken.append({
                        "position": i,
                        "entry_id": entry.entry_id,
                        "reason": "chain_link_broken",
                    })

        return {
            "intact": len(broken) == 0,
            "total_entries": len(self._entries),
            "broken_at": broken,
        }

    def get_entry(self, entry_id: str) -> Optional[LedgerEntry]:
        """Return the LedgerEntry for *entry_id*, or None if not found.

        O(1) lookup via the internal index.
        """
        return self._index.get(entry_id)

    def print_ledger(self) -> None:
        """Pretty-print every entry to stdout with colour-coded validity indicators.

        Each entry is labelled [VALID] in green or [TAMPERED] in red based on
        the result of verify_entry().  This is the primary demo output method.
        """
        print(f"\n{Fore.CYAN}{'═' * 70}")
        print(f"  SDVN BLOCKCHAIN LEDGER  —  {len(self._entries)} entries")
        print(f"{'═' * 70}{Style.RESET_ALL}\n")

        for i, entry in enumerate(self._entries):
            valid = self.verify_entry(entry.entry_id)
            status = (
                f"{Fore.GREEN}[VALID]   {Style.RESET_ALL}"
                if valid else
                f"{Fore.RED}[TAMPERED]{Style.RESET_ALL}"
            )

            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.timestamp))
            print(f"  {status} #{i:03d}  {entry.message_type:<18}  {ts}")
            print(f"           Vehicle : {entry.vehicle_id}")
            print(f"           Entry ID: {entry.entry_id}")
            print(f"           Prev  H : {entry.previous_hash[:24]}...")
            print(f"           Entry H : {entry.entry_hash[:24]}...")
            print(f"           Sig     : {entry.controller_signature[:24]}...")
            print()

        # Final chain-level verdict.
        chain_ok = self.verify_chain()
        if chain_ok:
            print(f"{Fore.GREEN}  Chain integrity: INTACT — no tampering detected.{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}  Chain integrity: BROKEN — tampering detected!{Style.RESET_ALL}\n")

    def export_to_json(self, filepath: str) -> None:
        """Serialise the full ledger to a JSON file at *filepath*.

        The export includes every LedgerEntry field verbatim, including
        the controller signature.  This file serves as a portable audit
        record that can be verified by any party holding the controller's
        public key — even offline, without access to this system.

        Args:
            filepath: Absolute or relative path for the output file.
                      Parent directory must exist.

        The exported format:
            {
                "ledger_version": "sdvn-v1",
                "controller_public_key": "<PEM string>",
                "entry_count": <int>,
                "entries": [ { ...LedgerEntry fields... }, ... ]
            }
        """
        import base64
        from cryptography.hazmat.primitives import serialization

        # Export the controller's public key in PEM format so verifiers can
        # authenticate every signature without contacting the controller.
        pub_pem = self.controller_public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        document = {
            "ledger_version": "sdvn-v1",
            "controller_public_key": pub_pem,
            "entry_count": len(self._entries),
            "entries": [asdict(e) for e in self._entries],
        }

        Path(filepath).write_text(
            json.dumps(document, indent=2),
            encoding="utf-8",
        )
        print(f"{Fore.CYAN}[LEDGER]{Style.RESET_ALL} Exported {len(self._entries)} entries -> {filepath}")

    # ── Diagnostics ──────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"BlockchainLedger(entries={len(self._entries)}, "
            f"tip={self._tip_hash()[:16]}...)"
        )


if __name__ == "__main__":
    print("=== blockchain_ledger self-test ===\n")

    ledger = BlockchainLedger()
    assert len(ledger) == 1, "Genesis block must be created on __init__"
    priv = ledger.controller_private_key
    print(f"  __init__             : genesis created, RSA keypair ready  [OK]")
    print(f"  repr                 : {ledger!r}")

    # Add three entries and verify each individually
    e1 = ledger.add_entry("V001", "KEY_EXCHANGE",
                          b"ECDH session established for V001", priv)
    e2 = ledger.add_entry("V001", "METRIC",
                          b'{"speed_kmh": 72, "gps": [51.5, -0.12]}', priv)
    e3 = ledger.add_entry("V001", "METRIC",
                          b'{"speed_kmh": 68, "gps": [51.51, -0.13]}', priv)
    assert len(ledger) == 4   # genesis + 3 entries
    print(f"  add_entry ×3         : ledger has {len(ledger)} entries  [OK]")

    for entry in [e1, e2, e3]:
        assert ledger.verify_entry(entry.entry_id), \
            f"Entry {entry.entry_id[:8]} must verify"
    print("  verify_entry         : all 3 entries individually valid  [OK]")

    # Full chain must be intact
    assert ledger.verify_chain() is True
    report = ledger.tamper_detect()
    assert report["intact"] is True and len(report["broken_at"]) == 0
    print("  verify_chain         : intact chain -> True  [OK]")
    print("  tamper_detect        : no broken links found  [OK]")

    # Tamper: overwrite vehicle_id of entry 2
    original_vid = ledger._entries[2].vehicle_id
    ledger._entries[2].vehicle_id = "ATTACKER"
    assert ledger.verify_chain() is False
    report2 = ledger.tamper_detect()
    assert not report2["intact"]
    tampered_pos = report2["broken_at"][0]["position"]
    tampered_reason = report2["broken_at"][0]["reason"]
    print(f"  tamper_detect        : tampering caught at pos={tampered_pos}, "
          f"reason={tampered_reason}  [OK]")

    # Restore and confirm recovery
    ledger._entries[2].vehicle_id = original_vid
    assert ledger.verify_chain() is True
    print("  restore + verify     : chain intact after restore  [OK]")

    # get_entry O(1) lookup
    fetched = ledger.get_entry(e2.entry_id)
    assert fetched is e2
    print("  get_entry            : O(1) lookup by entry_id  [OK]")

    # print_ledger for visual check
    print()
    ledger.print_ledger()

    print("[OK] blockchain_ledger — all assertions passed")
