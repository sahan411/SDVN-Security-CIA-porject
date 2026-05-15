"""
blockchain_ledger.py — Append-only hash-chained audit ledger.

Supports Availability and Non-Repudiation by providing a tamper-evident log
of every security-relevant event.  Each block commits to the hash of its
predecessor, so altering any historical entry invalidates all subsequent
blocks — making retroactive falsification detectable during the next
integrity check.

This is a simplified in-memory ledger for demonstration purposes.  A
production deployment would persist blocks to a distributed store (e.g.
a permissioned blockchain or an append-only database) replicated across
multiple controller nodes so that no single point of failure can erase
the audit trail (Availability).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Block:
    index: int
    timestamp: float
    event_type: str             # e.g. "KEY_EXCHANGE", "METRIC_RECEIVED", "ATTACK_DETECTED"
    data: dict[str, Any]
    previous_hash: str
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        block_str = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "event_type": self.event_type,
                "data": self.data,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_str.encode()).hexdigest()

    def is_valid(self) -> bool:
        return self.hash == self._compute_hash()


class BlockchainLedger:
    """Append-only sequence of blocks with chain-integrity verification."""

    GENESIS_HASH = "0" * 64  # Conventional placeholder for the first block's previous_hash

    def __init__(self) -> None:
        self._chain: list[Block] = [self._create_genesis_block()]

    def _create_genesis_block(self) -> Block:
        return Block(
            index=0,
            timestamp=time.time(),
            event_type="GENESIS",
            data={"note": "SDVN-Security-CIA-Project ledger initialised"},
            previous_hash=self.GENESIS_HASH,
        )

    def append(self, event_type: str, data: dict[str, Any]) -> Block:
        """Append a new event block and return it."""
        last = self._chain[-1]
        block = Block(
            index=last.index + 1,
            timestamp=time.time(),
            event_type=event_type,
            data=data,
            previous_hash=last.hash,
        )
        self._chain.append(block)
        return block

    def verify_chain(self) -> bool:
        """Return True iff every block's hash is internally consistent and the chain is unbroken."""
        for i in range(1, len(self._chain)):
            current = self._chain[i]
            previous = self._chain[i - 1]
            if not current.is_valid():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def to_json(self) -> str:
        return json.dumps([asdict(b) for b in self._chain], indent=2)

    def __len__(self) -> int:
        return len(self._chain)
