"""Extension Provenance Ledger.

Every extension execution emits immutable execution receipts.
Append-only lineage. Chain-hashed provenance.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field


class ExtensionExecutionReceipt(BaseModel):
    """Immutable execution receipt for an extension."""

    receipt_id: str
    extension_id: str
    package_hash: str
    worker_contract_version: str
    execution_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    execution_duration_ms: int
    output_hash: str
    deterministic_fingerprint: str
    replay_lineage: List[str] = Field(default_factory=list)
    previous_receipt_hash: str = ""
    receipt_hash: str = ""
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = self.model_dump(exclude={"receipt_hash"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


class ExtensionProvenanceLedger:
    """Append-only provenance ledger for extension executions."""

    def __init__(self, ledger_dir: Path) -> None:
        self.ledger_dir = Path(ledger_dir)
        self.ledger_dir.mkdir(parents=True, exist_ok=True)
        self._receipts: List[ExtensionExecutionReceipt] = []

    def append_receipt(self, receipt: ExtensionExecutionReceipt) -> ExtensionExecutionReceipt:
        prev_hash = self._receipts[-1].receipt_hash if self._receipts else ""
        # Update previous hash first, then compute hash
        receipt = receipt.model_copy(update={"previous_receipt_hash": prev_hash})
        receipt = receipt.model_copy(update={"receipt_hash": receipt.compute_hash()})
        self._receipts.append(receipt)
        path = self.ledger_dir / f"{receipt.receipt_id}.json"
        with open(path, "w") as f:
            json.dump(receipt.model_dump(), f, indent=2, default=str)
        return receipt

    def verify_chain(self) -> bool:
        """Verify receipt chain integrity."""
        for i, receipt in enumerate(self._receipts):
            expected_prev = self._receipts[i - 1].receipt_hash if i > 0 else ""
            if receipt.previous_receipt_hash != expected_prev:
                return False
            if receipt.receipt_hash != receipt.compute_hash():
                return False
        return True

    def lineage_for_extension(self, extension_id: str) -> List[ExtensionExecutionReceipt]:
        return [r for r in self._receipts if r.extension_id == extension_id]

    def load_all(self) -> None:
        self._receipts = []
        for path in sorted(self.ledger_dir.glob("*.json")):
            with open(path, "r") as f:
                data = json.load(f)
            self._receipts.append(ExtensionExecutionReceipt(**data))
        self._receipts.sort(key=lambda r: r.execution_timestamp)
