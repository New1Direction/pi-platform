from typing import List, Tuple

from .models import LedgerEntry
from .validator import validator


class AntiHallucinationGate:
    """Zero-tolerance gates that prevent hallucination, unauthorized transitions,
    and provenance violations in the PI Agents Analysis Squad.

    All gates are fail-closed. Any violation halts the pipeline.
    """

    ALLOWED_ACTORS = {
        "network-grpc-specialist",
        "serialization-extractor",
        "binary-static-analyst",
        "client-codegen-specialist",
        "governance-gate",  # For final validation
    }

    def verify_actor(self, actor_id: str) -> Tuple[bool, str]:
        """Ensure only pre-registered, specialized actors can write to the ledger."""
        if actor_id not in self.ALLOWED_ACTORS:
            return False, f"Unauthorized actor: {actor_id}. Only registered specialists may write."
        return True, "Actor verified"

    def verify_evidence_hash(self, entry: LedgerEntry, expected_path: str = None) -> Tuple[bool, str]:
        """Verify that the evidence_hash actually corresponds to real artifacts.

        In production this would compute SHA-256 of the referenced files.
        Here we enforce format and non-emptiness as a minimum gate.
        """
        if len(entry.evidence_hash) != 64 or not all(c in "0123456789abcdef" for c in entry.evidence_hash):
            return False, "evidence_hash is not a valid 64-character lowercase hex SHA-256"

        if entry.evidence_hash == "0" * 64:
            return False, "evidence_hash cannot be zero (no real artifact was processed)"

        return True, "Evidence hash format valid"

    def verify_provenance(self, entry: LedgerEntry, ledger_entries: List[LedgerEntry]) -> Tuple[bool, str]:
        """Ensure this entry's provenance chain is consistent with the ledger history."""
        if not entry.provenance:
            return True, "No provenance required for initial entries"

        # Simple check: the previous task_id should appear in history
        if not ledger_entries:
            return True, "First entry has no prior provenance"

        last_task = ledger_entries[-1].task_id
        if entry.provenance and entry.provenance[-1] != last_task:
            return False, f"Provenance chain broken. Expected previous task {last_task}, got {entry.provenance[-1]}"

        return True, "Provenance chain valid"

    def run_all_gates(self, entry: LedgerEntry, ledger_entries: List[LedgerEntry]) -> Tuple[bool, List[str]]:
        """Run every anti-hallucination and governance gate in sequence.

        Returns (all_passed, list_of_failure_reasons)
        """
        failures = []

        # 1. Actor verification
        actor_ok, reason = self.verify_actor(entry.actor_id)
        if not actor_ok:
            failures.append(reason)

        # 2. Evidence hash validation
        hash_ok, reason = self.verify_evidence_hash(entry)
        if not hash_ok:
            failures.append(reason)

        # 3. State machine + entropy (already done by validator, but double-check)
        validation = validator.validate_transition(entry)
        if not validation.is_valid:
            failures.append(validation.reason)

        # 4. Provenance integrity
        prov_ok, reason = self.verify_provenance(entry, ledger_entries)
        if not prov_ok:
            failures.append(reason)

        return len(failures) == 0, failures


# Global gate instance used by orchestrator and pipeline
gate = AntiHallucinationGate()
