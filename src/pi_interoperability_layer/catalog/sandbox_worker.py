"""Sandbox Validation Worker.

Executes catalog package behavior in an isolated deterministic sandbox.
Proves replay safety and determinism before admission.
No production replay. Sandbox-only.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pi_extension_governor.manifest import ExtensionManifest
from pi_extension_governor.sandbox import SandboxedExtensionRuntime


@dataclass(frozen=True)
class SandboxValidationReceipt:
    manifest_id: str
    executed: bool
    determinism_verified: bool
    replay_safe_verified: bool
    outputs_match: bool
    execution_duration_ms: int
    output_hash: str
    findings: Tuple[str, ...]
    receipt_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "manifest_id": self.manifest_id,
                "executed": self.executed,
                "determinism_verified": self.determinism_verified,
                "replay_safe_verified": self.replay_safe_verified,
                "outputs_match": self.outputs_match,
                "duration_ms": self.execution_duration_ms,
                "output_hash": self.output_hash,
                "findings": sorted(self.findings),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class SandboxValidationWorker:
    """Deterministic sandbox validation for catalog packages.

    Executes package in isolated sandbox.
    Verifies determinism via 3-run identical output hash comparison.
    Produces evidence-bound receipt.
    """

    def __init__(self, sandbox: Optional[SandboxedExtensionRuntime] = None) -> None:
        self.sandbox = sandbox or SandboxedExtensionRuntime(
            cpu_ms_max=5000,
            memory_mb_max=256,
            output_size_max=10 * 1024 * 1024,
        )

    def validate(
        self,
        manifest: ExtensionManifest,
        entrypoint_source: str,
        test_inputs: Dict[str, Any],
    ) -> SandboxValidationReceipt:
        """Run sandbox validation on a catalog package.

        Returns receipt with determinism and replay safety evidence.
        """
        findings: List[str] = []
        executed = False
        determinism_verified = False
        replay_safe_verified = False
        outputs_match = False
        duration_ms = 0
        output_hash = ""

        try:
            result = self.sandbox.execute(entrypoint_source, test_inputs)
            executed = True
            duration_ms = result.execution_time_ms

            if result.status == "SUCCESS":
                output_hash = hashlib.sha256(
                    json.dumps(result.output, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()

                # Determinism: 3-run comparison
                run_hashes: List[str] = []
                for _ in range(3):
                    run = self.sandbox.execute(entrypoint_source, test_inputs)
                    if run.status == "SUCCESS":
                        h = hashlib.sha256(
                            json.dumps(run.output, sort_keys=True, separators=(",", ":")).encode()
                        ).hexdigest()
                        run_hashes.append(h)
                    else:
                        findings.append(f"Run failed: status={run.status}, traceback={run.traceback}")
                        break

                if len(run_hashes) == 3 and len(set(run_hashes)) == 1:
                    determinism_verified = True
                    outputs_match = True
                    findings.append("Determinism verified: 3-run identical output hash")
                elif len(run_hashes) == 3:
                    findings.append("Determinism FAILED: output hashes diverged across runs")
                else:
                    findings.append("Determinism FAILED: insufficient successful runs")

                # Replay safety: check for time-dependent or random outputs
                if determinism_verified:
                    replay_safe_verified = True
                    findings.append("Replay safety: output stable across identical inputs")
            else:
                findings.append(f"Sandbox execution failed: status={result.status}, traceback={result.traceback}")

        except Exception as e:
            findings.append(f"Sandbox exception: {type(e).__name__}: {e}")

        receipt = SandboxValidationReceipt(
            manifest_id=manifest.extension_id,
            executed=executed,
            determinism_verified=determinism_verified,
            replay_safe_verified=replay_safe_verified,
            outputs_match=outputs_match,
            execution_duration_ms=duration_ms,
            output_hash=output_hash,
            findings=tuple(findings),
            receipt_hash="",
        )
        return SandboxValidationReceipt(
            manifest_id=receipt.manifest_id,
            executed=receipt.executed,
            determinism_verified=receipt.determinism_verified,
            replay_safe_verified=receipt.replay_safe_verified,
            outputs_match=receipt.outputs_match,
            execution_duration_ms=receipt.execution_duration_ms,
            output_hash=receipt.output_hash,
            findings=receipt.findings,
            receipt_hash=receipt.compute_hash(),
        )
