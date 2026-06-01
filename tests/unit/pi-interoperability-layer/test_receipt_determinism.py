"""Mesh execution receipt hashes must not depend on wall-clock telemetry.

Finding: ExecutionReceipt.compute_hash folded in resource_usage (cpu_ms, a
wall-clock float) and status_detail (which for TIMEOUT embeds the literal
"Elapsed {ms}ms > max ..." string). Because receipts are chained
(previous_receipt_hash) and verify_chain recomputes the hash, machine-speed
jitter changed the whole ledger chain — two identical logical runs diverged.
"""

from __future__ import annotations

from pi_interoperability_layer.mesh.receipts import ExecutionReceipt, OrchestrationLedger


def _receipt(cpu_ms: float, detail: str) -> ExecutionReceipt:
    return ExecutionReceipt(
        worker_class="W",
        worker_id="w1",
        phase="p1",
        input_slot_ids=["in"],
        output_slot_ids=["out"],
        status="SUCCESS",
        status_detail=detail,
        determinism_proof="dp",
        resource_usage={"cpu_ms": cpu_ms, "memory_mb": 0.0},
    )


def test_receipt_hash_ignores_wall_clock_resource_usage():
    fast = _receipt(12.3, "")
    slow = _receipt(987.6, "")
    assert fast.compute_hash() == slow.compute_hash()


def test_receipt_hash_ignores_wall_clock_status_detail():
    a = _receipt(10.0, "Elapsed 10.0ms > max 5.0ms")
    b = _receipt(10.0, "Elapsed 4000.0ms > max 5.0ms")
    assert a.compute_hash() == b.compute_hash()


def test_receipt_hash_still_reflects_logical_status():
    ok = _receipt(10.0, "")
    failed = ok.model_copy(update={"status": "FAIL"})
    assert ok.compute_hash() != failed.compute_hash()


def test_chain_is_reproducible_across_machine_speed():
    def build_chain(cpu_values):
        led = OrchestrationLedger()
        for cpu in cpu_values:
            led.append_receipt(_receipt(cpu, f"Elapsed {cpu}ms"))
        return [r.receipt_hash for r in led.receipts]

    assert build_chain([10.0, 11.0, 12.0]) == build_chain([900.0, 800.0, 700.0])
