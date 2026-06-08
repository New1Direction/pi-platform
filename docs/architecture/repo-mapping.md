# Repository-to-Specification Mapping

This document shows how the `pi-platform` repository maps to the formal [PI Runtime Specification v1.4](../PI-RUNTIME-SPEC-v1.4.md).

## Directory → Layer Mapping

| Directory | Layer | Spec Sections |
|-----------|-------|--------------|
| `src/pi_interoperability_layer/platform/tenant.py` | Layer 1 | 10 (Shard Sync), 11 (Receipts) |
| `src/pi_interoperability_layer/mesh/` | Layer 2 | 5 (Graph Exec), 6 (Phases), 8 (Scheduling), 10 (Shard Sync), 11 (Receipts) |
| `src/pi_interoperability_layer/execution.py` | Layer 2 | 7 (Replay), 11 (Receipts) |
| `src/pi_interoperability_layer/contracts.py` | Layer 2–3 | 4 (Artifacts), 7 (Replay) |
| `src/pi_extension_governor/` | Layer 3 | 9 (Policy), 12 (Trust Zones) |
| `src/pi_console/` | Layer 4 | Boundary enforcement, API reference |
| `pi-console-frontend/` | Layer 4 | UI components, visual builder |
| `tests/conformance/` | Spec verification | 14 (Conformance) |

## Key Files by Spec Section

- **Artifacts (§4)**: `src/pi_interoperability_layer/contracts.py`
- **Graph Execution (§5)**: `src/pi_interoperability_layer/mesh/kernel.py`
- **Phase Transitions (§6)**: `src/pi_interoperability_layer/mesh/kernel.py`
- **Replay (§7)**: `src/pi_interoperability_layer/execution.py`, `src/pi_interoperability_layer/mesh/receipts.py`
- **Scheduling (§8)**: `src/pi_interoperability_layer/mesh/shard.py`
- **Policy (§9)**: `src/pi_extension_governor/policy.py`
- **Shard Sync (§10)**: `src/pi_interoperability_layer/mesh/shard.py`
- **Receipts (§11)**: `src/pi_interoperability_layer/mesh/receipts.py`
- **Trust Zones (§12)**: `src/pi_extension_governor/trust_zones.py`

## Conformance Test Mapping

Each `CTEST-*` in Section 14 of the spec has a corresponding test class in:

```
tests/conformance/test_conformance.py
```

Run with:
```bash
make test-conformance
```
