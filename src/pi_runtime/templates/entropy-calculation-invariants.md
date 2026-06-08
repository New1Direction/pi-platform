# Entropy Calculation Invariants — PI Runtime v1.4.0

## Core Formula (Deterministic)
```
entropy = (
    unclassified_fields_count +
    (1 if weak_crypto_detected else 0) +
    (1 if missing_required_claim else 0) +
    (role_confusion_fields * 0.5)
)
```

## Monotonicity Rule
Every valid state transition after `EXTRACTING` MUST strictly decrease entropy.
Increase → immediate `ENTROPY_INCREASE` halt.

## JWT Domain Special Cases
- `alg=none` contributes +2 (critical)
- Missing `exp` contributes +1
- Presence of `admin`/`role` without policy contributes +1.5

## Implementation Contract
All entropy calculations must be pure functions with no side effects.
Results must be recorded in the immutable ledger before any downstream node executes.