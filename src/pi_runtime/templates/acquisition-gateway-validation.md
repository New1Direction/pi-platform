# Acquisition Gateway Validation Criteria (JWT/Auth Domain)

## Structural Invariants
- Every inbound packet MUST produce both `packet_hash` and `canonical_hash`
- Header keys MUST be lowercased and sorted before hashing
- Authorization prefixes (Bearer, Basic) MUST be stripped before JWT classification
- Body must be decompressed (gzip/deflate) before any semantic pass

## JWT-Specific Gates
- `alg` claim present and != "none"
- `exp` claim present and not expired
- `aud` claim present when cross-service tokens are expected
- No privilege escalation fields (`admin`, `is_admin`, `role`) without explicit allow-list

## Entropy Calculation
Entropy score = count of unclassified fields + (1 if alg=none else 0) + (1 if missing_exp else 0)
Threshold: > 3 → HALT with `ENTROPY_INCREASE`

## Fail-Closed Rules
Any violation of the above immediately returns status `INVALID_EVIDENCE` with full provenance.