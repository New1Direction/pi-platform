# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |

## Reporting a Vulnerability

Email security concerns directly — do not open public issues for undisclosed vulnerabilities.

**Critical checks:**
- Does the issue allow bypassing the `ExplicitCompositionRequest` boundary?
- Does it introduce non-determinism into the execution kernel?
- Does it permit cross-tenant data leakage?

## Security Philosophy

PI Platform is designed with security-in-depth:

1. **Fail-closed by default** — all policy evaluations default to DENY
2. **Zero trust within extensions** — sandboxed execution with bounded resources
3. **Immutable audit trail** — every action is receipted and chained
4. **Tenant isolation** — no cross-tenant access without explicit capability edges
5. **Deterministic execution** — replay-safe, side-effect-free core

## Security Checklist for Contributors

- [ ] No new network access in core runtimes
- [ ] No file-system writes outside designated paths
- [ ] No subprocess spawning in worker implementations
- [ ] All new artifacts use `frozen=True` Pydantic models
- [ ] All hashes use canonical JSON + SHA-256
- [ ] Tenant scoping applied to every new endpoint
