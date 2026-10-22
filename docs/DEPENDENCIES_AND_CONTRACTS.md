# Dependencies and Contracts — aether-ai-security

**Status:** Proposed; policy engine and runtime topology are not selected.

## Dependencies
Low-level policy/cryptographic utilities and optional low-level telemetry. Higher-level runtime components consume this repository's versioned contracts.

## Owned contracts
Policy request/decision, principal/action/resource/tenant context, obligations, safe reason codes, redaction helpers and security event schema.

## Contract rules
- Version public schemas and policy semantics.
- Fail closed on missing or invalid context for protected actions.
- Do not create identity/session or tenant-membership storage here.
- Callers must enforce decisions at every resource/action boundary.
- Define timeout, policy-unavailable behavior, redaction and correlation rules.
- Keep sensitive content out of ordinary logs and error messages.
