# Architecture — aether-ai-security

**Status:** Proposed; not implemented.

## Mission
Shared policy contracts, enforcement primitives, prompt/tool guardrails, secret handling, redaction and security event schema.

## Ownership
Security defines reusable policy and enforcement contracts. It does not own user identity, session state or canonical tenant membership. Each resource-owning service must enforce policy at its own boundary; a shared library or service does not replace local enforcement.

## Boundaries
Higher-level services consume versioned security contracts. Security must not import API, agents, UI or other consumers. Whether policy evaluation is a library or separately deployed service remains open.

## Decision flow
Validate principal/action/resource/tenant context; evaluate policy and required obligations; fail closed for protected actions when context is missing or invalid; return a versioned decision and safe reason code; require callers to enforce the result at the side-effect boundary.

## Open decisions
Policy engine, library-versus-service topology, reason-code taxonomy and quantitative decision latency targets require ADR review.
