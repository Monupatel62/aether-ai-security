# Policy Decision Contract and Enforcement Acceptance

**Status:** proposed contract for review. No policy engine, enforcement code, or passing security tests are claimed.

## Purpose and ownership

This repository defines a shared, versioned policy request/decision contract and reusable enforcement guidance. It does not own authentication, session lifecycle, canonical tenant membership, resource data, or final side-effect execution. The service that owns a resource must enforce authorization at that resource boundary. A shared decision is not a substitute for local enforcement.

ADR-0021 remains unresolved. Callers must obtain tenant and membership context from the eventually approved authoritative contract; this document does not select that owner.

## Request contract

A policy request should carry, where applicable:

- Contract/schema version.
- Authenticated principal identifier and principal type (human, service/workload, or delegated actor).
- Action identifier from a controlled vocabulary.
- Resource type and stable resource identifier.
- Tenant/workspace scope resolved from trusted server-side context.
- Requested operation context and relevant attributes, with explicit data classification.
- Correlation/request/run identifier and evaluation timestamp.
- Policy version or consistency token when supported by the chosen implementation.

Do not accept client-supplied role, membership, approval, or tenant claims as authoritative merely because they are present in the request. Validate required fields, normalize identifiers, reject unknown action/resource combinations, and avoid ambiguous fallback defaults.

## Decision contract

A policy decision should return:

- Contract version and a unique decision identifier.
- Allow or deny; indeterminate/error must remain distinguishable from deny in telemetry but MUST NOT be treated as allow.
- Stable, non-sensitive reason code.
- Obligations the caller must satisfy (for example, required approval, field filtering, or audit event), expressed as typed data rather than free-form instructions.
- Policy/version metadata and evaluation time.
- Expiry or consistency metadata only after semantics are defined by an accepted ADR.

Callers must reject malformed, unsupported, expired, or context-mismatched decisions. Unknown obligations or decision versions fail closed for protected actions. A caller must not silently discard obligations it cannot enforce.

## Enforcement and freshness

1. Authenticate the principal through Auth-owned contracts; authentication alone does not grant access.
2. Resolve resource and tenant scope using trusted server-side data and the approved ownership model.
3. Evaluate policy with a bounded deadline and validated context.
4. Enforce the decision and every obligation at the resource-owning boundary immediately before protected reads or side effects.
5. For queued, retried, or long-running work, re-check current authorization before side effects; an earlier allow decision is not a durable grant.
6. On policy dependency outage, malformed response, timeout, or unresolved context, deny protected operations. Any explicitly permitted degraded read-only mode requires a separately reviewed policy with narrow scope and evidence.
7. Emit sanitized audit events. Do not include secrets, raw credentials, or sensitive payloads in reason codes, logs, or client-facing errors.

A decision cache may only be introduced with an accepted consistency/revocation contract. This document sets no numeric TTL, propagation SLO, or stale-allow tolerance.

## Error taxonomy

Use stable machine-readable categories such as INVALID_CONTEXT, UNSUPPORTED_CONTRACT_VERSION, POLICY_DENIED, POLICY_UNAVAILABLE, POLICY_TIMEOUT, INVALID_DECISION, UNSATISFIED_OBLIGATION, and STALE_DECISION. Exact codes and public API mapping require contract review. Do not expose internal policy details that enable probing or leak protected attributes.

## Proposed acceptance matrix

These cases are required future evidence; they are not tests already run.

| Area | Acceptance case |
|---|---|
| Context | Missing, malformed, or unknown principal/action/resource context is rejected |
| Authority | Client-supplied role/tenant/approval cannot override authoritative state |
| Isolation | Cross-tenant and cross-resource requests are denied |
| Privilege | Lower-privilege principal cannot exercise admin or owner-only action |
| Decision parsing | Unknown version, malformed decision, and unknown obligation fail closed |
| Outage | Timeout, unavailable policy dependency, and invalid response never become allow |
| Freshness | Revoked membership/permission is rechecked before queued side effects |
| Obligations | Caller cannot silently ignore required approval, filtering, or audit obligations |
| Caching | Stale cached allow cannot override a required current-state check |
| Error safety | Client errors and logs do not reveal secrets or sensitive policy attributes |
| Audit | Denials and protected actions include correlation IDs and sanitized reason categories |
| Contract drift | Producer/consumer fixtures test supported request and decision schema versions |

## Contract governance

- Version schemas and semantics together; define compatibility and deprecation before publishing a stable package.
- Maintain valid, invalid, and boundary fixtures for every public contract version.
- Require consumer inventory and migration notes for breaking changes.
- Separate schema validation from semantic security testing; passing JSON Schema does not prove authorization correctness.
- Review policy changes with Security and affected resource-owning teams.
- Do not select a policy engine, runtime topology, quantitative SLO, or tenant-membership owner through this document.

## Related documents

- [Security architecture](ARCHITECTURE.md)
- [Dependencies and contracts](DEPENDENCIES_AND_CONTRACTS.md)
- [Security review checklist](SECURITY_REVIEW.md)
- [Platform tenant membership decision](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/TENANT_MEMBERSHIP_AND_ACL_CONSISTENCY_DECISION.md)
- [Auth revocation contract](https://github.com/Monupatel62/aether-ai-auth/blob/main/docs/SESSION_AND_TOKEN_REVOCATION_CONTRACT.md)
- [Cache revocation consistency](https://github.com/Monupatel62/aether-ai-cache/blob/main/docs/REVOCATION_CACHE_CONSISTENCY.md)
