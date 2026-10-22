# Security Review — aether-ai-security

**Status:** Design checklist only; no audit or certification is claimed.

## Main risks
Policy bypass, stale decisions, privilege escalation, inconsistent tenant context, prompt injection, secret leakage and fail-open behavior during dependency outages.

## Required controls
- Version principal/action/resource/tenant context and decision semantics.
- Fail closed for protected operations when required context is absent or invalid.
- Keep canonical identity and membership authority in the assigned owning domain.
- Require callers to enforce policy at every resource/action boundary.
- Redact credentials and protected content from logs and error details.
- Document policy versioning, decision expiry and revocation behavior before implementation.

## Verification plan
- [ ] Deny missing/invalid context.
- [ ] Deny cross-tenant and privilege-escalation attempts.
- [ ] Test policy dependency outage and stale decision behavior.
- [ ] Test secret and sensitive-content redaction.
