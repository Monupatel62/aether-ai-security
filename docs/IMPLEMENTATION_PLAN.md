# Implementation Plan — aether-ai-security

**Status:** Planning only.
1. Resolve policy library versus service and define owners through ADRs.
2. Define typed policy request/decision, obligation, reason-code and event schemas.
3. Agree principal, tenant and resource context semantics with Auth and domain owners.
4. Specify safe failure behavior for policy timeout, missing context and stale versions.
5. Implement only after approval with positive/negative policy fixtures.
6. Test privilege escalation, tenant mismatch, prompt injection, secret redaction and policy outage.
7. Add dependency/license and secret scanning plus operational response guidance.

No security certification or production protection is claimed by these documents.
