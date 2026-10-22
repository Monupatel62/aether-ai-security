# Engineering Standard — aether-ai-security

- Use typed, versioned policy contracts and stable safe reason codes.
- Fail closed for protected operations when required context is missing or invalid.
- Never treat caller-provided role, tenant or approval fields as authority.
- Keep identity/session and membership ownership in their assigned domains.
- Require policy enforcement at resource/action boundaries.
- Redact secrets and protected content from logs and error messages.
- Bound policy evaluation and define dependency-outage behavior.
- Test tenant isolation, privilege escalation, stale decisions and fail-closed behavior.
