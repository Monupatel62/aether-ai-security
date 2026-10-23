# @aether-ai/security

Best-effort sensitive-field redaction utilities for Aether AI. These utilities are not a complete DLP scanner or a substitute for security policy enforcement.

## Current implementation

- Recursive key-based redaction for credential-like field names.
- Best-effort redaction of common bearer/API-token patterns in strings.
- HTTP header value redaction.
- Bounds for recursion depth, node count, and string length; circular/unserializable values are marked safely.
- Synthetic tests and Node.js 22 CI with a high/critical dependency audit gate.

## Important limitations

- Pattern-based redaction can miss secrets and can produce false positives. Do not use it as the only control for sensitive or regulated data.
- This package does not implement authentication, authorization, policy evaluation, tenant membership, or tool approvals.
- Protected actions must fail closed when required trusted context is absent, and each owning service must enforce policy at its resource boundary.
- Policy engine/library-vs-service, version consistency, caching, and decision SLOs remain open decisions.

## Example

```ts
import { redactSensitiveData } from "@aether-ai/security";

const safe = redactSensitiveData({
  operation: "model.call",
  authorization: "Bearer synthetic-token",
  result: { status: "success" }
});
```

## Development

```bash
npm install
npm audit --audit-level=high
npm run typecheck
npm test
npm run build
```
