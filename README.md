# aether-ai-security

**Status:** Initial deterministic policy evaluator implemented on a feature branch. This is not a complete identity, policy-management, or enforcement platform.

## Implemented

- [Policy evaluator](src/index.js): tenant boundary check, explicit deny precedence, default-deny behavior, subject/action/resource matching, owner-only policy, versioned results, and fail-closed policy loading.
- [Unit tests](test/security.test.js): allow/deny decisions, tenant mismatch, wildcard selectors, owner restrictions, malformed policies, and policy-store failures.
- Dependency-free Node.js package with Node 20/22 CI.

## Security limitations

The caller must provide a trusted principal; this module does not validate JWTs, sessions, memberships, policy signatures, or policy administration. It does not enforce authorization inside database queries or side-effecting adapters. Policies are plain data and must come from a trusted, versioned source. Resource-level checks and support-access controls require explicit policy design and integration.

## Documentation

- [Repository specification](docs/REPOSITORY_SPECIFICATION.md)
- [Project specification](docs/PROJECT_SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Dependencies and contracts](docs/DEPENDENCIES_AND_CONTRACTS.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Security review](docs/SECURITY_REVIEW.md)
- [Master catalog](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/REPOSITORY_CATALOG.md)
