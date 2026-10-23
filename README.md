# aether-ai-security

Shared policy definitions, prompt/tool guardrails, secret handling, redaction and threat-model requirements.

**Status:** Initial executable policy primitives are implemented on the feature branch. This is not a complete authentication service, security certification, or production-ready authorization system.

## Implemented policy core

- [Policy package README](./README.md)
- [Source implementation](./src/index.js)
- [Unit tests](./test/policy.test.js)
- Dependency-free Node.js package with tenant mismatch denial, explicit allow/deny rules, and deny-by-default behavior.

## Important limitations

The current code validates shapes and evaluates explicit rules only. It does not authenticate users, verify JWT signatures, resolve canonical tenant membership, load authoritative policies, persist audit events, or establish that caller-supplied values are trusted. These must be integrated and tested before production use.

## Documentation

- [Project specification](docs/PROJECT_SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Dependencies and contracts](docs/DEPENDENCIES_AND_CONTRACTS.md)
- [Implementation plan](docs/IMPLEMENTATION_PLAN.md)
- [Technical design](docs/TECHNICAL_DESIGN.md)
- [Security review](docs/SECURITY_REVIEW.md)
- [Research and licenses](docs/RESEARCH_AND_LICENSES.md)
- [Engineering standard](docs/ENGINEERING_STANDARD.md)
- [Work log](docs/WORKLOG.md)

[Master catalog](https://github.com/Monupatel62/aether-ai-platform/blob/main/docs/REPOSITORY_CATALOG.md)
