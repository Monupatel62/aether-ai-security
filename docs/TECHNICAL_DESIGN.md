# Technical Design — aether-ai-security

**Status:** Proposed design, not implementation evidence.

## Purpose
Provide reusable security contracts and enforcement primitives across Aether AI.

## Request flow
Receive a typed policy request; validate schema and required context; resolve policy using the approved source; return decision, safe reason and obligations; require the caller to enforce at the resource boundary; emit sanitized security events with correlation IDs.

## Boundary rule
Authentication is not authorization. Client-supplied roles, tenant membership or approvals are not authoritative. The owning service must reauthorize protected reads and side effects as required by current state.

## Failure behavior
Protected actions fail closed if policy context cannot be verified. Define bounded timeout and recovery behavior without silently allowing access.

## Open decisions
Policy engine, version consistency, library/service boundary, caching and decision SLOs require reviewed ADRs.
