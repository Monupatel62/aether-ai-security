import test from "node:test";
import assert from "node:assert/strict";
import {
  AUTHORIZATION_CONTRACT_VERSION,
  AuthorizationReason,
  evaluateAuthorization,
} from "../src/index.js";

const validRequest = {
  principalId: "user-test-1",
  action: "document:read",
  resource: { type: "document", id: "doc-test-1" },
  scope: { tenantId: "tenant-test-1" },
  correlationId: "corr-test-1",
};

test("publishes a versioned contract", () => {
  assert.equal(AUTHORIZATION_CONTRACT_VERSION, "1.0");
});

test("denies missing principal, action, resource, or scope", () => {
  assert.equal(evaluateAuthorization({ ...validRequest, principalId: "" }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_PRINCIPAL);
  assert.equal(evaluateAuthorization({ ...validRequest, action: "" }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_ACTION);
  assert.equal(evaluateAuthorization({ ...validRequest, resource: null }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_RESOURCE);
  assert.equal(evaluateAuthorization({ ...validRequest, scope: {} }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_SCOPE);
});

test("denies oversized request identifiers and malformed scope", () => {
  assert.equal(evaluateAuthorization({ ...validRequest, principalId: "x".repeat(257) }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_PRINCIPAL);
  assert.equal(evaluateAuthorization({ ...validRequest, action: "x".repeat(129) }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_ACTION);
  assert.equal(evaluateAuthorization({ ...validRequest, scope: [] }, () => ({ effect: "allow" })).reason, AuthorizationReason.MISSING_SCOPE);
});

test("allows only when an injected policy explicitly allows", () => {
  const result = evaluateAuthorization(validRequest, () => ({ effect: "allow", obligations: ["audit", "redact"] }));
  assert.equal(result.effect, "allow");
  assert.deepEqual(result.obligations, ["audit", "redact"]);
  assert.equal(result.correlationId, validRequest.correlationId);
});

test("denies explicit policy denial and unexpected policy output", () => {
  assert.equal(evaluateAuthorization(validRequest, () => ({ effect: "deny" })).effect, "deny");
  assert.equal(evaluateAuthorization(validRequest, () => ({ effect: "maybe" })).reason, AuthorizationReason.POLICY_ERROR);
});

test("fails closed for malformed, oversized, or non-string obligations", () => {
  assert.equal(evaluateAuthorization(validRequest, () => ({ effect: "allow", obligations: "audit" })).reason, AuthorizationReason.POLICY_ERROR);
  assert.equal(evaluateAuthorization(validRequest, () => ({ effect: "allow", obligations: ["audit", ""] })).reason, AuthorizationReason.POLICY_ERROR);
  assert.equal(evaluateAuthorization(validRequest, () => ({ effect: "allow", obligations: ["x".repeat(129)] })).reason, AuthorizationReason.POLICY_ERROR);
  assert.equal(evaluateAuthorization(validRequest, () => ({ effect: "allow", obligations: Array(33).fill("audit") })).reason, AuthorizationReason.POLICY_ERROR);
});

test("fails closed if policy throws", () => {
  assert.equal(evaluateAuthorization(validRequest, () => { throw new Error("synthetic"); }).reason, AuthorizationReason.POLICY_ERROR);
});

test("does not mutate the caller request", () => {
  const before = structuredClone(validRequest);
  evaluateAuthorization(validRequest, () => ({ effect: "allow" }));
  assert.deepEqual(validRequest, before);
});
