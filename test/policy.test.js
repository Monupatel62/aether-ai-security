import test from "node:test";
import assert from "node:assert/strict";
import {
  assertAuthorized,
  AuthorizationError,
  evaluatePolicy,
  validatePrincipal,
  validateResource,
} from "../src/index.js";

const principal = { id: "user-1", tenantId: "tenant-a" };
const resource = { type: "document", id: "doc-1", tenantId: "tenant-a", ownerId: "user-1" };
const allow = { effect: "allow", tenantId: "tenant-a", subjectId: "user-1", action: "document:read", resourceType: "document" };

test("allows an explicitly permitted same-tenant action", () => {
  assert.deepEqual(evaluatePolicy({ principal, action: "document:read", resource, rules: [allow] }), {
    allowed: true, reason: "explicit_allow", policyVersion: 1,
  });
});

test("denies when no matching allow rule exists", () => {
  const result = evaluatePolicy({ principal, action: "document:delete", resource, rules: [allow] });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "no_matching_allow");
});

test("denies cross-tenant access before applying rules", () => {
  const result = evaluatePolicy({
    principal,
    action: "document:read",
    resource: { ...resource, tenantId: "tenant-b" },
    rules: [{ ...allow, tenantId: "tenant-a" }],
  });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "tenant_mismatch");
});

test("explicit deny overrides a matching allow", () => {
  const deny = { ...allow, effect: "deny" };
  const result = evaluatePolicy({ principal, action: "document:read", resource, rules: [allow, deny] });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "explicit_deny");
});

test("denies rules that do not match the subject", () => {
  const result = evaluatePolicy({
    principal, action: "document:read", resource, rules: [{ ...allow, subjectId: "user-2" }],
  });
  assert.equal(result.allowed, false);
});

test("rejects malformed principals and resources", () => {
  assert.throws(() => validatePrincipal({ id: "", tenantId: "tenant-a" }), TypeError);
  assert.throws(() => validatePrincipal(null), TypeError);
  assert.throws(() => validateResource({ type: "doc", id: "1" }), TypeError);
});

test("throws a typed error for a denied operation", () => {
  assert.throws(
    () => assertAuthorized({ principal, action: "document:delete", resource, rules: [allow] }),
    (error) => error instanceof AuthorizationError && error.code === "no_matching_allow",
  );
});

test("fails closed on malformed policy data", () => {
  const result = evaluatePolicy({ principal, action: "document:read", resource, rules: [{ effect: "allow" }] });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "invalid_policy");
});
