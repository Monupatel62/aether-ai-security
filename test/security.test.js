import test from "node:test";
import assert from "node:assert/strict";
import { createAuthorizationService, evaluatePolicy, PolicyError } from "../src/index.js";

const principal = { id: "user-1", tenantId: "tenant-a" };
const resource = { type: "file", id: "file-1", tenantId: "tenant-a", ownerId: "user-1" };
const allow = { effect: "allow", actions: ["file:read"], subjectIds: ["user-1"], resourceTypes: ["file"], tenantId: "tenant-a" };

test("allows a matching subject/action/resource within the tenant", () => {
  assert.deepEqual(evaluatePolicy({ principal, action: "file:read", resource, policies: [allow], policyVersion: 3 }), { allowed: true, reason: "matched_allow", policyVersion: 3 });
});

test("defaults to deny and rejects cross-tenant access", () => {
  assert.equal(evaluatePolicy({ principal, action: "file:delete", resource, policies: [allow], policyVersion: 1 }).allowed, false);
  assert.equal(evaluatePolicy({ principal, action: "file:read", resource: { ...resource, tenantId: "tenant-b" }, policies: [allow], policyVersion: 1 }).reason, "tenant_mismatch");
});

test("explicit deny overrides a matching allow", () => {
  const deny = { ...allow, effect: "deny", resourceId: "file-1" };
  const result = evaluatePolicy({ principal, action: "file:read", resource, policies: [allow, deny], policyVersion: 4 });
  assert.equal(result.allowed, false);
  assert.equal(result.reason, "explicit_deny");
});

test("supports owner-only restrictions and wildcard policy selectors", () => {
  const policy = { effect: "allow", actions: ["*"], subjectIds: ["*"], resourceTypes: ["file"], tenantId: "tenant-a", ownerOnly: true };
  assert.equal(evaluatePolicy({ principal, action: "file:read", resource, policies: [policy], policyVersion: 1 }).allowed, true);
  assert.equal(evaluatePolicy({ principal: { ...principal, id: "user-2" }, action: "file:read", resource, policies: [policy], policyVersion: 1 }).allowed, false);
});

test("rejects malformed policy data and fails closed on loader errors", async () => {
  assert.throws(() => evaluatePolicy({ principal, action: "file:read", resource, policies: [{ effect: "maybe" }], policyVersion: 1 }), PolicyError);
  const auth = createAuthorizationService({ loadPolicySet: async () => { throw new Error("private database details"); } });
  await assert.rejects(auth.authorize({ principal, action: "file:read", resource }), (e) => e.code === "policy_unavailable" && !e.message.includes("private"));
});


test("rejects oversized or malformed policy selectors", () => {
  assert.throws(() => evaluatePolicy({ principal, action: "file:read", resource, policies: Array.from({ length: 1001 }, () => allow), policyVersion: 1 }), (e) => e.code === "invalid_policy_set");
  assert.throws(() => evaluatePolicy({ principal, action: "file:read", resource, policies: [{ ...allow, actions: ["bad action"] }], policyVersion: 1 }), (e) => e.code === "malformed_policy");
  assert.throws(() => evaluatePolicy({ principal, action: "file:read", resource, policies: [{ ...allow, ownerOnly: "yes" }], policyVersion: 1 }), (e) => e.code === "malformed_policy");
});
