const ID = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const EFFECTS = new Set(["allow", "deny"]);
export class PolicyError extends Error {
  constructor(code, message = "Authorization policy could not be evaluated") { super(message); this.name = "PolicyError"; this.code = code; }
}
function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function validId(value) { return typeof value === "string" && ID.test(value) && value.trim() === value; }

/**
 * Minimal deterministic policy evaluator. Any explicit deny overrides allows;
 * no matching allow means deny. Policy retrieval/signature verification and
 * identity/token verification remain responsibilities of trusted callers.
 */
export function evaluatePolicy({ principal, action, resource, policies, policyVersion } = {}) {
  if (!isRecord(principal) || !validId(principal.id) || !validId(principal.tenantId)) throw new PolicyError("invalid_principal");
  if (!validId(action) || !isRecord(resource) || !validId(resource.type) || !validId(resource.tenantId)) throw new PolicyError("invalid_request");
  if (!Array.isArray(policies) || policies.length > 1000 || !Number.isSafeInteger(policyVersion) || policyVersion < 1) throw new PolicyError("invalid_policy_set");
  if (resource.tenantId !== principal.tenantId) return Object.freeze({ allowed: false, reason: "tenant_mismatch", policyVersion });

  const matching = [];
  for (const policy of policies) {
    if (!isRecord(policy) || !EFFECTS.has(policy.effect) || !Array.isArray(policy.actions) || !Array.isArray(policy.subjectIds) || !Array.isArray(policy.resourceTypes)) {
      throw new PolicyError("malformed_policy");
    }
    if (policy.actions.length > 256 || policy.subjectIds.length > 256 || policy.resourceTypes.length > 256
      || policy.actions.some((v) => v !== "*" && !validId(v))
      || policy.subjectIds.some((v) => v !== "*" && !validId(v))
      || policy.resourceTypes.some((v) => v !== "*" && !validId(v))
      || (policy.tenantId !== "*" && !validId(policy.tenantId))
      || (policy.resourceId !== undefined && !validId(policy.resourceId))
      || (policy.ownerOnly !== undefined && typeof policy.ownerOnly !== "boolean")) {
      throw new PolicyError("malformed_policy");
    }
    if (!policy.actions.includes(action) && !policy.actions.includes("*")) continue;
    if (!policy.subjectIds.includes(principal.id) && !policy.subjectIds.includes("*")) continue;
    if (!policy.resourceTypes.includes(resource.type) && !policy.resourceTypes.includes("*")) continue;
    if (policy.tenantId !== "*" && policy.tenantId !== principal.tenantId) continue;
    if (policy.resourceId !== undefined && policy.resourceId !== resource.id) continue;
    if (policy.ownerOnly === true && resource.ownerId !== principal.id) continue;
    matching.push(policy);
  }
  if (matching.some((p) => p.effect === "deny")) return Object.freeze({ allowed: false, reason: "explicit_deny", policyVersion });
  if (matching.some((p) => p.effect === "allow")) return Object.freeze({ allowed: true, reason: "matched_allow", policyVersion });
  return Object.freeze({ allowed: false, reason: "no_matching_allow", policyVersion });
}

export function createAuthorizationService({ loadPolicySet, clock = () => Date.now() }) {
  if (typeof loadPolicySet !== "function" || typeof clock !== "function") throw new TypeError("Policy loader and clock are required");
  return Object.freeze({
    async authorize(request) {
      let policySet;
      try { policySet = await loadPolicySet({ tenantId: request?.principal?.tenantId, at: clock() }); }
      catch { throw new PolicyError("policy_unavailable"); }
      if (!isRecord(policySet)) throw new PolicyError("policy_unavailable");
      return evaluatePolicy({ ...request, policies: policySet.policies, policyVersion: policySet.version });
    },
  });
}
