/**
 * Minimal, dependency-free authorization primitives.
 *
 * SECURITY BOUNDARY:
 * These functions do not authenticate tokens, verify signatures, establish the
 * trustworthiness of a principal, or fetch canonical tenant membership. Callers
 * must pass a principal created by a separately trusted authentication boundary.
 * Missing/invalid context and missing policy rules are denied by default.
 */

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const EFFECTS = new Set(["allow", "deny"]);

export class AuthorizationError extends Error {
  constructor(code, message = "Access denied") {
    super(message);
    this.name = "AuthorizationError";
    this.code = code;
  }
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireIdentifier(value, field) {
  if (typeof value !== "string" || !IDENTIFIER.test(value) || value.trim() !== value) {
    throw new TypeError(`Invalid ${field}`);
  }
  return value;
}

/**
 * Validate the minimum principal shape required by policy evaluation.
 * This is structural validation only, not proof of identity.
 */
export function validatePrincipal(value) {
  if (!isRecord(value)) throw new TypeError("Principal must be an object");
  return Object.freeze({
    id: requireIdentifier(value.id, "principal.id"),
    tenantId: requireIdentifier(value.tenantId, "principal.tenantId"),
  });
}

/** Validate a resource authorization target. */
export function validateResource(value) {
  if (!isRecord(value)) throw new TypeError("Resource must be an object");
  const resource = {
    type: requireIdentifier(value.type, "resource.type"),
    id: requireIdentifier(value.id, "resource.id"),
    tenantId: requireIdentifier(value.tenantId, "resource.tenantId"),
  };
  if (value.ownerId !== undefined && value.ownerId !== null) {
    resource.ownerId = requireIdentifier(value.ownerId, "resource.ownerId");
  }
  return Object.freeze(resource);
}

/**
 * Validate a deliberately explicit policy rule.
 * Wildcards and implicit role inheritance are not supported in this baseline.
 */
export function validatePolicyRule(value) {
  if (!isRecord(value)) throw new TypeError("Policy rule must be an object");
  if (!EFFECTS.has(value.effect)) throw new TypeError("Invalid policy rule effect");
  const rule = {
    effect: value.effect,
    tenantId: requireIdentifier(value.tenantId, "rule.tenantId"),
    action: requireIdentifier(value.action, "rule.action"),
    resourceType: requireIdentifier(value.resourceType, "rule.resourceType"),
  };
  if (value.subjectId !== undefined && value.subjectId !== null) {
    rule.subjectId = requireIdentifier(value.subjectId, "rule.subjectId");
  }
  if (value.resourceId !== undefined && value.resourceId !== null) {
    rule.resourceId = requireIdentifier(value.resourceId, "rule.resourceId");
  }
  return Object.freeze(rule);
}

function ruleMatches(rule, principal, action, resource) {
  return rule.tenantId === principal.tenantId
    && rule.action === action
    && rule.resourceType === resource.type
    && (rule.subjectId === undefined || rule.subjectId === principal.id)
    && (rule.resourceId === undefined || rule.resourceId === resource.id);
}

/**
 * Evaluate an explicit policy. Deny rules override allow rules.
 * Tenant mismatch and absence of a matching allow rule both deny.
 */
export function evaluatePolicy({ principal: principalInput, action: actionInput, resource: resourceInput, rules: rulesInput }) {
  const principal = validatePrincipal(principalInput);
  const resource = validateResource(resourceInput);
  const action = requireIdentifier(actionInput, "action");

  if (!Array.isArray(rulesInput)) {
    return Object.freeze({ allowed: false, reason: "invalid_policy", policyVersion: 1 });
  }

  let rules;
  try {
    rules = rulesInput.map(validatePolicyRule);
  } catch {
    return Object.freeze({ allowed: false, reason: "invalid_policy", policyVersion: 1 });
  }

  if (principal.tenantId !== resource.tenantId) {
    return Object.freeze({ allowed: false, reason: "tenant_mismatch", policyVersion: 1 });
  }

  const matching = rules.filter((rule) => ruleMatches(rule, principal, action, resource));
  if (matching.some((rule) => rule.effect === "deny")) {
    return Object.freeze({ allowed: false, reason: "explicit_deny", policyVersion: 1 });
  }
  if (!matching.some((rule) => rule.effect === "allow")) {
    return Object.freeze({ allowed: false, reason: "no_matching_allow", policyVersion: 1 });
  }

  return Object.freeze({ allowed: true, reason: "explicit_allow", policyVersion: 1 });
}

/** Throw when policy evaluation denies an operation. */
export function assertAuthorized(input) {
  const decision = evaluatePolicy(input);
  if (!decision.allowed) {
    throw new AuthorizationError(decision.reason);
  }
  return decision;
}
