/**
 * Versioned authorization contract.
 *
 * This module does not authenticate identities or establish tenant/workspace
 * membership. Callers must provide trusted context and a policy evaluator that
 * uses authoritative domain-owned grants. Missing or malformed context denies.
 */

export const AUTHORIZATION_CONTRACT_VERSION = "1.0";

const REASON = Object.freeze({
  ALLOW: "ALLOW",
  INVALID_REQUEST: "INVALID_REQUEST",
  MISSING_PRINCIPAL: "MISSING_PRINCIPAL",
  MISSING_ACTION: "MISSING_ACTION",
  MISSING_RESOURCE: "MISSING_RESOURCE",
  MISSING_SCOPE: "MISSING_SCOPE",
  POLICY_DENIED: "POLICY_DENIED",
  POLICY_ERROR: "POLICY_ERROR",
});

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function deny(reason, correlationId) {
  return Object.freeze({
    contractVersion: AUTHORIZATION_CONTRACT_VERSION,
    effect: "deny",
    reason,
    obligations: [],
    ...(nonEmptyString(correlationId) ? { correlationId } : {}),
  });
}

/**
 * @typedef {Object} AuthorizationRequest
 * @property {string} principalId Authenticated principal identifier.
 * @property {string} action Stable action name, e.g. "document:read".
 * @property {{type:string,id:string}} resource Resource identity.
 * @property {{tenantId?:string,workspaceId?:string}} scope Trusted scope context.
 * @property {string} [correlationId] Non-sensitive trace identifier.
 */

/**
 * Evaluate a request using an injected authoritative policy function.
 * The policy function must return { effect: "allow"|"deny", obligations?: string[] }.
 * Errors and all unexpected results fail closed.
 *
 * @param {AuthorizationRequest} request
 * @param {(request: AuthorizationRequest) => {effect:string, obligations?:string[]}} policy
 */
export function evaluateAuthorization(request, policy) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return deny(REASON.INVALID_REQUEST);
  }

  const correlationId = request.correlationId;
  if (!nonEmptyString(request.principalId)) {
    return deny(REASON.MISSING_PRINCIPAL, correlationId);
  }
  if (!nonEmptyString(request.action)) {
    return deny(REASON.MISSING_ACTION, correlationId);
  }
  if (
    !request.resource ||
    !nonEmptyString(request.resource.type) ||
    !nonEmptyString(request.resource.id)
  ) {
    return deny(REASON.MISSING_RESOURCE, correlationId);
  }
  const scope = request.scope;
  if (
    !scope ||
    typeof scope !== "object" ||
    (!nonEmptyString(scope.tenantId) && !nonEmptyString(scope.workspaceId))
  ) {
    return deny(REASON.MISSING_SCOPE, correlationId);
  }
  if (typeof policy !== "function") {
    return deny(REASON.POLICY_ERROR, correlationId);
  }

  try {
    const decision = policy(Object.freeze({ ...request, scope: Object.freeze({ ...scope }), resource: Object.freeze({ ...request.resource }) }));
    if (!decision || (decision.effect !== "allow" && decision.effect !== "deny")) {
      return deny(REASON.POLICY_ERROR, correlationId);
    }
    const obligations = Array.isArray(decision.obligations) &&
      decision.obligations.every(nonEmptyString)
      ? [...new Set(decision.obligations)]
      : [];
    if (decision.effect !== "allow") {
      return Object.freeze({
        contractVersion: AUTHORIZATION_CONTRACT_VERSION,
        effect: "deny",
        reason: REASON.POLICY_DENIED,
        obligations: [],
        ...(nonEmptyString(correlationId) ? { correlationId } : {}),
      });
    }
    return Object.freeze({
      contractVersion: AUTHORIZATION_CONTRACT_VERSION,
      effect: "allow",
      reason: REASON.ALLOW,
      obligations: Object.freeze(obligations),
      ...(nonEmptyString(correlationId) ? { correlationId } : {}),
    });
  } catch {
    return deny(REASON.POLICY_ERROR, correlationId);
  }
}

export const AuthorizationReason = REASON;
