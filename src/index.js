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

const MAX_IDENTIFIER_LENGTH = 256;
const MAX_ACTION_LENGTH = 128;
const MAX_OBLIGATIONS = 32;
const MAX_OBLIGATION_LENGTH = 128;

function boundedString(value, maxLength = MAX_IDENTIFIER_LENGTH) {
  return typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maxLength;
}

function deny(reason, correlationId) {
  return Object.freeze({
    contractVersion: AUTHORIZATION_CONTRACT_VERSION,
    effect: "deny",
    reason,
    obligations: Object.freeze([]),
    ...(boundedString(correlationId) ? { correlationId } : {}),
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
 * Missing/malformed context, evaluator errors, unexpected output, and malformed
 * obligations all fail closed. This module does not authenticate the caller.
 *
 * @param {AuthorizationRequest} request
 * @param {(request: AuthorizationRequest) => {effect:string, obligations?:string[]}} policy
 */
export function evaluateAuthorization(request, policy) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return deny(REASON.INVALID_REQUEST);
  }

  const correlationId = request.correlationId;
  if (!boundedString(request.principalId)) {
    return deny(REASON.MISSING_PRINCIPAL, correlationId);
  }
  if (!boundedString(request.action, MAX_ACTION_LENGTH)) {
    return deny(REASON.MISSING_ACTION, correlationId);
  }
  if (
    !request.resource ||
    typeof request.resource !== "object" ||
    Array.isArray(request.resource) ||
    !boundedString(request.resource.type, MAX_ACTION_LENGTH) ||
    !boundedString(request.resource.id)
  ) {
    return deny(REASON.MISSING_RESOURCE, correlationId);
  }

  const scope = request.scope;
  if (
    !scope ||
    typeof scope !== "object" ||
    Array.isArray(scope) ||
    (!boundedString(scope.tenantId) && !boundedString(scope.workspaceId))
  ) {
    return deny(REASON.MISSING_SCOPE, correlationId);
  }
  if (typeof policy !== "function") {
    return deny(REASON.POLICY_ERROR, correlationId);
  }

  try {
    const trustedRequest = Object.freeze({
      ...request,
      scope: Object.freeze({ ...scope }),
      resource: Object.freeze({ ...request.resource }),
    });
    const decision = policy(trustedRequest);
    if (!decision || (decision.effect !== "allow" && decision.effect !== "deny")) {
      return deny(REASON.POLICY_ERROR, correlationId);
    }

    if (decision.effect !== "allow") {
      return Object.freeze({
        contractVersion: AUTHORIZATION_CONTRACT_VERSION,
        effect: "deny",
        reason: REASON.POLICY_DENIED,
        obligations: Object.freeze([]),
        ...(boundedString(correlationId) ? { correlationId } : {}),
      });
    }

    if (
      decision.obligations !== undefined &&
      (!Array.isArray(decision.obligations) ||
        decision.obligations.length > MAX_OBLIGATIONS ||
        !decision.obligations.every((item) => boundedString(item, MAX_OBLIGATION_LENGTH)))
    ) {
      return deny(REASON.POLICY_ERROR, correlationId);
    }

    const obligations = [...new Set(decision.obligations ?? [])];
    return Object.freeze({
      contractVersion: AUTHORIZATION_CONTRACT_VERSION,
      effect: "allow",
      reason: REASON.ALLOW,
      obligations: Object.freeze(obligations),
      ...(boundedString(correlationId) ? { correlationId } : {}),
    });
  } catch {
    return deny(REASON.POLICY_ERROR, correlationId);
  }
}

export const AuthorizationReason = REASON;
