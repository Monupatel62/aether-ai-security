export interface RedactionOptions {
  readonly maxDepth?: number;
  readonly maxNodes?: number;
  readonly maxStringChars?: number;
}

const SENSITIVE_KEY = /(?:authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key|client[_-]?secret|private[_-]?key|credential|access[_-]?key)/i;
const STRING_PATTERNS: readonly RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g
];

function redactString(input: string, maxChars: number): string {
  let value = input.length > maxChars ? input.slice(0, maxChars) + "[TRUNCATED]" : input;
  for (const pattern of STRING_PATTERNS) value = value.replace(pattern, "[REDACTED]");
  return value;
}

/**
 * Best-effort redaction for logs and test artifacts. This is not a DLP scanner and
 * must not be used as the sole control for handling secrets or regulated data.
 */
export function redactSensitiveData(value: unknown, options: RedactionOptions = {}): unknown {
  const maxDepth = options.maxDepth ?? 12;
  const maxNodes = options.maxNodes ?? 5_000;
  const maxStringChars = options.maxStringChars ?? 8_192;
  if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > 64) throw new RangeError("maxDepth must be between 1 and 64.");
  if (!Number.isInteger(maxNodes) || maxNodes < 1 || maxNodes > 100_000) throw new RangeError("maxNodes must be between 1 and 100000.");
  if (!Number.isInteger(maxStringChars) || maxStringChars < 1 || maxStringChars > 1_000_000) throw new RangeError("maxStringChars must be between 1 and 1000000.");

  const seen = new WeakSet<object>();
  let nodes = 0;

  const visit = (current: unknown, depth: number, key?: string): unknown => {
    if (key !== undefined && SENSITIVE_KEY.test(key)) return "[REDACTED]";
    nodes++;
    if (nodes > maxNodes || depth > maxDepth) return "[TRUNCATED]";
    if (typeof current === "string") return redactString(current, maxStringChars);
    if (current === null || typeof current === "number" || typeof current === "boolean") return current;
    if (current === undefined) return "[UNDEFINED]";
    if (typeof current === "bigint" || typeof current === "symbol" || typeof current === "function") return "[UNSERIALIZABLE]";
    if (typeof current !== "object") return "[UNSERIALIZABLE]";
    if (seen.has(current)) return "[CIRCULAR]";
    seen.add(current);

    if (Array.isArray(current)) return current.map(item => visit(item, depth + 1));
    const output: Record<string, unknown> = {};
    for (const [childKey, childValue] of Object.entries(current as Record<string, unknown>)) {
      output[childKey] = visit(childValue, depth + 1, childKey);
    }
    return output;
  };

  return visit(value, 0);
}

/** Redact sensitive HTTP header values before recording header metadata. */
export function redactHeaders(headers: Readonly<Record<string, string>>): Readonly<Record<string, string>> {
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    output[name] = SENSITIVE_KEY.test(name) ? "[REDACTED]" : redactString(value, 8_192);
  }
  return Object.freeze(output);
}
