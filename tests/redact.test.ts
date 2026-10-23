import { describe, expect, it } from "vitest";
import { redactHeaders, redactSensitiveData } from "../src/index.js";

describe("best-effort redaction", () => {
  it("redacts sensitive object keys recursively", () => {
    expect(redactSensitiveData({
      user: "synthetic-user",
      authorization: "Bearer synthetic-secret",
      nested: { client_secret: "fake", safe: "value" }
    })).toEqual({
      user: "synthetic-user",
      authorization: "[REDACTED]",
      nested: { client_secret: "[REDACTED]", safe: "value" }
    });
  });

  it("redacts common token patterns in free text", () => {
    const result = redactSensitiveData("auth=Bearer abc.def.ghi token=sk-12345678901234567890 ghp_123456789012345678901234");
    expect(result).not.toContain("abc.def.ghi");
    expect(result).not.toContain("sk-12345678901234567890");
    expect(result).not.toContain("ghp_123456789012345678901234");
    expect(result).toContain("[REDACTED]");
  });

  it("redacts sensitive headers and preserves safe header values", () => {
    expect(redactHeaders({ Authorization: "Bearer synthetic", "Content-Type": "application/json", Cookie: "session=synthetic" }))
      .toEqual({ Authorization: "[REDACTED]", "Content-Type": "application/json", Cookie: "[REDACTED]" });
  });

  it("bounds recursion, node count, and string length", () => {
    expect(redactSensitiveData({ a: { b: { c: "value" } } }, { maxDepth: 1 })).toEqual({ a: { b: "[TRUNCATED]" } });
    expect(redactSensitiveData({ a: "x", b: "y" }, { maxNodes: 2 })).toEqual({ a: "x", b: "[TRUNCATED]" });
    expect(redactSensitiveData("abcdef", { maxStringChars: 3 })).toBe("abc[TRUNCATED]");
  });

  it("handles circular objects without throwing", () => {
    const value: { safe: string; self?: unknown } = { safe: "synthetic" };
    value.self = value;
    expect(redactSensitiveData(value)).toEqual({ safe: "synthetic", self: "[CIRCULAR]" });
  });
});
