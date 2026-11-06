import { describe, expect, test } from "bun:test";
import { shellJoin, shellQuote } from "../src/quote.ts";

describe("shellQuote", () => {
  test("quotes plain values", () => {
    expect(shellQuote("echo hi")).toBe("'echo hi'");
  });

  test("escapes embedded single quotes", () => {
    expect(shellQuote("it's")).toBe("'it'\\''s'");
  });

  test("keeps newlines and shell metacharacters literal", () => {
    expect(shellQuote("a\nb;$(x)")).toBe("'a\nb;$(x)'");
  });
});

describe("shellJoin", () => {
  test("quotes every token", () => {
    expect(shellJoin(["bwrap", "--", "bash", "-lc", "echo 'x'"])).toBe(
      "'bwrap' '--' 'bash' '-lc' 'echo '\\''x'\\'''"
    );
  });
});
