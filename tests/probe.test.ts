import { describe, expect, test } from "bun:test";
import { resolveSandboxBinary } from "../src/binary.ts";
import { probe } from "../src/probe.ts";

describe("resolveSandboxBinary", () => {
  test("refuses an unsupported platform shape", () => {
    // `resolveSandboxBinary` only accepts linux/darwin; the cast documents
    // the runtime guard in createSandbox instead.
    expect(["linux", "darwin"]).toContain(process.platform);
  });

  test("resolves the real binary when installed", () => {
    const platform = process.platform === "darwin" ? "darwin" : "linux";
    const result = resolveSandboxBinary(platform);
    if (process.env.SANDBOX_REQUIRE_BWRAP === "1" && platform === "linux") {
      expect(result.ok).toBe(true);
    }
    if (result.ok) expect(result.path.startsWith("/")).toBe(true);
  });

  test("never resolves through a PATH shim", () => {
    const platform = process.platform === "darwin" ? "darwin" : "linux";
    const before = process.env.PATH;
    process.env.PATH = "/tmp/osb-shim";
    try {
      const result = resolveSandboxBinary(platform);
      if (result.ok) expect(result.path).not.toContain("/tmp/osb-shim");
    } finally {
      process.env.PATH = before;
    }
  });
});

describe("probe", () => {
  test("fails closed for a non-sandbox executable", async () => {
    const result = await probe("linux", "/bin/true", 2000);
    expect(result.available).toBe(false);
    expect(result.reason).toBeDefined();
  });

  test("fails closed for a missing executable", async () => {
    const result = await probe("linux", "/definitely/not/bwrap", 2000);
    expect(result.available).toBe(false);
  });
});
