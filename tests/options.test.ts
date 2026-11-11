import { describe, expect, test } from "bun:test";
import path from "node:path";
import { expandPath, parseOptions, parseOptionsSafe } from "../src/options.ts";

describe("parseOptions", () => {
  test("secure defaults", () => {
    const options = parseOptions({}, "/tmp/project");
    expect(options.network).toBe("deny");
    expect(options.mode).toBe("enforce");
    expect(options.writablePaths).toEqual([]);
    expect(options.readablePaths).toEqual([]);
    expect(options.passEnv).toEqual([]);
    expect(options.toolGuard).toBe("enforce");
    expect(options.webfetch).toBe("allow");
    expect(options.webfetchAllowlist).toEqual([]);
    expect(path.isAbsolute(options.shell)).toBe(true);
  });

  test("accepts explicit values", () => {
    const options = parseOptions(
      {
        network: "allow",
        mode: "permissive",
        writablePaths: ["/tmp/a"],
        readablePaths: ["/tmp/b"],
        passEnv: ["TOKEN"],
        shell: "/bin/sh",
        toolGuard: "enforce",
        webfetch: "deny",
        webfetchAllowlist: ["Example.COM", "*.example.com", ".api.example.com"],
      },
      "/tmp/project"
    );
    expect(options.network).toBe("allow");
    expect(options.mode).toBe("permissive");
    expect(options.writablePaths).toEqual(["/tmp/a"]);
    expect(options.readablePaths).toEqual(["/tmp/b"]);
    expect(options.passEnv).toEqual(["TOKEN"]);
    expect(options.shell).toBe("/bin/sh");
    expect(options.toolGuard).toBe("enforce");
    expect(options.webfetch).toBe("deny");
    expect(options.webfetchAllowlist).toEqual([
      "example.com",
      "*.example.com",
      "*.api.example.com",
    ]);
  });

  test("accepts toolGuard off when no webfetch policy is configured", () => {
    const options = parseOptions({ toolGuard: "off" }, "/tmp/project");
    expect(options.toolGuard).toBe("off");
    expect(options.webfetch).toBe("allow");
    expect(options.webfetchAllowlist).toEqual([]);
  });

  test("rejects a webfetch policy when the tool guard is off", () => {
    expect(() => parseOptions({ toolGuard: "off", webfetch: "deny" }, "/tmp/project")).toThrow(
      /toolGuard/
    );
    expect(() =>
      parseOptions({ toolGuard: "off", webfetchAllowlist: ["example.com"] }, "/tmp/project")
    ).toThrow(/toolGuard/);
  });

  test("falls back on malformed values and reports them", () => {
    const parsed = parseOptionsSafe(
      {
        network: "yes",
        mode: "off",
        writablePaths: "nope",
        readablePaths: [1],
        passEnv: [1],
        shell: "bash",
      },
      "/tmp/project"
    );
    expect(parsed.errors.length).toBe(6);
    expect(parsed.options.network).toBe("deny");
    expect(parsed.options.mode).toBe("enforce");
    expect(parsed.options.writablePaths).toEqual([]);
    expect(parsed.options.readablePaths).toEqual([]);
    expect(parsed.options.passEnv).toEqual([]);
    expect(parsed.options.toolGuard).toBe("enforce");
    expect(parsed.options.webfetch).toBe("allow");
    expect(path.isAbsolute(parsed.options.shell)).toBe(true);
  });

  test("fails closed on malformed security values", () => {
    const parsed = parseOptionsSafe(
      { toolGuard: "nope", webfetch: "nope", webfetchAllowlist: "example.com" },
      "/tmp/project"
    );
    expect(parsed.errors.length).toBeGreaterThan(0);
    expect(parsed.options.toolGuard).toBe("enforce");
    expect(parsed.options.webfetch).toBe("deny");
    expect(parsed.options.webfetchAllowlist).toEqual([]);
  });

  test("fails closed when a webfetch policy is combined with toolGuard off", () => {
    const parsed = parseOptionsSafe(
      { toolGuard: "off", webfetchAllowlist: ["example.com"] },
      "/tmp/project"
    );
    expect(parsed.errors.length).toBe(1);
    expect(parsed.options.toolGuard).toBe("enforce");
    expect(parsed.options.webfetch).toBe("allow");
    expect(parsed.options.webfetchAllowlist).toEqual(["example.com"]);
  });

  test("rejects malformed security values in strict mode", () => {
    expect(() => parseOptions({ toolGuard: "nope" }, "/tmp/project")).toThrow(/toolGuard/);
    expect(() => parseOptions({ webfetch: "nope" }, "/tmp/project")).toThrow(/webfetch/);
    expect(() => parseOptions({ webfetchAllowlist: "example.com" }, "/tmp/project")).toThrow(
      /array of hostnames/
    );
  });

  test("rejects a malformed webfetch allowlist entry", () => {
    expect(() =>
      parseOptions({ webfetchAllowlist: ["https://example.com"] }, "/tmp/project")
    ).toThrow(/not a hostname/);
    expect(() => parseOptions({ webfetchAllowlist: ["bad host"] }, "/tmp/project")).toThrow(
      /not a hostname/
    );
  });

  test("refuses the filesystem root as a mount", () => {
    const options = parseOptions({ writablePaths: ["/"], readablePaths: ["/"] }, "/tmp/project");
    expect(options.writablePaths).toEqual([]);
    expect(options.readablePaths).toEqual([]);
  });

  test("expands and normalizes paths", () => {
    expect(expandPath("./a", "/tmp/project")).toBe("/tmp/project/a");
    expect(expandPath("/a/../b", "/tmp/project")).toBe("/b");
    expect(expandPath("~/x", "/tmp/project")).toBe(path.join(process.env.HOME ?? "", "x"));
  });

  test("requires an absolute shell", () => {
    const parsed = parseOptionsSafe({ shell: "bash" }, "/tmp/project");
    expect(parsed.errors).toEqual(["shell must be an absolute path"]);
    expect(path.isAbsolute(parsed.options.shell)).toBe(true);
  });

  test("drops invalid environment names", () => {
    const options = parseOptions({ passEnv: ["GOOD", "bad-name", "1BAD", "A=B"] }, "/tmp/project");
    expect(options.passEnv).toEqual(["GOOD"]);
  });
});
