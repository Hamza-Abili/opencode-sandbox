import { describe, expect, test } from "bun:test";
import path from "node:path";
import { expandPath, parseOptions } from "../src/options.ts";

describe("parseOptions", () => {
  test("secure defaults", () => {
    const options = parseOptions({}, "/tmp/project");
    expect(options.network).toBe("deny");
    expect(options.mode).toBe("enforce");
    expect(options.writablePaths).toEqual([]);
    expect(options.readablePaths).toEqual([]);
    expect(options.passEnv).toEqual([]);
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
      },
      "/tmp/project"
    );
    expect(options.network).toBe("allow");
    expect(options.mode).toBe("permissive");
    expect(options.writablePaths).toEqual(["/tmp/a"]);
    expect(options.readablePaths).toEqual(["/tmp/b"]);
    expect(options.passEnv).toEqual(["TOKEN"]);
    expect(options.shell).toBe("/bin/sh");
  });

  test("falls back on malformed values", () => {
    const options = parseOptions(
      { network: "yes", mode: "off", writablePaths: "nope", passEnv: [1] },
      "/tmp/project"
    );
    expect(options.network).toBe("deny");
    expect(options.mode).toBe("enforce");
    expect(options.writablePaths).toEqual([]);
    expect(options.passEnv).toEqual([]);
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
    const options = parseOptions({ shell: "bash" }, "/tmp/project");
    expect(path.isAbsolute(options.shell)).toBe(true);
  });

  test("drops invalid environment names", () => {
    const options = parseOptions({ passEnv: ["GOOD", "bad-name", "1BAD", "A=B"] }, "/tmp/project");
    expect(options.passEnv).toEqual(["GOOD"]);
  });
});
