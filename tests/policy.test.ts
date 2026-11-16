import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseOptions } from "../src/options.ts";
import { capBySystem, resolveEffectiveOptions, trustedPolicyPaths } from "../src/policy.ts";
import { DEFAULT_OPTIONS } from "../src/types.ts";

function tempDir(prefix = "osb-policy-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function fixture() {
  const root = tempDir();
  const workspace = path.join(root, "ws");
  fs.mkdirSync(workspace);
  const paths = {
    user: path.join(root, "user.json"),
    system: path.join(root, "system.json"),
  };
  return { root, workspace, paths };
}

function writePolicy(file: string, value: unknown, mode = 0o600): void {
  fs.writeFileSync(file, JSON.stringify(value), { mode });
  fs.chmodSync(file, mode);
}

function resolve(
  f: ReturnType<typeof fixture>,
  raw: Record<string, unknown> = {},
  uid = typeof process.getuid === "function" ? process.getuid() : undefined
) {
  return resolveEffectiveOptions(raw, f.workspace, {
    paths: f.paths,
    uid,
    platform: "linux",
  });
}

describe("trustedPolicyPaths", () => {
  test("uses XDG_CONFIG_HOME and the platform system directory", () => {
    expect(trustedPolicyPaths({ HOME: "/home/u", XDG_CONFIG_HOME: "/x" }, "linux")).toEqual({
      user: "/x/opencode/opencode-sandbox.json",
      system: "/etc/opencode/opencode-sandbox.json",
    });
    expect(trustedPolicyPaths({ HOME: "/Users/u" }, "darwin")).toEqual({
      user: "/Users/u/.config/opencode/opencode-sandbox.json",
      system: "/Library/Application Support/opencode/opencode-sandbox.json",
    });
  });

  test("honors OPENCODE_CONFIG_DIR", () => {
    expect(
      trustedPolicyPaths({ HOME: "/home/u", OPENCODE_CONFIG_DIR: "/custom/oc" }, "linux").user
    ).toBe("/custom/oc/opencode-sandbox.json");
  });
});

describe("resolveEffectiveOptions", () => {
  test("defaults when no trusted file exists", () => {
    const f = fixture();
    try {
      const result = resolve(f);
      expect(result.options).toEqual(DEFAULT_OPTIONS);
      expect(result.user.used).toBe(false);
      expect(result.system.used).toBe(false);
      expect(result.warnings).toEqual([]);
      expect(result.errors).toEqual([]);
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("plugin options cannot widen the policy", () => {
    const f = fixture();
    try {
      const result = resolve(f, {
        network: "allow",
        mode: "permissive",
        toolGuard: "off",
        writablePaths: [path.join(f.root, "extra")],
        readablePaths: [path.join(os.homedir(), ".ssh")],
        passEnv: ["TOKEN"],
        deniedPaths: [".env"],
        unsandboxedCommands: ["git push *"],
        shell: "/bin/false",
      });
      expect(result.options).toEqual(DEFAULT_OPTIONS);
      const warnings = result.warnings.join("\n");
      expect(warnings).toContain("network");
      expect(warnings).toContain("mode");
      expect(warnings).toContain("toolGuard");
      expect(warnings).toContain("writablePaths");
      expect(warnings).toContain("readablePaths");
      expect(warnings).toContain("passEnv");
      expect(warnings).toContain("deniedPaths");
      expect(warnings).toContain("unsandboxedCommands");
      expect(warnings).toContain("shell");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("the trusted user file can widen the defaults", () => {
    const f = fixture();
    const shared = path.join(f.root, "shared");
    const readable = path.join(f.root, "readable");
    fs.mkdirSync(shared);
    fs.mkdirSync(readable);
    try {
      writePolicy(f.paths.user, {
        network: "allow",
        mode: "permissive",
        toolGuard: "off",
        writablePaths: [shared],
        readablePaths: [readable],
        passEnv: ["TOKEN"],
        deniedPaths: [".env"],
        unsandboxedCommands: ["git push *"],
      });
      const result = resolve(f);
      expect(result.user.used).toBe(true);
      expect(result.options.network).toBe("allow");
      expect(result.options.mode).toBe("permissive");
      expect(result.options.toolGuard).toBe("off");
      expect(result.options.writablePaths).toEqual([shared]);
      expect(result.options.readablePaths).toEqual([readable]);
      expect(result.options.passEnv).toEqual(["TOKEN"]);
      expect(result.options.deniedPaths).toEqual([path.join(f.workspace, ".env")]);
      expect(result.options.unsandboxedCommands).toEqual(["git push *"]);
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("webfetch can be denied from the trusted file", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, { webfetch: "deny" });
      const result = resolve(f);
      expect(result.options.webfetch).toBe("deny");
      expect(result.options.toolGuard).toBe("enforce");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("plugin options can only tighten a trusted policy", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, {
        network: "allow",
        mode: "permissive",
        toolGuard: "off",
        webfetch: "allow",
      });
      const result = resolve(f, {
        network: "deny",
        mode: "enforce",
        toolGuard: "enforce",
        webfetch: "deny",
      });
      expect(result.options.network).toBe("deny");
      expect(result.options.mode).toBe("enforce");
      expect(result.options.toolGuard).toBe("enforce");
      expect(result.options.webfetch).toBe("deny");
      expect(result.warnings).toEqual([]);
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("webfetch allowlists intersect", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, { webfetchAllowlist: ["a.example", "b.example"] });
      const result = resolve(f, { webfetchAllowlist: ["b.example", "c.example"] });
      expect(result.options.webfetch).toBe("allow");
      expect(result.options.webfetchAllowlist).toEqual(["b.example"]);
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("a malformed plugin option does not change the trusted policy", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, { network: "allow" });
      const result = resolve(f, { network: "deny", mode: "sometimes" });
      expect(result.options.network).toBe("allow");
      expect(result.errors.join("\n")).toContain("plugin options");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("a malformed trusted file is ignored with an error", () => {
    const f = fixture();
    try {
      fs.writeFileSync(f.paths.user, "{ not json");
      const result = resolve(f);
      expect(result.options).toEqual(DEFAULT_OPTIONS);
      expect(result.user.used).toBe(false);
      expect(result.errors.join("\n")).toContain("not valid JSON");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("unknown keys and unsafe permissions ignore the file", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, { network: "allow", writablepath: ["/tmp"] });
      let result = resolve(f);
      expect(result.options.network).toBe("deny");
      expect(result.errors.join("\n")).toContain("unknown option");

      writePolicy(f.paths.user, { network: "allow" }, 0o666);
      result = resolve(f);
      expect(result.options.network).toBe("deny");
      expect(result.errors.join("\n")).toContain("group/world-writable");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("a policy file owned by another user is ignored", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, { network: "allow" });
      const uid = typeof process.getuid === "function" ? process.getuid() : 0;
      const result = resolve(f, {}, uid + 1);
      expect(result.options.network).toBe("deny");
      expect(result.errors.join("\n")).toContain("not owned by the current user");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("a policy file inside the workspace is ignored", () => {
    const f = fixture();
    try {
      const inner = path.join(f.workspace, "policy.json");
      writePolicy(inner, { network: "allow" });
      const result = resolveEffectiveOptions({}, f.workspace, {
        paths: { user: inner, system: f.paths.system },
        uid: typeof process.getuid === "function" ? process.getuid() : undefined,
      });
      expect(result.options.network).toBe("deny");
      expect(result.errors.join("\n")).toContain("inside the workspace");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("an invalid system file removes the cap and disables the user file", () => {
    const f = fixture();
    try {
      writePolicy(f.paths.user, {
        network: "allow",
        mode: "permissive",
        writablePaths: [path.join(f.root, "extra")],
      });
      writePolicy(f.paths.system, { network: "allow" });
      const result = resolve(f);
      // Tests run unprivileged, so the temp system file is not a valid root
      // policy. The user file must not be applied without that cap.
      expect(result.options).toEqual(DEFAULT_OPTIONS);
      expect(result.system.used).toBe(false);
      expect(result.user.used).toBe(false);
      expect(result.user.ignored).toBe(true);
      expect(result.errors.join("\n")).toContain("not root-owned");
      expect(result.errors.join("\n")).toContain("ignored because the system policy is invalid");
    } finally {
      fs.rmSync(f.root, { recursive: true, force: true });
    }
  });
});

describe("capBySystem", () => {
  test("keeps only the strictest scalar values and the allowed mount set", () => {
    const user = parseOptions(
      {
        network: "allow",
        mode: "permissive",
        toolGuard: "off",
        writablePaths: ["/a", "/b"],
        readablePaths: ["/r1", "/r2"],
        passEnv: ["TOKEN", "OTHER"],
        webfetch: "allow",
      },
      "/tmp"
    );
    const system = parseOptions(
      {
        network: "deny",
        mode: "enforce",
        toolGuard: "enforce",
        writablePaths: ["/a"],
        readablePaths: ["/r2"],
        passEnv: ["TOKEN"],
        webfetch: "deny",
      },
      "/tmp"
    );

    const capped = capBySystem(user, system);
    expect(capped.network).toBe("deny");
    expect(capped.mode).toBe("enforce");
    expect(capped.toolGuard).toBe("enforce");
    expect(capped.writablePaths).toEqual(["/a"]);
    expect(capped.readablePaths).toEqual(["/r2"]);
    expect(capped.passEnv).toEqual(["TOKEN"]);
    expect(capped.webfetch).toBe("deny");
  });

  test("intersects allowlists and rejects an empty intersection", () => {
    const user = parseOptions({ webfetchAllowlist: ["a.example", "b.example"] }, "/tmp");
    const system = parseOptions({ webfetchAllowlist: ["b.example", "c.example"] }, "/tmp");
    expect(capBySystem(user, system).webfetchAllowlist).toEqual(["b.example"]);

    const disjoint = capBySystem(user, parseOptions({ webfetchAllowlist: ["c.example"] }, "/tmp"));
    expect(disjoint.webfetch).toBe("deny");
  });
});
