import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildDarwinProfile, DARWIN_SYSTEM_READ, darwinEnvironment } from "../src/darwin.ts";
import { resolveLayout } from "../src/paths.ts";

function tempDir(prefix = "osb-darwin-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function inputFor(
  workspace: string,
  home: string,
  overrides: Partial<Parameters<typeof buildDarwinProfile>[0]> = {}
): Parameters<typeof buildDarwinProfile>[0] {
  return {
    layout: resolveLayout(workspace, { writablePaths: [], readablePaths: [] }),
    home,
    network: "deny",
    passEnv: [],
    shell: "/bin/bash",
    env: { PATH: "/usr/bin:/bin", TERM: "xterm" },
    ...overrides,
  };
}

function lineIndex(profile: string, line: string): number {
  return profile.split("\n").indexOf(line);
}

describe("buildDarwinProfile", () => {
  test("never grants the whole /System volume (which contains /System/Volumes/Data)", () => {
    expect(DARWIN_SYSTEM_READ).not.toContain("/System");
    expect(DARWIN_SYSTEM_READ).not.toContain("/System/Volumes/Data");
    expect(DARWIN_SYSTEM_READ).toContain("/System/Library");
  });

  test("denies kern.procargs after the sysctl allow", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    try {
      const profile = buildDarwinProfile(inputFor(dir, home));
      expect(profile).toContain("(allow sysctl-read)");
      expect(profile).toContain("(deny sysctl-read");
      expect(profile).toContain('(sysctl-name "kern.procargs")');
      expect(profile).toContain('(sysctl-name "kern.procargs2")');
      expect(profile.indexOf("(deny sysctl-read")).toBeGreaterThan(
        profile.indexOf("(allow sysctl-read)")
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("denies by default and allows the expected primitives", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    try {
      const profile = buildDarwinProfile(inputFor(dir, home));
      expect(profile).toContain("(deny default)");
      expect(profile).toContain("(allow process-exec)");
      expect(profile).toContain("(allow process-fork)");
      expect(profile).toContain("(allow file-read-metadata)");
      expect(profile).toContain(`(subpath ${JSON.stringify(dir)})`);
      expect(profile).toContain(`(subpath ${JSON.stringify(home)})`);
      expect(profile).not.toContain("(allow network*)");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("does not grant access to the host home", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    try {
      const profile = buildDarwinProfile(inputFor(dir, home));
      expect(profile).not.toContain(os.homedir());
      expect(profile).not.toContain(".ssh");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("adds network and DNS/TLS services only when allowed", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    try {
      const profile = buildDarwinProfile(inputFor(dir, home, { network: "allow" }));
      expect(profile).toContain("(allow network*)");
      for (const service of [
        "com.apple.networkd",
        "com.apple.SystemConfiguration.DNSConfiguration",
        "com.apple.dnssd.service",
        "com.apple.TrustEvaluationAgent",
        "com.apple.trustd.agent",
      ]) {
        expect(profile).toContain(service);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("limits writes to workspace, home, temp and explicit paths", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    const extra = tempDir("osb-extra-");
    try {
      const profile = buildDarwinProfile(
        inputFor(dir, home, {
          layout: resolveLayout(dir, { writablePaths: [extra], readablePaths: [] }),
        })
      );
      expect(profile).toContain(`(subpath ${JSON.stringify(dir)})`);
      expect(profile).toContain(`(subpath ${JSON.stringify(home)})`);
      expect(profile).toContain(`(subpath ${JSON.stringify(extra)})`);
      expect(profile).toContain('(literal "/dev/null")');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(extra, { recursive: true, force: true });
    }
  });

  test("makes writable paths readable as well", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    const extra = tempDir("osb-extra-");
    try {
      const profile = buildDarwinProfile(
        inputFor(dir, home, {
          layout: resolveLayout(dir, { writablePaths: [extra], readablePaths: [] }),
        })
      );
      const readLine = profile
        .split("\n")
        .find((line) => line.startsWith("(allow file-read* ") && line.includes(extra));
      expect(readLine).toBeDefined();
      expect(profile).toContain(`(allow file-write* (subpath ${JSON.stringify(extra)}))`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(extra, { recursive: true, force: true });
    }
  });

  test("denies writes to a readable subdirectory after the workspace", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    const vendor = path.join(dir, "vendor");
    fs.mkdirSync(vendor);
    try {
      const profile = buildDarwinProfile(
        inputFor(dir, home, {
          layout: resolveLayout(dir, { writablePaths: [], readablePaths: [vendor] }),
        })
      );
      const allow = lineIndex(profile, `(allow file-write* (subpath ${JSON.stringify(dir)}))`);
      const deny = lineIndex(profile, `(deny file-write* (subpath ${JSON.stringify(vendor)}))`);
      expect(allow).toBeGreaterThan(-1);
      expect(deny).toBeGreaterThan(allow);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("a readable ancestor does not shadow the workspace", () => {
    const parent = tempDir();
    const home = tempDir("osb-home-");
    const workspace = path.join(parent, "ws");
    fs.mkdirSync(workspace);
    try {
      const profile = buildDarwinProfile(
        inputFor(workspace, home, {
          layout: resolveLayout(workspace, { writablePaths: [], readablePaths: [parent] }),
        })
      );
      const deny = lineIndex(profile, `(deny file-write* (subpath ${JSON.stringify(parent)}))`);
      const allow = lineIndex(
        profile,
        `(allow file-write* (subpath ${JSON.stringify(workspace)}))`
      );
      expect(deny).toBeGreaterThan(-1);
      expect(allow).toBeGreaterThan(deny);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("a writable child wins over a readable parent", () => {
    const parent = tempDir();
    const home = tempDir("osb-home-");
    const workspace = path.join(parent, "ws");
    const cache = path.join(parent, "cache");
    fs.mkdirSync(workspace);
    fs.mkdirSync(cache);
    try {
      const profile = buildDarwinProfile(
        inputFor(workspace, home, {
          layout: resolveLayout(workspace, {
            writablePaths: [cache],
            readablePaths: [parent],
          }),
        })
      );
      const deny = lineIndex(profile, `(deny file-write* (subpath ${JSON.stringify(parent)}))`);
      const allow = lineIndex(profile, `(allow file-write* (subpath ${JSON.stringify(cache)}))`);
      expect(deny).toBeGreaterThan(-1);
      expect(allow).toBeGreaterThan(deny);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("quotes paths safely", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    const weird = path.join(dir, 'a "quoted" path');
    fs.mkdirSync(weird);
    try {
      const profile = buildDarwinProfile(
        inputFor(dir, home, {
          layout: resolveLayout(dir, { writablePaths: [weird], readablePaths: [] }),
        })
      );
      expect(profile).toContain(JSON.stringify(weird));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe("darwinEnvironment", () => {
  test("uses the synthetic home and filters invisible PATH entries", () => {
    const dir = tempDir();
    const home = tempDir("osb-home-");
    try {
      const env = darwinEnvironment(
        inputFor(dir, home, {
          passEnv: ["TOKEN", "HOME"],
          env: {
            PATH: "/Users/someone/.bun/bin:/usr/bin:/bin",
            TERM: "xterm",
            TOKEN: "secret",
            HOME: "/Users/someone",
          },
        })
      );
      expect(env.HOME).toBe(home);
      expect(env.TMPDIR).toBe(path.join(home, "tmp"));
      expect(env.PATH).not.toContain("/Users/someone");
      expect(env.PATH).toContain("/usr/bin");
      expect(env.TOKEN).toBe("secret");
      expect(env.TERM).toBe("xterm");
      expect(env.HOME).not.toBe("/Users/someone");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
