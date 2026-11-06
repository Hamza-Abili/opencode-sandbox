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
