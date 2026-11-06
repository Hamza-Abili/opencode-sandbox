import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveLayout } from "../src/paths.ts";
import { buildLinuxProfile, sandboxPath } from "../src/profile.ts";

function tempDir(prefix = "osb-profile-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function profileFor(
  workspace: string,
  overrides: Partial<Parameters<typeof buildLinuxProfile>[0]> = {},
  mounts: { writablePaths?: string[]; readablePaths?: string[] } = {}
): string[] {
  return buildLinuxProfile({
    layout: resolveLayout(workspace, {
      writablePaths: mounts.writablePaths ?? [],
      readablePaths: mounts.readablePaths ?? [],
    }),
    network: "deny",
    passEnv: [],
    shell: "/bin/bash",
    env: { PATH: "/usr/bin:/bin", TERM: "xterm" },
    ...overrides,
  });
}

function expectBind(args: string[], flag: string, target: string): void {
  const index = args.indexOf(target);
  expect(index).toBeGreaterThan(0);
  expect(args[index - 1]).toBe(flag);
}

function mountIndex(args: string[], flag: string, target: string): number {
  return args.findIndex((value, index) => value === flag && args[index + 1] === target);
}

describe("buildLinuxProfile", () => {
  test("starts from an isolated, capability-free namespace", () => {
    const dir = tempDir();
    try {
      const args = profileFor(dir);
      expect(args).toContain("--unshare-all");
      expect(args).toContain("--cap-drop");
      expect(args).toContain("--die-with-parent");
      expect(args).toContain("--new-session");
      expect(args).toContain("--clearenv");
      expect(args).not.toContain("--share-net");
      expect(args).not.toContain("--chdir");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("shares the network only when explicitly allowed", () => {
    const dir = tempDir();
    try {
      expect(profileFor(dir, { network: "allow" })).toContain("--share-net");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("mounts the workspace read-write and extras with the right mode", () => {
    const dir = tempDir();
    const writable = tempDir("osb-rw-");
    const readable = tempDir("osb-ro-");
    try {
      const args = profileFor(dir, {}, { writablePaths: [writable], readablePaths: [readable] });
      expectBind(args, "--bind", dir);
      expectBind(args, "--bind", writable);
      expectBind(args, "--ro-bind", readable);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(writable, { recursive: true, force: true });
      fs.rmSync(readable, { recursive: true, force: true });
    }
  });

  test("a readable parent does not shadow the workspace", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    fs.mkdirSync(workspace);
    try {
      const args = profileFor(workspace, {}, { readablePaths: [parent] });
      const readable = mountIndex(args, "--ro-bind", parent);
      const writable = mountIndex(args, "--bind", workspace);
      expect(readable).toBeGreaterThan(0);
      expect(writable).toBeGreaterThan(readable);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("a readable subdirectory is mounted after the workspace", () => {
    const workspace = tempDir();
    const vendor = path.join(workspace, "vendor");
    fs.mkdirSync(vendor);
    try {
      const args = profileFor(workspace, {}, { readablePaths: [vendor] });
      const writable = mountIndex(args, "--bind", workspace);
      const readable = mountIndex(args, "--ro-bind", vendor);
      expect(writable).toBeGreaterThan(0);
      expect(readable).toBeGreaterThan(writable);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("a writable subdirectory wins over a readable parent", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    const cache = path.join(parent, "cache");
    fs.mkdirSync(workspace);
    fs.mkdirSync(cache);
    try {
      const args = profileFor(
        workspace,
        {},
        {
          writablePaths: [cache],
          readablePaths: [parent],
        }
      );
      const readable = mountIndex(args, "--ro-bind", parent);
      const writable = mountIndex(args, "--bind", cache);
      expect(readable).toBeGreaterThan(0);
      expect(writable).toBeGreaterThan(readable);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("clears ambient environment and sets a synthetic home", () => {
    const dir = tempDir();
    try {
      const args = profileFor(dir, {
        passEnv: ["SECRET", "HOME", "PATH"],
        env: {
          PATH: "/usr/bin:/home/ubuntu/.bun/bin",
          TERM: "xterm",
          SECRET: "yes",
          HOME: "/home/ubuntu",
        },
      });
      expect(args).toContain("--clearenv");
      expect(args).toContain("HOME");
      expect(args).toContain("/home/sandbox");
      expect(args).toContain("TMPDIR");
      expect(args).toContain("SECRET");
      expect(args).toContain("yes");
      expect(args).toContain("xterm");
      expect(args).not.toContain("/home/ubuntu");
      expect(args.join(" ")).not.toContain("/home/ubuntu/.bun/bin");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("does not let passEnv override the sandbox home or PATH", () => {
    const dir = tempDir();
    try {
      const args = profileFor(dir, {
        passEnv: ["HOME", "PATH"],
        env: { HOME: "/host/home", PATH: "/evil/bin" },
      });
      const value = (key: string): string[] => {
        const out: string[] = [];
        for (let i = 0; i < args.length - 1; i++) {
          if (args[i] === "--setenv" && args[i + 1] === key) out.push(args[i + 2] as string);
        }
        return out;
      };
      expect(value("HOME")).toEqual(["/home/sandbox"]);
      expect(value("PATH").at(-1)).toBe("/usr/local/bin:/usr/bin:/bin");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("mounts symlinked extra paths at their canonical target", () => {
    const dir = tempDir();
    const real = tempDir("osb-real-");
    const link = path.join(dir, "link");
    fs.symlinkSync(real, link);
    try {
      const args = profileFor(dir, {}, { writablePaths: [link] });
      expect(args).toContain(real);
      expectBind(args, "--bind", real);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      fs.rmSync(real, { recursive: true, force: true });
    }
  });
});

describe("sandboxPath", () => {
  test("keeps visible entries and always adds safe defaults", () => {
    const value = sandboxPath("/home/user/.bun/bin:/usr/bin:/opt/tool/bin", ["/usr", "/opt"]);
    expect(value).toBe("/usr/bin:/opt/tool/bin:/usr/local/bin:/bin");
  });

  test("falls back when the host PATH is empty", () => {
    expect(sandboxPath(undefined, [])).toBe("/usr/local/bin:/usr/bin:/bin");
  });
});
