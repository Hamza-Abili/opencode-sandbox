import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildDarwinProfile } from "../src/darwin.ts";
import { parseOptions } from "../src/options.ts";
import { resolveLayout } from "../src/paths.ts";
import { buildLinuxProfile } from "../src/profile.ts";
import { protectedPaths } from "../src/protected.ts";
import {
  createToolPolicy,
  evaluatePermission,
  type PermissionEvaluation,
} from "../src/tool-policy.ts";

function tempDir(prefix = "osb-protected-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function workspaceFixture() {
  const workspace = tempDir();
  fs.mkdirSync(path.join(workspace, ".opencode", "plugin"), { recursive: true });
  fs.writeFileSync(path.join(workspace, ".opencode", "plugin", "evil.ts"), "export {}\n");
  fs.writeFileSync(path.join(workspace, "opencode.json"), "{}\n");
  fs.mkdirSync(path.join(workspace, ".git", "hooks"), { recursive: true });
  fs.writeFileSync(path.join(workspace, ".git", "config"), "[core]\n");
  fs.writeFileSync(path.join(workspace, ".gitattributes"), "* text=auto\n");
  fs.writeFileSync(path.join(workspace, ".env"), "SECRET=value\n");
  fs.mkdirSync(path.join(workspace, "secrets"));
  fs.writeFileSync(path.join(workspace, "secrets", "token"), "SECRET=value\n");
  fs.writeFileSync(path.join(workspace, "notes.txt"), "hello\n");
  return workspace;
}

function layoutFor(workspace: string, deniedPaths: string[] = []) {
  return resolveLayout(workspace, { writablePaths: [], readablePaths: [], deniedPaths });
}

describe("protectedPaths", () => {
  test("includes lexical paths even when they do not exist", () => {
    const workspace = tempDir();
    try {
      const paths = protectedPaths(workspace);
      expect(paths).toContain(path.join(workspace, ".opencode"));
      expect(paths).toContain(path.join(workspace, "opencode.json"));
      expect(paths).toContain(path.join(workspace, ".git", "hooks"));
      expect(paths).toContain(path.join(workspace, ".git", "config"));
      expect(paths).toContain(path.join(workspace, ".git", "info", "attributes"));
      expect(paths).toContain(path.join(workspace, ".gitmodules"));
      expect(paths).toContain(path.join(workspace, ".envrc"));
      expect(paths).toContain(path.join(workspace, ".gitattributes"));
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("protects the .git pointer file in a worktree but not the whole directory", () => {
    const workspace = tempDir();
    const main = tempDir();
    try {
      fs.mkdirSync(path.join(main, ".git", "worktrees", "wt"), { recursive: true });
      fs.writeFileSync(
        path.join(workspace, ".git"),
        `gitdir: ${path.join(main, ".git", "worktrees", "wt")}\n`
      );
      const paths = protectedPaths(workspace);
      expect(paths).toContain(path.join(workspace, ".git"));
      expect(paths).not.toContain(workspace);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(main, { recursive: true, force: true });
    }
  });

  test("rejects a symlinked protected path", () => {
    const workspace = tempDir();
    const target = path.join(tempDir("osb-protected-target-"), "policy.json");
    try {
      fs.writeFileSync(target, "{}\n");
      fs.symlinkSync(target, path.join(workspace, "opencode.json"));
      expect(() => protectedPaths(workspace)).toThrow(/is a symlink/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(path.dirname(target), { recursive: true, force: true });
    }
  });

  test("rejects a nested symlink under a host-loaded protected tree", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "plugins"));
      fs.writeFileSync(path.join(workspace, "plugins", "evil.ts"), "evil\n");
      fs.mkdirSync(path.join(workspace, ".opencode", "plugin"), { recursive: true });
      fs.symlinkSync(
        path.join(workspace, "plugins", "evil.ts"),
        path.join(workspace, ".opencode", "plugin", "evil.ts")
      );
      expect(() => protectedPaths(workspace)).toThrow(/is a symlink/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("skips package-manager symlinks under node_modules", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, ".opencode", "node_modules", "dep"), {
        recursive: true,
      });
      fs.symlinkSync(
        path.join(workspace, ".opencode", "node_modules", "dep"),
        path.join(workspace, ".opencode", "node_modules", "link")
      );
      expect(() => protectedPaths(workspace)).not.toThrow();
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a symlink named node_modules", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "plugins"));
      fs.mkdirSync(path.join(workspace, ".opencode"), { recursive: true });
      fs.symlinkSync(
        path.join(workspace, "plugins"),
        path.join(workspace, ".opencode", "node_modules")
      );
      expect(() => protectedPaths(workspace)).toThrow(/is a symlink/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("protects nested .git pointers and nested repositories", () => {
    const workspace = tempDir();
    try {
      fs.writeFileSync(path.join(workspace, ".gitmodules"), '[submodule "x"]\n\tpath = sub\n');
      fs.mkdirSync(path.join(workspace, ".git", "modules", "sub"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../../.git/modules/sub\n");
      fs.mkdirSync(path.join(workspace, "nested", ".git"), { recursive: true });
      fs.writeFileSync(path.join(workspace, "nested", ".git", "config"), "[core]\n");
      const paths = protectedPaths(workspace);
      expect(paths).toContain(path.join(workspace, "sub", ".git"));
      expect(paths).toContain(path.join(workspace, "nested", ".git"));
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects symlinks inside a nested .git", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "evil"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "sub", ".git"), { recursive: true });
      fs.symlinkSync(path.join(workspace, "evil"), path.join(workspace, "sub", ".git", "hooks"));
      expect(() => protectedPaths(workspace)).toThrow(/is a symlink/);

      fs.rmSync(path.join(workspace, "sub", ".git", "hooks"));
      fs.writeFileSync(path.join(workspace, "sub", ".git", "config"), "[core]\n");
      fs.rmSync(path.join(workspace, "sub", ".git", "config"));
      fs.symlinkSync(path.join(workspace, "evil"), path.join(workspace, "sub", ".git", "config"));
      expect(() => protectedPaths(workspace)).toThrow(/is a symlink/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("canonicalizes case variants on macOS", () => {
    if (process.platform !== "darwin") return;
    const parent = tempDir();
    const workspace = path.join(parent, "Proj");
    try {
      fs.mkdirSync(path.join(workspace, "sub"), { recursive: true });
      fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../../proj/evil\n");
      expect(() => protectedPaths(workspace)).toThrow(
        /traverses writable workspace path|targets writable path/
      );
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("rejects a pointer into an explicit writable mount", () => {
    const workspace = tempDir();
    const cache = tempDir("osb-protected-cache-");
    try {
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.writeFileSync(
        path.join(workspace, "sub", ".git"),
        `gitdir: ${path.join(cache, "evil")}\n`
      );
      expect(() => protectedPaths(workspace, [cache])).toThrow(/writable mount/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(cache, { recursive: true, force: true });
    }
  });

  test("canonicalizes a symlink alias in a nested .git pointer", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "evil"));
      fs.symlinkSync(workspace, path.join(workspace, "alias"));
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../alias/evil\n");
      expect(() => protectedPaths(workspace)).toThrow(
        /traverses writable workspace path|targets writable path/
      );
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("resolves gitdir pointers with kernel symlink.. semantics", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    try {
      fs.mkdirSync(path.join(workspace, "a", "b"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "outside", "evil"), { recursive: true });
      fs.symlinkSync(path.join(workspace, "a", "b"), path.join(workspace, "link"));
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../link/../../outside/evil\n");
      expect(() => protectedPaths(workspace)).toThrow(
        /traverses writable workspace path|targets writable path/
      );

      fs.rmSync(path.join(workspace, "sub", ".git"));
      fs.writeFileSync(path.join(workspace, ".git"), "gitdir: ./link/../../outside/evil\n");
      expect(() => protectedPaths(workspace)).toThrow(
        /traverses writable workspace path|targets a writable path/
      );
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("rejects external pointers through a mutable workspace component", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    try {
      fs.mkdirSync(path.join(workspace, "a", "b"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "outside", "evil"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "sub"));
      const link = path.join(workspace, "link");
      const pointer = path.join(workspace, "sub", ".git");

      fs.mkdirSync(link);
      fs.writeFileSync(pointer, "gitdir: ../link/../../outside/evil\n");
      expect(() => protectedPaths(workspace)).toThrow(/traverses writable workspace path/);

      fs.rmSync(link, { recursive: true });
      fs.symlinkSync(path.join(parent, "outside"), link);
      expect(() => protectedPaths(workspace)).toThrow(/traverses writable workspace path/);

      fs.rmSync(link);
      expect(() => protectedPaths(workspace)).toThrow(/traverses writable workspace path/);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("rejects a mutable symlink alias into a trusted .git tree", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, ".git", "modules"), { recursive: true });
      fs.mkdirSync(path.join(workspace, ".git", "worktrees"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "sub"));
      for (const target of [
        path.join(workspace, ".git", "modules"),
        path.join(workspace, ".git", "worktrees"),
        path.join(workspace, ".git"),
      ]) {
        const alias = path.join(workspace, "alias");
        try {
          fs.rmSync(alias);
        } catch {}
        fs.symlinkSync(target, alias);
        fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../alias/evil\n");
        expect(() => protectedPaths(workspace)).toThrow(/traverses writable workspace path/);
      }
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("allows absolute in-workspace pointers into .git/modules and worktrees", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, ".git", "modules", "m"), { recursive: true });
      fs.mkdirSync(path.join(workspace, ".git", "worktrees", "wt"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "sub"));
      for (const target of [
        path.join(workspace, ".git", "modules", "m"),
        path.join(workspace, ".git", "worktrees", "wt"),
      ]) {
        fs.writeFileSync(path.join(workspace, "sub", ".git"), `gitdir: ${target}\n`);
        const paths = protectedPaths(workspace);
        expect(paths).toContain(path.join(workspace, "sub", ".git"));
      }
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("allows a nested worktree pointer under the root .git/worktrees", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, ".git", "worktrees", "foo"), { recursive: true });
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../.git/worktrees/foo\n");
      const paths = protectedPaths(workspace);
      expect(paths).toContain(path.join(workspace, "sub", ".git"));
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a too-large or non-UTF-8 gitdir pointer", () => {
    const workspace = tempDir();
    try {
      fs.writeFileSync(path.join(workspace, ".git"), "x".repeat(20_000));
      expect(() => protectedPaths(workspace)).toThrow(/too large/);

      fs.writeFileSync(path.join(workspace, ".git"), Buffer.from([0xff, 0xfe]));
      expect(() => protectedPaths(workspace)).toThrow(/UTF-8/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a nested .git pointer to another writable workspace path", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.mkdirSync(path.join(workspace, "evil"));
      fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../evil\n");
      expect(() => protectedPaths(workspace)).toThrow(
        /traverses writable workspace path|targets writable path/
      );
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a root .git pointer into the workspace", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "evil"));
      fs.writeFileSync(path.join(workspace, ".git"), "gitdir: ./evil\n");
      expect(() => protectedPaths(workspace)).toThrow(
        /traverses writable workspace path|targets a writable path/
      );
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a nested .git symlink", () => {
    const workspace = tempDir();
    try {
      fs.mkdirSync(path.join(workspace, "evil"));
      fs.mkdirSync(path.join(workspace, "sub"));
      fs.symlinkSync(path.join(workspace, "evil"), path.join(workspace, "sub", ".git"));
      expect(() => protectedPaths(workspace)).toThrow(/is a symlink/);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("protects a submodule pointer from a subdirectory workspace", () => {
    const repo = tempDir();
    try {
      fs.mkdirSync(path.join(repo, ".git", "modules", "vendor"), { recursive: true });
      const workspace = path.join(repo, "packages", "app");
      fs.mkdirSync(workspace, { recursive: true });
      fs.mkdirSync(path.join(workspace, "vendor"));
      fs.writeFileSync(
        path.join(workspace, "vendor", ".git"),
        "gitdir: ../../../.git/modules/vendor\n"
      );
      const paths = protectedPaths(workspace);
      expect(paths).toContain(path.join(workspace, "vendor", ".git"));
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  test("allows a linked-worktree submodule pointer into the main .git/modules", () => {
    const main = tempDir();
    const worktree = tempDir();
    try {
      fs.mkdirSync(path.join(main, ".git", "modules", "sub"), { recursive: true });
      fs.writeFileSync(path.join(main, ".git", "modules", "sub", "config"), "[core]\n");
      fs.mkdirSync(path.join(main, ".git", "worktrees", "wt"), { recursive: true });
      fs.writeFileSync(
        path.join(worktree, ".git"),
        `gitdir: ${path.join(main, ".git", "worktrees", "wt")}\n`
      );
      fs.mkdirSync(path.join(worktree, "sub"));
      fs.writeFileSync(
        path.join(worktree, "sub", ".git"),
        `gitdir: ${path.join(main, ".git", "modules", "sub")}\n`
      );
      const paths = protectedPaths(worktree);
      expect(paths).toContain(path.join(worktree, "sub", ".git"));
    } finally {
      fs.rmSync(main, { recursive: true, force: true });
      fs.rmSync(worktree, { recursive: true, force: true });
    }
  });

  test("does not read a stray ancestor repository", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    fs.mkdirSync(workspace);
    fs.mkdirSync(path.join(parent, ".git"));
    fs.writeFileSync(path.join(parent, ".gitmodules"), '[submodule "x"]\n\tpath = ../evil\n');
    fs.chmodSync(parent, 0o777);
    try {
      const paths = protectedPaths(workspace);
      expect(paths).not.toContain(path.join(parent, ".gitmodules"));
      expect(paths).not.toContain(path.join(parent, ".git", "config"));
    } finally {
      fs.chmodSync(parent, 0o700);
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("denies a missing path under a symlinked parent through its resolved target", () => {
    const workspace = tempDir();
    try {
      const real = path.join(workspace, "real");
      fs.mkdirSync(real);
      fs.symlinkSync(real, path.join(workspace, "link"));
      const layout = resolveLayout(workspace, {
        writablePaths: [],
        readablePaths: [],
        deniedPaths: [path.join(workspace, "link", "secret")],
      });
      expect(layout.deniedPaths).toContain(path.join(real, "secret"));
      const policy = createToolPolicy(layout, parseOptions({}, workspace), "linux");
      const write: PermissionEvaluation = {
        action: "edit",
        resources: [path.join(real, "secret")],
        effect: "allow",
      };
      evaluatePermission(write, policy);
      expect(write.effect).toBe("deny");
      expect(write.message).toContain("hidden by deniedPaths");
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("follows a broken denied symlink target", () => {
    const workspace = tempDir();
    try {
      fs.symlinkSync(".env.local", path.join(workspace, ".env"));
      const layout = resolveLayout(workspace, {
        writablePaths: [],
        readablePaths: [],
        deniedPaths: [path.join(workspace, ".env")],
      });
      expect(layout.deniedPaths).toContain(path.join(workspace, ".env.local"));
      const policy = createToolPolicy(layout, parseOptions({}, workspace), "linux");
      const write: PermissionEvaluation = {
        action: "edit",
        resources: [path.join(workspace, ".env.local")],
        effect: "allow",
      };
      evaluatePermission(write, policy);
      expect(write.effect).toBe("deny");
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("allows normal workspace writes and denied-path search roots are refused", () => {
    const workspace = workspaceFixture();
    try {
      const layout = layoutFor(workspace, [path.join(workspace, "secrets")]);
      const options = parseOptions({ deniedPaths: [path.join(workspace, "secrets")] }, workspace);
      const policy = createToolPolicy(layout, options, "linux");

      const normal: PermissionEvaluation = {
        action: "edit",
        resources: [path.join(workspace, "notes.txt")],
        effect: "allow",
      };
      evaluatePermission(normal, policy);
      expect(normal.effect).toBe("allow");

      const search: PermissionEvaluation = {
        action: "glob",
        resources: [],
        metadata: { path: path.join(workspace, "secrets") },
        effect: "allow",
      };
      evaluatePermission(search, policy);
      expect(search.effect).toBe("deny");
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });
});

describe("sandbox profiles", () => {
  test("Linux mounts protected paths read-only after the workspace and masks denied paths", () => {
    const workspace = workspaceFixture();
    try {
      const layout = layoutFor(workspace, [
        path.join(workspace, ".env"),
        path.join(workspace, "secrets"),
      ]);
      const args = buildLinuxProfile({
        layout,
        network: "deny",
        passEnv: [],
        shell: "/bin/bash",
        env: { PATH: "/usr/bin:/bin" },
      });

      const workspaceBind = args.indexOf(workspace);
      const protectedBind = args.indexOf(path.join(workspace, ".opencode"));
      expect(workspaceBind).toBeGreaterThan(0);
      expect(protectedBind).toBeGreaterThan(workspaceBind);
      expect(args[protectedBind - 1]).toBe("--ro-bind");

      const git = args.indexOf(path.join(workspace, ".git"));
      expect(git).toBeGreaterThan(0);
      expect(args[git - 1]).toBe("--bind");

      const env = args.indexOf(path.join(workspace, ".env"));
      expect(env).toBeGreaterThan(0);
      expect(args.slice(env - 2, env)).toEqual(["--ro-bind", "/dev/null"]);

      const secrets = args.indexOf(path.join(workspace, "secrets"));
      expect(secrets).toBeGreaterThan(0);
      expect(args[secrets - 1]).toBe("--tmpfs");
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("a readable .git mount stays read-only after the pin", () => {
    const workspace = workspaceFixture();
    try {
      const layout = resolveLayout(workspace, {
        writablePaths: [],
        readablePaths: [path.join(workspace, ".git")],
      });
      const args = buildLinuxProfile({
        layout,
        network: "deny",
        passEnv: [],
        shell: "/bin/bash",
        env: { PATH: "/usr/bin:/bin" },
      });
      const git = path.join(workspace, ".git");
      const pin = args.findIndex(
        (value, index) => value === "--bind" && args[index + 1] === git && args[index + 2] === git
      );
      const readOnly = args.findIndex(
        (value, index) =>
          value === "--ro-bind" && args[index + 1] === git && args[index + 2] === git
      );
      expect(readOnly).toBeGreaterThan(0);
      if (pin !== -1) expect(readOnly).toBeGreaterThan(pin);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("macOS denies writes to protected paths and reads/writes to denied paths", () => {
    const workspace = workspaceFixture();
    const home = tempDir("osb-protected-home-");
    try {
      const layout = layoutFor(workspace, [path.join(workspace, ".env")]);
      const profile = buildDarwinProfile({
        layout,
        home,
        network: "deny",
        passEnv: [],
        shell: "/bin/bash",
        env: { PATH: "/usr/bin:/bin" },
      });
      const lines = profile.split("\n");
      const workspaceAllow = lines.findIndex((line) =>
        line.includes(`(allow file-write* (subpath "${workspace}"))`)
      );
      const protectedDeny = lines.findIndex((line) =>
        line.includes(`(deny file-write* (literal "${path.join(workspace, ".opencode")}"))`)
      );
      const deniedRead = lines.findIndex((line) =>
        line.includes(`(deny file-read* file-write* (literal "${path.join(workspace, ".env")}"))`)
      );
      const gitDeny = lines.findIndex((line) =>
        line.includes(`(deny file-write-unlink (literal "${path.join(workspace, ".git")}"))`)
      );
      expect(workspaceAllow).toBeGreaterThan(0);
      expect(protectedDeny).toBeGreaterThan(workspaceAllow);
      expect(gitDeny).toBeGreaterThan(protectedDeny);
      expect(deniedRead).toBeGreaterThan(gitDeny);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
