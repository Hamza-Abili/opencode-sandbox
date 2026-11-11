import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseOptions } from "../src/options.ts";
import {
  createToolPolicy,
  evaluatePermission,
  guardToolInput,
  type PermissionEvaluation,
} from "../src/tool-policy.ts";
import type { SandboxLayout } from "../src/types.ts";

function tempDir(prefix = "osb-tool-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function outsideBase(): string {
  return fs.realpathSync.native(process.platform === "darwin" ? "/private/var/tmp" : "/var/tmp");
}

function fixture(overrides: Record<string, unknown> = {}, base = os.tmpdir()) {
  const workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(base, "osb-tool-")));
  const writable = tempDir("osb-tool-rw-");
  const readable = tempDir("osb-tool-ro-");
  const layout: SandboxLayout = {
    workspace,
    hostHome: fs.realpathSync.native(os.homedir()),
    writablePaths: [writable],
    readablePaths: [readable],
  };
  const options = parseOptions(
    {
      toolGuard: "enforce",
      writablePaths: [writable],
      readablePaths: [readable],
      ...overrides,
    },
    workspace
  );
  const policy = createToolPolicy(
    layout,
    options,
    process.platform === "darwin" ? "darwin" : "linux"
  );
  const cleanup = () => {
    fs.rmSync(workspace, { recursive: true, force: true });
    fs.rmSync(writable, { recursive: true, force: true });
    fs.rmSync(readable, { recursive: true, force: true });
  };
  return { workspace, writable, readable, layout, options, policy, cleanup };
}

function event(
  action: string,
  resources: string[],
  metadata?: Record<string, unknown>
): PermissionEvaluation {
  return { action, resources, metadata, effect: "allow" };
}

describe("evaluatePermission", () => {
  test("allows workspace reads and denies the host home", () => {
    const f = fixture();
    try {
      const inside = event("read", ["AGENTS.md"]);
      evaluatePermission(inside, f.policy);
      expect(inside.effect).toBe("allow");

      const outside = event("read", [path.join(f.layout.hostHome, ".ssh", "id_rsa")]);
      evaluatePermission(outside, f.policy);
      expect(outside.effect).toBe("deny");
      expect(outside.message).toContain("read denied");

      // A legitimate workspace entry whose name starts with `..` is not a
      // parent traversal.
      const dotdot = event("read", ["..foo"]);
      evaluatePermission(dotdot, f.policy);
      expect(dotdot.effect).toBe("allow");
    } finally {
      f.cleanup();
    }
  });

  test("allows explicit readable and writable paths", () => {
    const f = fixture();
    try {
      const read = event("read", [path.join(f.readable, "notes.txt")]);
      evaluatePermission(read, f.policy);
      expect(read.effect).toBe("allow");

      const write = event("edit", [path.join(f.writable, "out.txt")]);
      evaluatePermission(write, f.policy);
      expect(write.effect).toBe("allow");
    } finally {
      f.cleanup();
    }
  });

  test("applies readable-subdirectory precedence to writes", () => {
    const workspace = tempDir();
    const vendor = path.join(workspace, "vendor");
    const sub = path.join(vendor, "sub");
    fs.mkdirSync(sub, { recursive: true });
    const layout: SandboxLayout = {
      workspace,
      hostHome: fs.realpathSync.native(os.homedir()),
      writablePaths: [sub],
      readablePaths: [vendor],
    };
    const options = parseOptions({ toolGuard: "enforce" }, workspace);
    const policy = createToolPolicy(
      layout,
      options,
      process.platform === "darwin" ? "darwin" : "linux"
    );
    try {
      const protectedFile = event("edit", ["vendor/keep.txt"]);
      evaluatePermission(protectedFile, policy);
      expect(protectedFile.effect).toBe("deny");

      const explicitWritableChild = event("edit", ["vendor/sub/new.txt"]);
      evaluatePermission(explicitWritableChild, policy);
      expect(explicitWritableChild.effect).toBe("allow");

      const workspaceFile = event("edit", ["src/index.ts"]);
      evaluatePermission(workspaceFile, policy);
      expect(workspaceFile.effect).toBe("allow");
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("denies writes outside the workspace and writable paths", () => {
    const f = fixture();
    try {
      const inside = event("edit", ["src/index.ts"]);
      evaluatePermission(inside, f.policy);
      expect(inside.effect).toBe("allow");

      const outside = event("edit", [path.join(f.layout.hostHome, "notes.txt")]);
      evaluatePermission(outside, f.policy);
      expect(outside.effect).toBe("deny");
      expect(outside.message).toContain("write denied");

      const system = event("edit", ["/etc/hosts"]);
      evaluatePermission(system, f.policy);
      expect(system.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("denies a symlink inside the workspace that points outside", () => {
    const f = fixture();
    try {
      const link = path.join(f.workspace, "escape");
      fs.symlinkSync(path.join(f.layout.hostHome, "secret-outside"), link);
      const denied = event("read", ["escape"]);
      evaluatePermission(denied, f.policy);
      expect(denied.effect).toBe("deny");

      const broken = path.join(f.workspace, "broken");
      fs.symlinkSync(path.join(f.layout.hostHome, "does-not-exist"), broken);
      const brokenRead = event("read", ["broken"]);
      evaluatePermission(brokenRead, f.policy);
      expect(brokenRead.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("treats literal undefined/null search paths as paths, not as absent", () => {
    const f = fixture();
    try {
      fs.symlinkSync(path.join(f.layout.hostHome, "outside"), path.join(f.workspace, "undefined"));
      const grep = event("grep", ["secret"], { path: "undefined" });
      evaluatePermission(grep, f.policy);
      expect(grep.effect).toBe("deny");

      const globMissing = event("glob", ["**/*"], {});
      evaluatePermission(globMissing, f.policy);
      expect(globMissing.effect).toBe("allow");

      expect(() => guardToolInput("grep", { path: "undefined" }, f.policy)).toThrow(/grep denied/);
      expect(() => guardToolInput("glob", { path: "undefined" }, f.policy)).toThrow(/glob denied/);
    } finally {
      f.cleanup();
    }
  });

  test("denies a read that would load a symlinked AGENTS.md", () => {
    const f = fixture();
    const outside = tempDir("osb-tool-instr-");
    const secret = path.join(outside, "secret.txt");
    fs.writeFileSync(secret, "outside");
    fs.mkdirSync(path.join(f.workspace, "sub"), { recursive: true });
    fs.writeFileSync(path.join(f.workspace, "sub", "file.txt"), "ok");
    try {
      fs.symlinkSync(secret, path.join(f.workspace, "sub", "AGENTS.md"));
      const denied = event("read", ["sub/file.txt"]);
      evaluatePermission(denied, f.policy);
      expect(denied.effect).toBe("deny");
      expect(() => guardToolInput("read", { path: "sub/file.txt" }, f.policy, "v2")).toThrow(
        /read denied/
      );

      // A regular workspace AGENTS.md and a link to a readable path stay allowed.
      fs.rmSync(path.join(f.workspace, "sub", "AGENTS.md"));
      fs.writeFileSync(path.join(f.workspace, "sub", "AGENTS.md"), "instructions");
      const regular = event("read", ["sub/file.txt"]);
      evaluatePermission(regular, f.policy);
      expect(regular.effect).toBe("allow");

      fs.rmSync(path.join(f.workspace, "sub", "AGENTS.md"));
      fs.writeFileSync(path.join(f.readable, "AGENTS.md"), "readable");
      fs.symlinkSync(
        path.join(f.readable, "AGENTS.md"),
        path.join(f.workspace, "sub", "AGENTS.md")
      );
      const readable = event("read", ["sub/file.txt"]);
      evaluatePermission(readable, f.policy);
      expect(readable.effect).toBe("allow");
    } finally {
      f.cleanup();
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("ignores instruction files upstream does not load", () => {
    const root = tempDir("osb-tool-worktree-");
    const workspace = path.join(root, "app");
    const lib = path.join(root, "lib");
    fs.mkdirSync(workspace, { recursive: true });
    fs.mkdirSync(lib, { recursive: true });
    fs.writeFileSync(path.join(lib, "file.txt"), "ok");
    const outside = tempDir("osb-tool-instr-");
    const secret = path.join(outside, "secret.txt");
    fs.writeFileSync(secret, "outside");
    // A root AGENTS.md is an ancestor of the location root and is ignored.
    fs.symlinkSync(secret, path.join(root, "AGENTS.md"));
    const layout: SandboxLayout = {
      workspace,
      hostHome: fs.realpathSync.native(os.homedir()),
      writablePaths: [],
      readablePaths: [lib],
    };
    const options = parseOptions({ toolGuard: "enforce", readablePaths: [lib] }, workspace);
    const policy = createToolPolicy(
      layout,
      options,
      process.platform === "darwin" ? "darwin" : "linux"
    );
    try {
      const read = event("read", ["../lib/file.txt"]);
      evaluatePermission(read, policy);
      expect(read.effect).toBe("allow");

      // V1 does not walk instruction files for external or directory reads.
      fs.mkdirSync(path.join(workspace, "sub"), { recursive: true });
      fs.symlinkSync(secret, path.join(workspace, "sub", "CLAUDE.md"));
      expect(() => guardToolInput("read", { filePath: "sub" }, policy)).not.toThrow();
      expect(() =>
        guardToolInput("read", { filePath: path.join(lib, "file.txt") }, policy)
      ).not.toThrow();
      expect(() =>
        guardToolInput("read", { path: path.join(lib, "file.txt") }, policy, "v2")
      ).not.toThrow();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("checks V1 CLAUDE.md and CONTEXT.md instruction files", () => {
    const f = fixture();
    const outside = tempDir("osb-tool-instr-");
    const secret = path.join(outside, "secret.txt");
    fs.writeFileSync(secret, "outside");
    fs.mkdirSync(path.join(f.workspace, "sub"), { recursive: true });
    fs.writeFileSync(path.join(f.workspace, "sub", "file.txt"), "ok");
    try {
      for (const name of ["CLAUDE.md", "CONTEXT.md"]) {
        const link = path.join(f.workspace, "sub", name);
        fs.symlinkSync(secret, link);
        expect(() => guardToolInput("read", { filePath: "sub/file.txt" }, f.policy)).toThrow(
          /read denied/
        );
        fs.rmSync(link);
      }
    } finally {
      f.cleanup();
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("checks V1 non-file instruction targets", () => {
    const f = fixture();
    fs.mkdirSync(path.join(f.workspace, "sub"), { recursive: true });
    fs.writeFileSync(path.join(f.workspace, "sub", "file.txt"), "ok");
    try {
      fs.symlinkSync("/dev/null", path.join(f.workspace, "sub", "AGENTS.md"));
      expect(() => guardToolInput("read", { filePath: "sub/file.txt" }, f.policy)).toThrow(
        /read denied/
      );
    } finally {
      f.cleanup();
    }
  });

  test("checks V1 lexical instruction levels across a re-entering symlink", () => {
    const base = tempDir("osb-v1leak-");
    const workspace = path.join(base, "repo", "sub");
    fs.mkdirSync(workspace, { recursive: true });
    fs.symlinkSync("../..", path.join(workspace, "up"));
    fs.writeFileSync(path.join(workspace, "file.txt"), "ok");
    const outside = tempDir("osb-v1leak-secret-");
    const secret = path.join(outside, "secret.txt");
    fs.writeFileSync(secret, "outside");
    fs.symlinkSync(secret, path.join(base, "AGENTS.md"));
    const layout: SandboxLayout = {
      workspace: fs.realpathSync.native(workspace),
      hostHome: fs.realpathSync.native(os.homedir()),
      writablePaths: [],
      readablePaths: [],
    };
    const options = parseOptions({ toolGuard: "enforce" }, layout.workspace);
    const policy = createToolPolicy(
      layout,
      options,
      process.platform === "darwin" ? "darwin" : "linux"
    );
    try {
      expect(() => guardToolInput("read", { filePath: "up/repo/sub/file.txt" }, policy)).toThrow(
        /read denied/
      );
    } finally {
      fs.rmSync(base, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("checks instruction files outside location.directory but inside the readable root", () => {
    const root = tempDir("osb-tool-worktree-");
    const workspace = path.join(root, "proj");
    const sibling = path.join(root, "sibling");
    const outside = tempDir("osb-tool-instr-");
    const secret = path.join(outside, "secret.txt");
    fs.mkdirSync(workspace, { recursive: true });
    fs.mkdirSync(sibling, { recursive: true });
    fs.writeFileSync(path.join(sibling, "file.txt"), "ok");
    fs.writeFileSync(secret, "outside");
    fs.symlinkSync(secret, path.join(sibling, "AGENTS.md"));
    const layout: SandboxLayout = {
      workspace,
      hostHome: fs.realpathSync.native(os.homedir()),
      writablePaths: [],
      readablePaths: [root],
    };
    const options = parseOptions({ toolGuard: "enforce", readablePaths: [root] }, workspace);
    const policy = createToolPolicy(
      layout,
      options,
      process.platform === "darwin" ? "darwin" : "linux"
    );
    try {
      const read = event("read", ["../sibling/file.txt"]);
      evaluatePermission(read, policy);
      expect(read.effect).toBe("deny");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("allows a symlink inside the workspace that points to a readable path", () => {
    const f = fixture();
    try {
      fs.writeFileSync(path.join(f.readable, "notes.txt"), "safe");
      fs.symlinkSync(path.join(f.readable, "notes.txt"), path.join(f.workspace, "notes-link"));
      const allowed = event("read", ["notes-link"]);
      evaluatePermission(allowed, f.policy);
      expect(allowed.effect).toBe("allow");
    } finally {
      f.cleanup();
    }
  });

  test("denies parent traversal and exact outside reads; external approval is left upstream", () => {
    const f = fixture({}, outsideBase());
    const outside = tempDir("osb-tool-out-");
    const secret = path.join(outside, "secret.txt");
    fs.writeFileSync(secret, "outside");
    try {
      const traversal = event("read", ["../outside.txt"]);
      evaluatePermission(traversal, f.policy);
      expect(traversal.effect).toBe("deny");

      // The guard does not auto-approve or deny the external-directory prompt;
      // the exact read is the boundary.
      const external = event("external_directory", [`${outside}/*`]);
      evaluatePermission(external, f.policy);
      expect(external.effect).toBe("allow");

      const forced = event("read", [secret]);
      evaluatePermission(forced, f.policy);
      expect(forced.effect).toBe("deny");

      const credential = event("read", [path.join(f.layout.hostHome, ".ssh", "id_rsa")]);
      evaluatePermission(credential, f.policy);
      expect(credential.effect).toBe("deny");
    } finally {
      f.cleanup();
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("rejects a temp root symlinked into a home subdirectory", () => {
    const f = fixture();
    const base = tempDir("osb-tool-tmp-anc-");
    const fakeHome = path.join(base, "home");
    fs.mkdirSync(path.join(fakeHome, ".ssh"), { recursive: true });
    const previous = process.env.TMPDIR;
    try {
      fs.symlinkSync(path.join(fakeHome, ".ssh"), path.join(base, "opencode"));
      process.env.TMPDIR = base;
      const layout = { ...f.layout, hostHome: fakeHome };
      const policy = createToolPolicy(layout, f.options, "linux");
      expect(policy.readRoots).not.toContain(path.join(fakeHome, ".ssh"));

      const denied = event("read", [path.join(fakeHome, ".ssh", "id_rsa")]);
      evaluatePermission(denied, policy);
      expect(denied.effect).toBe("deny");
    } finally {
      if (previous === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previous;
      f.cleanup();
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("does not use a TMPDIR inside the host home as a read root", () => {
    const f = fixture();
    const previous = process.env.TMPDIR;
    try {
      process.env.TMPDIR = f.layout.hostHome;
      const policy = createToolPolicy(f.layout, f.options, "linux");
      expect(policy.readRoots).not.toContain(f.layout.hostHome);
      expect(policy.readRoots).not.toContain(path.join(f.layout.hostHome, ".ssh"));
    } finally {
      if (previous === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previous;
      f.cleanup();
    }
  });

  test("allows OpenCode's temp directory for generated images", () => {
    const f = fixture();
    try {
      const image = event("read", [
        path.join(os.tmpdir(), "opencode", "images", "session", "image.png"),
      ]);
      evaluatePermission(image, f.policy);
      expect(image.effect).toBe("allow");
    } finally {
      f.cleanup();
    }
  });

  test("does not follow a symlinked OpenCode temp root outside the temp base", () => {
    const f = fixture();
    const base = tempDir("osb-tool-tmp-");
    const previous = process.env.TMPDIR;
    try {
      fs.symlinkSync("/", path.join(base, "opencode"));
      process.env.TMPDIR = base;
      const policy = createToolPolicy(f.layout, f.options, "linux");
      expect(policy.readRoots).not.toContain("/");

      const denied = event("read", [path.join(f.layout.hostHome, ".ssh", "id_rsa")]);
      evaluatePermission(denied, policy);
      expect(denied.effect).toBe("deny");

      // A link back to the temp base must not widen reads to the whole base.
      fs.rmSync(path.join(base, "opencode"));
      fs.symlinkSync(base, path.join(base, "opencode"));
      const sameBase = createToolPolicy(f.layout, f.options, "linux");
      expect(sameBase.readRoots).not.toContain(base);
      const sibling = event("read", [path.join(base, "sibling.txt")]);
      evaluatePermission(sibling, sameBase);
      expect(sibling.effect).toBe("deny");
    } finally {
      if (previous === undefined) delete process.env.TMPDIR;
      else process.env.TMPDIR = previous;
      f.cleanup();
      fs.rmSync(base, { recursive: true, force: true });
    }
  });

  test("supports a file-valued readable path without approving its siblings", () => {
    const workspace = tempDir();
    const dir = tempDir("osb-tool-file-");
    const file = path.join(dir, "allowed.txt");
    fs.writeFileSync(file, "ok");
    fs.writeFileSync(path.join(dir, "sibling.txt"), "no");
    const layout: SandboxLayout = {
      workspace,
      hostHome: fs.realpathSync.native(os.homedir()),
      writablePaths: [],
      readablePaths: [file],
    };
    const options = parseOptions({ toolGuard: "enforce" }, workspace);
    const policy = createToolPolicy(
      layout,
      options,
      process.platform === "darwin" ? "darwin" : "linux"
    );
    try {
      const approval = event("external_directory", [`${dir}/*`]);
      evaluatePermission(approval, policy);
      expect(approval.effect).toBe("allow");

      const allowed = event("read", [file]);
      evaluatePermission(allowed, policy);
      expect(allowed.effect).toBe("allow");

      const sibling = event("read", [path.join(dir, "sibling.txt")]);
      evaluatePermission(sibling, policy);
      expect(sibling.effect).toBe("deny");
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test("uses a narrower Darwin tool read set without broad temp or device roots", () => {
    const f = fixture();
    try {
      const policy = createToolPolicy(f.layout, f.options, "darwin");
      expect(policy.readRoots).not.toContain("/dev");
      expect(policy.readRoots).not.toContain("/var/folders");
      const temp = event("read", ["/var/tmp/secret"]);
      evaluatePermission(temp, policy);
      expect(temp.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("allows OpenCode's retained tool-output directory only", () => {
    const workspace = tempDir();
    const fakeHome = tempDir("osb-tool-home-");
    const data = path.join(fakeHome, ".local", "share");
    const base = path.join(data, "opencode");
    const output = path.join(base, "tool-output", "tool_abc.txt");
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, "ok");
    const layout: SandboxLayout = {
      workspace,
      hostHome: fakeHome,
      writablePaths: [],
      readablePaths: [],
    };
    const options = parseOptions({ toolGuard: "enforce" }, workspace);
    const previous = process.env.XDG_DATA_HOME;
    try {
      delete process.env.XDG_DATA_HOME;
      const policy = createToolPolicy(layout, options, "linux");

      const allowed = event("read", [output]);
      evaluatePermission(allowed, policy);
      expect(allowed.effect).toBe("allow");

      const sibling = event("read", [path.join(base, "auth.json")]);
      evaluatePermission(sibling, policy);
      expect(sibling.effect).toBe("deny");
    } finally {
      if (previous === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = previous;
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(fakeHome, { recursive: true, force: true });
    }
  });

  test("does not follow an opencode data symlink into home credentials", () => {
    const workspace = tempDir();
    const fakeHome = tempDir("osb-tool-home-");
    const data = path.join(fakeHome, ".local", "share");
    fs.mkdirSync(data, { recursive: true });
    fs.mkdirSync(path.join(fakeHome, ".ssh"), { recursive: true });
    fs.symlinkSync(path.join(fakeHome, ".ssh"), path.join(data, "opencode"));
    const layout: SandboxLayout = {
      workspace,
      hostHome: fakeHome,
      writablePaths: [],
      readablePaths: [],
    };
    const options = parseOptions({ toolGuard: "enforce" }, workspace);
    const previous = process.env.XDG_DATA_HOME;
    try {
      delete process.env.XDG_DATA_HOME;
      const policy = createToolPolicy(layout, options, "linux");
      expect(policy.readRoots).not.toContain(path.join(fakeHome, ".ssh", "tool-output"));
      const denied = event("read", [path.join(fakeHome, ".ssh", "id_rsa")]);
      evaluatePermission(denied, policy);
      expect(denied.effect).toBe("deny");
    } finally {
      if (previous === undefined) delete process.env.XDG_DATA_HOME;
      else process.env.XDG_DATA_HOME = previous;
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(fakeHome, { recursive: true, force: true });
    }
  });

  test("resolves relative search paths against the lexical session directory", () => {
    const root = tempDir("osb-base-");
    const real = path.join(root, "ro", "proj");
    fs.mkdirSync(real, { recursive: true });
    const link = path.join(root, "link");
    fs.symlinkSync(real, link);
    const layout: SandboxLayout = {
      workspace: fs.realpathSync.native(real),
      hostHome: fs.realpathSync.native(os.homedir()),
      writablePaths: [],
      readablePaths: [fs.realpathSync.native(path.join(root, "ro"))],
    };
    const options = parseOptions(
      { toolGuard: "enforce", readablePaths: [path.join(root, "ro")] },
      layout.workspace
    );
    const policy = createToolPolicy(
      layout,
      options,
      process.platform === "darwin" ? "darwin" : "linux",
      link
    );
    try {
      // The tool resolves `link/..` lexically to the symlink's parent; the
      // guard must check the same directory, not the canonical project parent.
      const outside = event("glob", ["**/*"], { path: ".." });
      evaluatePermission(outside, policy);
      expect(outside.effect).toBe("deny");

      const inside = event("grep", ["needle"], { path: "proj" });
      evaluatePermission(inside, policy);
      expect(inside.effect).toBe("allow");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  test("checks the search root for glob and grep", () => {
    const f = fixture();
    try {
      const inside = event("glob", ["**/*.ts"], { path: "src" });
      evaluatePermission(inside, f.policy);
      expect(inside.effect).toBe("allow");

      const outside = event("grep", ["secret"], { path: f.layout.hostHome });
      evaluatePermission(outside, f.policy);
      expect(outside.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("enforces webfetch allow, deny and allowlist modes", () => {
    const f = fixture();
    try {
      const allowed = event("webfetch", ["https://example.com/docs"]);
      evaluatePermission(allowed, f.policy);
      expect(allowed.effect).toBe("allow");

      const ftp = event("webfetch", ["ftp://example.com/docs"]);
      evaluatePermission(ftp, f.policy);
      expect(ftp.effect).toBe("deny");
    } finally {
      f.cleanup();
    }

    const denied = fixture({ webfetch: "deny" });
    try {
      const eventDenied = event("webfetch", ["https://example.com"]);
      evaluatePermission(eventDenied, denied.policy);
      expect(eventDenied.effect).toBe("deny");
    } finally {
      denied.cleanup();
    }

    const listed = fixture({ webfetchAllowlist: ["*.example.com"] });
    try {
      for (const url of ["https://example.com", "https://api.example.com"]) {
        const allowedHost = event("webfetch", [url]);
        evaluatePermission(allowedHost, listed.policy);
        expect(allowedHost.effect).toBe("allow");
      }
      for (const url of ["https://evil-example.com", "https://example.com.evil.net"]) {
        const blockedHost = event("webfetch", [url]);
        evaluatePermission(blockedHost, listed.policy);
        expect(blockedHost.effect).toBe("deny");
      }
    } finally {
      listed.cleanup();
    }
  });

  test("fails closed for a malformed direct webfetch allowlist", () => {
    const f = fixture();
    try {
      const policy = createToolPolicy(
        f.layout,
        { ...f.options, webfetchAllowlist: ["*"] },
        process.platform === "darwin" ? "darwin" : "linux"
      );
      expect(policy.webfetch).toBe("deny");
      const request = event("webfetch", ["https://example.com"]);
      evaluatePermission(request, policy);
      expect(request.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("fails closed for a non-array direct webfetch allowlist", () => {
    const f = fixture();
    try {
      const policy = createToolPolicy(
        f.layout,
        {
          ...f.options,
          webfetchAllowlist: "localhost" as unknown as string[],
        },
        process.platform === "darwin" ? "darwin" : "linux"
      );
      expect(policy.webfetch).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("allows the schedule tool-selection sentinel for webfetch", () => {
    const f = fixture();
    try {
      const sentinel = event("webfetch", ["*"]);
      evaluatePermission(sentinel, f.policy);
      expect(sentinel.effect).toBe("allow");
    } finally {
      f.cleanup();
    }

    const listed = fixture({ webfetchAllowlist: ["example.com"] });
    try {
      const sentinel = event("webfetch", ["*"]);
      evaluatePermission(sentinel, listed.policy);
      expect(sentinel.effect).toBe("allow");
    } finally {
      listed.cleanup();
    }

    const denied = fixture({ webfetch: "deny" });
    try {
      const sentinel = event("webfetch", ["*"]);
      evaluatePermission(sentinel, denied.policy);
      expect(sentinel.effect).toBe("deny");
    } finally {
      denied.cleanup();
    }
  });

  test("does not weaken an existing deny or unknown action", () => {
    const f = fixture();
    try {
      const deny = event("read", ["AGENTS.md"]);
      deny.effect = "deny";
      deny.message = "upstream deny";
      evaluatePermission(deny, f.policy);
      expect(deny.message).toBe("upstream deny");

      const unknown = event("websearch", ["anything"]);
      evaluatePermission(unknown, f.policy);
      expect(unknown.effect).toBe("allow");
    } finally {
      f.cleanup();
    }
  });
});

describe("guardToolInput", () => {
  test("guards V1 file paths and patch targets", () => {
    const f = fixture();
    try {
      expect(() => guardToolInput("read", { filePath: "AGENTS.md" }, f.policy)).not.toThrow();
      expect(() =>
        guardToolInput("read", { filePath: path.join(f.layout.hostHome, "secret") }, f.policy)
      ).toThrow(/read denied/);
      expect(() =>
        guardToolInput("write", { filePath: path.join(f.layout.hostHome, "out") }, f.policy)
      ).toThrow(/write denied/);

      const patch = [
        "*** Begin Patch",
        "*** Add File: src/new.ts",
        "+export {}",
        `*** Update File: ${path.join(f.layout.hostHome, "outside.ts")}`,
        "@@",
        "-a",
        "+b",
        "*** End Patch",
      ].join("\n");
      expect(() => guardToolInput("patch", { patchText: patch }, f.policy)).toThrow(/patch denied/);

      // V1 registers apply_patch and uses a prefix/trim parser: tab and no
      // space after the colon are valid.
      for (const header of ["*** Add File:\t", "*** Add File:"]) {
        const text = `${header}${path.join(f.layout.hostHome, "outside.ts")}\n+export {}`;
        expect(() => guardToolInput("apply_patch", { patchText: text }, f.policy)).toThrow(
          /apply_patch denied/
        );
      }
      expect(() =>
        guardToolInput(
          "apply_patch",
          { patchText: "*** Add File: src/new.ts\n+export {}" },
          f.policy
        )
      ).not.toThrow();
    } finally {
      f.cleanup();
    }
  });

  test("resolves V1 absolute paths in kernel order across symlinks", () => {
    const f = fixture();
    try {
      fs.symlinkSync(".", path.join(f.workspace, "link"));
      // Do not use path.join here: it collapses `..` before the guard sees it.
      const escapedPath = `${f.workspace}/link/../outside.txt`;
      expect(() => guardToolInput("read", { filePath: escapedPath }, f.policy)).toThrow(
        /read denied/
      );
      expect(() => guardToolInput("write", { filePath: escapedPath }, f.policy)).toThrow(
        /write denied/
      );
      expect(() => guardToolInput("glob", { path: `${f.workspace}/link/..` }, f.policy)).toThrow(
        /glob denied/
      );
    } finally {
      f.cleanup();
    }
  });

  test("resolves a V2 absolute path across a workspace symlink", () => {
    const f = fixture();
    try {
      fs.symlinkSync(".", path.join(f.workspace, "link"));
      const denied = event("read", [`${f.workspace}/link/../outside.txt`]);
      evaluatePermission(denied, f.policy);
      expect(denied.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("checks lexical and kernel targets for V1 absolute paths", () => {
    const f = fixture();
    try {
      fs.mkdirSync(path.join(f.workspace, "a", "b"), { recursive: true });
      fs.symlinkSync(path.join("a", "b"), path.join(f.workspace, "s"));
      const raw = `${f.workspace}/s/../../outside`;
      expect(() => guardToolInput("read", { filePath: raw }, f.policy)).toThrow(/read denied/);
      expect(() => guardToolInput("write", { filePath: raw }, f.policy)).toThrow(/write denied/);
      expect(() => guardToolInput("grep", { path: raw }, f.policy)).toThrow(/grep denied/);
      expect(() =>
        guardToolInput("apply_patch", { patchText: `*** Add File: ${raw}` }, f.policy)
      ).toThrow(/apply_patch denied/);
    } finally {
      f.cleanup();
    }
  });

  test("checks lexical and kernel targets for V2 absolute paths", () => {
    const f = fixture();
    try {
      fs.mkdirSync(path.join(f.workspace, "a", "b"), { recursive: true });
      fs.symlinkSync(path.join("a", "b"), path.join(f.workspace, "s"));
      const raw = `${f.workspace}/s/../../outside`;
      const denied = event("read", [raw]);
      evaluatePermission(denied, f.policy);
      expect(denied.effect).toBe("deny");
    } finally {
      f.cleanup();
    }
  });

  test("uses V2 argument semantics for the pre-execution guard", () => {
    const f = fixture();
    try {
      fs.symlinkSync(path.join(f.layout.hostHome, "outside"), path.join(f.workspace, "undefined"));

      // V2 glob normalizes "undefined"; V2 grep treats it as a literal path.
      expect(() => guardToolInput("glob", { path: "undefined" }, f.policy, "v2")).not.toThrow();
      expect(() => guardToolInput("grep", { path: "undefined" }, f.policy, "v2")).toThrow(
        /grep denied/
      );

      const outside = path.join(f.layout.hostHome, "outside");
      expect(() => guardToolInput("read", { path: outside }, f.policy, "v2")).toThrow(
        /read denied/
      );
      expect(() =>
        guardToolInput("patch", { patchText: `*** Add File: ${outside}` }, f.policy, "v2")
      ).toThrow(/patch denied/);

      // V2 ignores a stale filePath key; the guard must follow `path`.
      expect(() =>
        guardToolInput("write", { filePath: "AGENTS.md", path: outside }, f.policy, "v2")
      ).toThrow(/write denied/);

      // V2 patch trims the header line before matching.
      expect(() =>
        guardToolInput("patch", { patchText: ` *** Add File: ${outside}` }, f.policy, "v2")
      ).toThrow(/patch denied/);

      // V1 uses filePath, so the same conflicting object is an inside write.
      expect(() =>
        guardToolInput("write", { filePath: "AGENTS.md", path: outside }, f.policy, "v1")
      ).not.toThrow();
    } finally {
      f.cleanup();
    }
  });

  test("resolves V1 tilde literally, matching the tool", () => {
    const f = fixture();
    try {
      // V1 treats `~` as a literal directory name and resolves against the
      // workspace; this traversal must not be checked as the host home.
      expect(() => guardToolInput("read", { filePath: "~/../../etc/passwd" }, f.policy)).toThrow(
        /read denied/
      );
      expect(() => guardToolInput("read", { filePath: "~/notes.txt" }, f.policy)).not.toThrow();
    } finally {
      f.cleanup();
    }
  });

  test("guards V1 search paths and webfetch hosts", () => {
    const f = fixture({ webfetchAllowlist: ["example.com"] });
    try {
      expect(() => guardToolInput("glob", { path: "src" }, f.policy)).not.toThrow();
      expect(() => guardToolInput("grep", { path: f.layout.hostHome }, f.policy)).toThrow(
        /grep denied/
      );
      expect(() =>
        guardToolInput("webfetch", { url: "https://example.com" }, f.policy)
      ).not.toThrow();
      expect(() => guardToolInput("webfetch", { url: "https://evil.net" }, f.policy)).toThrow(
        /webfetch denied/
      );
    } finally {
      f.cleanup();
    }
  });

  test("leaves tools with missing arguments to OpenCode validation", () => {
    const f = fixture();
    try {
      expect(() => guardToolInput("read", { command: "echo" }, f.policy)).not.toThrow();
      expect(() => guardToolInput("patch", {}, f.policy)).not.toThrow();
      expect(() => guardToolInput("webfetch", {}, f.policy)).not.toThrow();
    } finally {
      f.cleanup();
    }
  });
});
