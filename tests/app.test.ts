import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSandbox, type ShellCreateEvent } from "../src/app.ts";
import { resolveSandboxBinary } from "../src/binary.ts";
import { parseOptions, parseOptionsSafe } from "../src/options.ts";
import { probe } from "../src/probe.ts";
import type { PermissionEvaluation } from "../src/tool-policy.ts";

function tempDir(prefix = "osb-app-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function fakeShell() {
  let callback: ((event: ShellCreateEvent) => Promise<void> | void) | undefined;
  const context = {
    shell: {
      hook: async (
        _name: "create.before",
        fn: (event: ShellCreateEvent) => Promise<void> | void
      ) => {
        callback = fn;
        return { dispose: async () => {} };
      },
    },
  };
  return { context, get: () => callback };
}

function fakeTool() {
  const callbacks: Array<(event: { tool: string; input?: unknown }) => Promise<void> | void> = [];
  let disposed = false;
  const context = {
    tool: {
      hook: async (
        _name: "execute.before",
        fn: (event: { tool: string; input?: unknown }) => Promise<void> | void
      ) => {
        callbacks.push(fn);
        return {
          dispose: async () => {
            disposed = true;
          },
        };
      },
    },
  };
  return {
    context,
    get: () =>
      callbacks.length === 0
        ? undefined
        : (event: { tool: string; input?: unknown }) => {
            for (const callback of callbacks) callback(event);
          },
    disposed: () => disposed,
  };
}

function fakePermission() {
  let callback: ((event: PermissionEvaluation) => Promise<void> | void) | undefined;
  let disposed = false;
  const context = {
    permission: {
      hook: async (
        _name: "evaluate",
        fn: (event: PermissionEvaluation) => Promise<void> | void
      ) => {
        callback = fn;
        return {
          dispose: async () => {
            disposed = true;
          },
        };
      },
    },
  };
  return { context, get: () => callback, disposed: () => disposed };
}

const platform = process.platform === "darwin" ? "darwin" : "linux";
const binary = resolveSandboxBinary(platform);
const required =
  platform === "linux"
    ? process.env.SANDBOX_REQUIRE_BWRAP === "1"
    : process.env.SANDBOX_REQUIRE_SANDBOX_EXEC === "1";
const available = binary.ok ? (await probe(platform, binary.path)).available : false;
const runnable = available || required;

function options(workspace: string, overrides: Record<string, unknown> = {}) {
  // Existing tests exercise the shell boundary; tool-guard tests opt in.
  return parseOptions({ toolGuard: "off", ...overrides }, workspace);
}

describe("createSandbox", () => {
  test("replaces only the shell executable and keeps the command", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const fake = fakeShell();
    const app = await createSandbox(
      { location: { directory: workspace }, ...fake.context },
      options(workspace)
    );
    try {
      const callback = fake.get();
      expect(callback).toBeDefined();
      const event: ShellCreateEvent = {
        command: "printf original",
        cwd: workspace,
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      await callback?.(event);
      expect(event.command).toBe("printf original");
      expect(event.cwd).toBe(workspace);
      expect(event.shell).not.toBe("/bin/bash");
      expect(event.shell.startsWith("/")).toBe(true);
      expect(fs.statSync(event.shell).mode & 0o111).toBeGreaterThan(0);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("rejects a working directory outside the workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const fake = fakeShell();
    const app = await createSandbox(
      { location: { directory: workspace }, ...fake.context },
      options(workspace)
    );
    try {
      const callback = fake.get();
      const event: ShellCreateEvent = {
        command: "pwd",
        cwd: os.tmpdir(),
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      expect(() => callback?.(event)).toThrow(/outside/);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed when the workspace is the host home", async () => {
    const fake = fakeShell();
    const home = os.homedir();
    const app = await createSandbox(
      { location: { directory: home }, ...fake.context },
      options(home)
    );
    try {
      const callback = fake.get();
      const event: ShellCreateEvent = {
        command: "true",
        cwd: home,
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      expect(() => callback?.(event)).toThrow(/host home/);
    } finally {
      app.dispose();
    }
  });

  test("uses the tool hook as a fail-closed fallback", async () => {
    const fake = fakeTool();
    const home = os.homedir();
    const app = await createSandbox(
      { location: { directory: home }, ...fake.context },
      options(home)
    );
    try {
      const callback = fake.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "shell" })).toThrow(/refusing to run/);
      expect(() => callback?.({ tool: "read" })).not.toThrow();
      expect(() => callback?.({ tool: "webfetch" })).not.toThrow();
    } finally {
      app.dispose();
    }
  });

  test("blocks guarded tools on layout failure when toolGuard is enforced", async () => {
    const tool = fakeTool();
    const home = os.homedir();
    const app = await createSandbox(
      { location: { directory: home }, ...tool.context },
      options(home, { toolGuard: "enforce" })
    );
    try {
      const callback = tool.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "shell" })).toThrow(/refusing to run/);
      expect(() => callback?.({ tool: "read" })).toThrow(/refusing/);
      expect(() => callback?.({ tool: "webfetch" })).toThrow(/refusing/);
    } finally {
      app.dispose();
    }
  });

  test("uses a deny-all permission guard on layout failure", async () => {
    const shell = fakeShell();
    const permission = fakePermission();
    const home = os.homedir();
    const app = await createSandbox(
      {
        location: { directory: home },
        ...shell.context,
        ...permission.context,
      },
      options(home, { toolGuard: "enforce" })
    );
    try {
      expect(shell.get()).toBeDefined();
      const guard = permission.get();
      expect(guard).toBeDefined();
      for (const action of ["read", "edit", "glob", "grep", "webfetch", "image_generate"]) {
        const evaluation: PermissionEvaluation = {
          action,
          resources: ["*"],
          effect: "allow",
        };
        guard?.(evaluation);
        expect(evaluation.effect).toBe("deny");
      }
      const other: PermissionEvaluation = {
        action: "websearch",
        resources: ["query"],
        effect: "allow",
      };
      guard?.(other);
      expect(other.effect).toBe("allow");
    } finally {
      app.dispose();
    }
  });

  test("falls back to the tool hook when the layout fails", async () => {
    const tool = fakeTool();
    const home = os.homedir();
    const app = await createSandbox(
      {
        location: { directory: home },
        shell: {
          hook: async () => {
            throw new Error("shell surface broke");
          },
        },
        ...tool.context,
      },
      options(home)
    );
    try {
      const callback = tool.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "shell" })).toThrow(/refusing to run/);
      expect(() => callback?.({ tool: "read" })).not.toThrow();
    } finally {
      app.dispose();
    }
  });

  test("fails closed when shell hook registration fails on a valid workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const tool = fakeTool();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        shell: {
          hook: async () => {
            throw new Error("shell surface broke");
          },
        },
        ...tool.context,
      },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      const callback = tool.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "shell" })).toThrow(/refusing to run/);
      expect(() => callback?.({ tool: "read" })).toThrow(/refusing/);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("registers a V2 pre-execution check before file tools read", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const outside = tempDir("osb-app-out-");
    const secret = path.join(outside, "secret.txt");
    fs.writeFileSync(secret, "outside");
    fs.symlinkSync(secret, path.join(workspace, "link"));
    const shell = fakeShell();
    const permission = fakePermission();
    const tool = fakeTool();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...permission.context,
        ...tool.context,
      },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      const callback = tool.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "read", input: { path: "link" } })).toThrow(/read denied/);
      expect(() => callback?.({ tool: "write", input: { path: "link" } })).toThrow(/write denied/);
      expect(() => callback?.({ tool: "edit", input: { path: "link" } })).toThrow(/edit denied/);
      expect(() =>
        callback?.({
          tool: "patch",
          input: { patchText: " *** Update File: link" },
        })
      ).toThrow(/patch denied/);
      expect(() => callback?.({ tool: "read", input: { path: "AGENTS.md" } })).not.toThrow();
      expect(permission.get()).toBeDefined();
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("resolves V2 relative search paths against the lexical location", async () => {
    if (!runnable) return;
    const real = tempDir("osb-app-real-");
    const link = `${real}-link`;
    fs.symlinkSync(real, link);
    const shell = fakeShell();
    const permission = fakePermission();
    const app = await createSandbox(
      {
        location: { directory: link },
        ...shell.context,
        ...permission.context,
      },
      options(real, { toolGuard: "enforce" })
    );
    try {
      const guard = permission.get();
      expect(guard).toBeDefined();
      const outside: PermissionEvaluation = {
        action: "grep",
        resources: ["secret"],
        metadata: { path: ".." },
        effect: "allow",
      };
      guard?.(outside);
      expect(outside.effect).toBe("deny");

      const inside: PermissionEvaluation = {
        action: "grep",
        resources: ["needle"],
        metadata: { path: "." },
        effect: "allow",
      };
      guard?.(inside);
      expect(inside.effect).toBe("allow");
    } finally {
      app.dispose();
      fs.rmSync(real, { recursive: true, force: true });
      fs.rmSync(link, { force: true });
    }
  });

  test("keeps the tool policy when only the shell hook fails", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const tool = fakeTool();
    const permission = fakePermission();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        shell: {
          hook: async () => {
            throw new Error("shell surface broke");
          },
        },
        ...tool.context,
        ...permission.context,
      },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      const guard = permission.get();
      expect(guard).toBeDefined();
      const inside: PermissionEvaluation = {
        action: "read",
        resources: ["AGENTS.md"],
        effect: "allow",
      };
      guard?.(inside);
      expect(inside.effect).toBe("allow");
      const outside: PermissionEvaluation = {
        action: "read",
        resources: [path.join(os.homedir(), ".ssh", "id_rsa")],
        effect: "allow",
      };
      guard?.(outside);
      expect(outside.effect).toBe("deny");

      const callback = tool.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "shell" })).toThrow(/refusing to run/);
      expect(() => callback?.({ tool: "read" })).not.toThrow();
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("honors permissive mode when shell hook registration fails", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const tool = fakeTool();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        shell: {
          hook: async () => {
            throw new Error("shell surface broke");
          },
        },
        ...tool.context,
      },
      options(workspace, { toolGuard: "enforce", mode: "permissive" })
    );
    try {
      await Bun.sleep(0);
      expect(tool.disposed()).toBe(true);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed when the generated wrapper cannot run", async () => {
    const workspace = tempDir();
    const fake = fakeShell();
    const app = await createSandbox(
      { location: { directory: workspace }, ...fake.context },
      options(workspace, { shell: "/definitely/not/a/shell" })
    );
    try {
      const callback = fake.get();
      expect(callback).toBeDefined();
      const event: ShellCreateEvent = {
        command: "true",
        cwd: workspace,
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      expect(() => callback?.(event)).toThrow(/refusing to run/);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("throws when no hook surface can enforce the refusal", async () => {
    const home = os.homedir();
    await expect(createSandbox({ location: { directory: home } }, options(home))).rejects.toThrow(
      /enforceable shell or tool hook/
    );
  });

  test("permissive mode warns and leaves commands unsandboxed", async () => {
    const fake = fakeShell();
    const home = os.homedir();
    const app = await createSandbox(
      { location: { directory: home }, ...fake.context },
      options(home, { mode: "permissive" })
    );
    try {
      expect(fake.get()).toBeUndefined();
    } finally {
      app.dispose();
    }
  });

  test("registers a V2 tool guard and keeps reads inside the workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const permission = fakePermission();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...permission.context,
      },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      const guard = permission.get();
      expect(guard).toBeDefined();

      const inside: PermissionEvaluation = {
        action: "read",
        resources: ["AGENTS.md"],
        effect: "allow",
      };
      guard?.(inside);
      expect(inside.effect).toBe("allow");

      const outside: PermissionEvaluation = {
        action: "read",
        resources: [path.join(os.homedir(), ".ssh", "id_rsa")],
        effect: "allow",
      };
      guard?.(outside);
      expect(outside.effect).toBe("deny");
      expect(outside.message).toContain("read denied");

      const shellEvent: ShellCreateEvent = {
        command: "printf both",
        cwd: workspace,
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      await shell.get()?.(shellEvent);
      expect(shellEvent.shell).not.toBe("/bin/bash");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("enforces the webfetch host allowlist through the tool guard", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const permission = fakePermission();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...permission.context,
      },
      options(workspace, {
        toolGuard: "enforce",
        webfetchAllowlist: ["example.com"],
      })
    );
    try {
      const guard = permission.get();
      const allowed: PermissionEvaluation = {
        action: "webfetch",
        resources: ["https://example.com/docs"],
        effect: "allow",
      };
      guard?.(allowed);
      expect(allowed.effect).toBe("allow");

      const evilHost: PermissionEvaluation = {
        action: "webfetch",
        resources: ["https://evil.example.net/collect"],
        effect: "allow",
      };
      guard?.(evilHost);
      expect(evilHost.effect).toBe("deny");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("keeps the shell sandbox and blocks guarded tools without a permission hook", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const tool = fakeTool();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...tool.context,
      },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      const shellCallback = shell.get();
      expect(shellCallback).toBeDefined();
      const event: ShellCreateEvent = {
        command: "printf ok",
        cwd: workspace,
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      await shellCallback?.(event);
      expect(event.shell).not.toBe("/bin/bash");

      const toolCallback = tool.get();
      expect(toolCallback).toBeDefined();
      expect(() => toolCallback?.({ tool: "read" })).toThrow(/refusing/);
      expect(() => toolCallback?.({ tool: "webfetch" })).toThrow(/refusing/);
      expect(() => toolCallback?.({ tool: "todo" })).not.toThrow();
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("falls back to the blocking tool hook when permission registration fails", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const tool = fakeTool();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...tool.context,
        permission: {
          hook: async () => {
            throw new Error("permission surface broke");
          },
        },
      },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      expect(shell.get()).toBeDefined();
      const callback = tool.get();
      expect(callback).toBeDefined();
      expect(() => callback?.({ tool: "read" })).toThrow(/refusing/);
      expect(() => callback?.({ tool: "image_generate" })).toThrow(/refusing/);
      expect(() => callback?.({ tool: "worktree_remove" })).toThrow(/refusing/);
      expect(() => callback?.({ tool: "todo" })).not.toThrow();
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("keeps the shell sandbox when options needed a secure fallback", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const permission = fakePermission();
    const parsed = parseOptionsSafe(
      { toolGuard: "enforce", webfetchAllowlist: "https://example.com" },
      workspace
    );
    expect(parsed.errors.length).toBe(1);
    expect(parsed.options.webfetch).toBe("deny");

    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...permission.context,
      },
      parsed.options
    );
    try {
      expect(shell.get()).toBeDefined();
      expect(permission.get()).toBeDefined();
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("keeps the shell sandbox when no tool-guard hook exists", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const app = await createSandbox(
      { location: { directory: workspace }, ...shell.context },
      options(workspace, { toolGuard: "enforce" })
    );
    try {
      const callback = shell.get();
      expect(callback).toBeDefined();
      const event: ShellCreateEvent = {
        command: "printf ok",
        cwd: workspace,
        timeout: 0,
        shell: "/bin/bash",
        env: {},
      };
      await callback?.(event);
      expect(event.shell).not.toBe("/bin/bash");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("disposes the permission guard with the sandbox", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const permission = fakePermission();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...permission.context,
      },
      options(workspace, { toolGuard: "enforce" })
    );
    app.dispose();
    await Bun.sleep(0);
    expect(permission.disposed()).toBe(true);
    fs.rmSync(workspace, { recursive: true, force: true });
  });

  test("does not register a tool guard when toolGuard is off", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const shell = fakeShell();
    const permission = fakePermission();
    const app = await createSandbox(
      {
        location: { directory: workspace },
        ...shell.context,
        ...permission.context,
      },
      options(workspace, { toolGuard: "off" })
    );
    try {
      expect(permission.get()).toBeUndefined();
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });
});
