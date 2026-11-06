import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSandbox, type ShellCreateEvent } from "../src/app.ts";
import { resolveSandboxBinary } from "../src/binary.ts";
import { parseOptions } from "../src/options.ts";
import { probe } from "../src/probe.ts";

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
  let callback: ((event: { tool: string }) => Promise<void> | void) | undefined;
  const context = {
    tool: {
      hook: async (
        _name: "execute.before",
        fn: (event: { tool: string }) => Promise<void> | void
      ) => {
        callback = fn;
        return { dispose: async () => {} };
      },
    },
  };
  return { context, get: () => callback };
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
  return parseOptions({ ...overrides }, workspace);
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
    } finally {
      app.dispose();
    }
  });

  test("falls back to the tool hook when shell hook registration fails", async () => {
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
    } finally {
      app.dispose();
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
});
