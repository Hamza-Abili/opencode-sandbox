import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSandbox, type ShellCreateEvent } from "../src/app.ts";
import { resolveSandboxBinary } from "../src/binary.ts";
import { parseOptions } from "../src/options.ts";
import { probe } from "../src/probe.ts";

function tempDir(prefix = "osb-int-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

/** Host-writable location outside the workspace and the OS temp dirs. */
function outsideDir(prefix = "osb-outside-"): string {
  const base = process.platform === "darwin" ? "/private/var/tmp" : "/var/tmp";
  return fs.realpathSync.native(fs.mkdtempSync(path.join(base, prefix)));
}

function fakeShell() {
  let callback: ((event: ShellCreateEvent) => Promise<void> | void) | undefined;
  return {
    context: {
      shell: {
        hook: async (
          _name: "create.before",
          fn: (event: ShellCreateEvent) => Promise<void> | void
        ) => {
          callback = fn;
          return { dispose: async () => {} };
        },
      },
    },
    get: () => callback,
  };
}

const platform = process.platform === "darwin" ? "darwin" : "linux";
const binary = resolveSandboxBinary(platform);
const required =
  platform === "linux"
    ? process.env.SANDBOX_REQUIRE_BWRAP === "1"
    : process.env.SANDBOX_REQUIRE_SANDBOX_EXEC === "1";
const available = binary.ok ? (await probe(platform, binary.path)).available : false;
const runnable = available || required;

async function sandbox(workspace: string, overrides: Record<string, unknown> = {}) {
  const fake = fakeShell();
  const app = await createSandbox(
    { location: { directory: workspace }, ...fake.context },
    parseOptions({ toolGuard: "off", ...overrides }, workspace)
  );
  const callback = fake.get();
  if (callback === undefined) throw new Error("sandbox was not installed");

  const shellFor = async (cwd = workspace): Promise<string> => {
    const event: ShellCreateEvent = {
      command: "true",
      cwd,
      timeout: 0,
      shell: "/bin/bash",
      env: {},
    };
    await callback(event);
    return event.shell;
  };

  const run = async (command: string, cwd = workspace, env: Record<string, string> = {}) => {
    const shell = await shellFor(cwd);
    const child = Bun.spawn({
      cmd: [shell, "-c", command],
      cwd,
      env: { ...process.env, ...env },
      stdout: "pipe",
      stderr: "pipe",
    });
    const code = await child.exited;
    const [stdout, stderr] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { code, stdout, stderr };
  };

  return { app, run, shellFor };
}

describe("real sandbox integration", () => {
  test("runs commands inside the workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const { app, run } = await sandbox(workspace);
    try {
      const result = await run("printf sandbox-ok");
      expect(result.code).toBe(0);
      expect(result.stdout).toBe("sandbox-ok");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("allows writes inside the workspace and blocks host paths", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const outside = outsideDir();
    const marker = path.join(outside, "marker");
    const { app, run } = await sandbox(workspace);
    try {
      const write = await run("printf written > inside.txt");
      expect(write.code).toBe(0);
      expect(fs.existsSync(path.join(workspace, "inside.txt"))).toBe(true);

      const denied = await run(`printf nope > ${marker}`);
      expect(denied.code).not.toBe(0);
      expect(fs.existsSync(marker)).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  test("hides the host home and its secrets", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const secret = path.join(os.homedir(), `osb-secret-${process.pid}-${Date.now()}`);
    fs.writeFileSync(secret, "host-secret", { mode: 0o600 });
    const { app, run } = await sandbox(workspace);
    try {
      const result = await run(`cat ${JSON.stringify(secret)}`);
      expect(result.code).not.toBe(0);
      expect(result.stdout).not.toContain("host-secret");
      if (platform === "darwin") {
        const alias = await run(`cat ${JSON.stringify(`/System/Volumes/Data${secret}`)}`);
        expect(alias.code).not.toBe(0);
        expect(alias.stdout).not.toContain("host-secret");
      }
      expect(fs.readFileSync(secret, "utf8")).toBe("host-secret");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(secret, { force: true });
    }
  });

  test("cannot read the parent environment through sysctl (macOS)", async () => {
    if (platform !== "darwin" || !runnable) return;
    const key = "OSB_PARENT_SECRET";
    process.env[key] = "parent-secret";
    const workspace = tempDir();
    const { app, run } = await sandbox(workspace);
    try {
      const result = await run("ps eww -p $PPID 2>&1");
      expect(result.stdout).not.toContain("parent-secret");
      expect(result.stderr).not.toContain("parent-secret");
    } finally {
      app.dispose();
      delete process.env[key];
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("clears ambient environment unless explicitly passed", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const key = "OPENCODE_SANDBOX_TEST_SECRET";
    process.env[key] = "leak";
    const scrub = await sandbox(workspace);
    try {
      const result = await scrub.run(`printenv ${key}`);
      expect(result.stdout.trim()).toBe("");
    } finally {
      scrub.app.dispose();
    }

    const passed = await sandbox(workspace, { passEnv: [key] });
    try {
      const result = await passed.run(`printenv ${key}`);
      expect(result.stdout.trim()).toBe("leak");
    } finally {
      passed.app.dispose();
      delete process.env[key];
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("denies network access by default", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const { app, run } = await sandbox(workspace);
    try {
      const result = await run("/usr/bin/curl -sS --max-time 2 http://1.1.1.1/");
      expect(result.code).not.toBe(0);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("shares the host network only when allowed", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () => new Response("network-ok"),
    });
    const deny = await sandbox(workspace);
    try {
      const blocked = await deny.run(
        `/usr/bin/curl -sS --max-time 2 http://127.0.0.1:${server.port}/`
      );
      expect(blocked.code).not.toBe(0);
    } finally {
      deny.app.dispose();
    }

    const allow = await sandbox(workspace, { network: "allow" });
    try {
      const result = await allow.run(
        `/usr/bin/curl -sS --max-time 5 http://127.0.0.1:${server.port}/`
      );
      expect(result.code).toBe(0);
      expect(result.stdout).toBe("network-ok");
    } finally {
      allow.app.dispose();
      server.stop(true);
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("reaches HTTPS when network is allowed (DNS and TLS)", async () => {
    if (!runnable || process.env.SANDBOX_TEST_INTERNET !== "1") return;
    const workspace = tempDir();
    const allow = await sandbox(workspace, { network: "allow" });
    try {
      let result = await allow.run(
        "/usr/bin/curl -sS --max-time 10 -o /dev/null -w '%{http_code}' https://example.com"
      );
      for (
        let attempt = 0;
        attempt < 2 && (result.code !== 0 || result.stdout.trim() !== "200");
        attempt++
      ) {
        Bun.sleepSync(500);
        result = await allow.run(
          "/usr/bin/curl -sS --max-time 10 -o /dev/null -w '%{http_code}' https://example.com"
        );
      }
      if (result.code !== 0) console.error(`macOS HTTPS probe failed: ${result.stderr}`);
      expect(result.code).toBe(0);
      expect(result.stdout.trim()).toBe("200");
    } finally {
      allow.app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("mounts extra writable paths only when requested", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const extra = outsideDir("osb-extra-");
    const denied = await sandbox(workspace);
    try {
      const result = await denied.run(`printf nope > ${path.join(extra, "blocked")}`);
      expect(result.code).not.toBe(0);
      expect(fs.existsSync(path.join(extra, "blocked"))).toBe(false);
    } finally {
      denied.app.dispose();
    }

    const allowed = await sandbox(workspace, { writablePaths: [extra] });
    try {
      const result = await allowed.run(`printf yes > ${path.join(extra, "allowed")}`);
      expect(result.code).toBe(0);
      expect(fs.readFileSync(path.join(extra, "allowed"), "utf8")).toBe("yes");
    } finally {
      allowed.app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(extra, { recursive: true, force: true });
    }
  });

  test("enforces readable and writable mount precedence", async () => {
    if (!runnable) return;
    const parent = outsideDir("osb-precedence-");
    const workspace = path.join(parent, "ws");
    const vendor = path.join(workspace, "vendor");
    const cache = path.join(parent, "cache");
    fs.mkdirSync(workspace);
    fs.mkdirSync(vendor);
    fs.mkdirSync(cache);
    const { app, run } = await sandbox(workspace, {
      writablePaths: [cache],
      readablePaths: [parent, vendor],
    });
    try {
      const writable = await run("printf ok > ws.txt");
      expect(writable.code).toBe(0);
      expect(fs.existsSync(path.join(workspace, "ws.txt"))).toBe(true);

      const readOnlyChild = await run("printf nope > vendor.txt", vendor);
      expect(readOnlyChild.code).not.toBe(0);
      expect(fs.existsSync(path.join(vendor, "vendor.txt"))).toBe(false);

      const writableChild = await run("printf ok > cache.txt", cache);
      expect(writableChild.code).toBe(0);
      expect(fs.existsSync(path.join(cache, "cache.txt"))).toBe(true);

      const readOnlyParent = await run("printf nope > parent.txt", parent);
      expect(readOnlyParent.code).not.toBe(0);
      expect(fs.existsSync(path.join(parent, "parent.txt"))).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("honours a working directory inside the workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const sub = path.join(workspace, "sub");
    fs.mkdirSync(sub);
    const { app, run } = await sandbox(workspace);
    try {
      const result = await run("pwd -P", sub);
      expect(result.code).toBe(0);
      expect(result.stdout.trim()).toBe(sub);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("the wrapper refuses an escaped working directory", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const outside = outsideDir("osb-cwd-");
    const { app, shellFor } = await sandbox(workspace);
    try {
      const shell = await shellFor(workspace);
      const result = Bun.spawnSync({
        cmd: [shell, "-c", "true"],
        cwd: outside,
        env: process.env,
      });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr.toString()).toContain("outside the sandbox");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});
