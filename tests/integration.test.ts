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

  test("does not follow a workspace symlink to the host home", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const name = `.osb-link-secret-${process.pid}-${Date.now()}`;
    const secret = path.join(os.homedir(), name);
    const written = path.join(os.homedir(), `${name}-pwn`);
    fs.writeFileSync(secret, "host-secret", { mode: 0o600 });
    fs.symlinkSync(os.homedir(), path.join(workspace, "leak"));
    const { app, run } = await sandbox(workspace);
    try {
      const read = await run(`cat leak/${name} 2>&1`);
      expect(read.stdout).not.toContain("host-secret");
      expect(read.stderr).not.toContain("host-secret");

      const write = await run(`printf evil > leak/${name}-pwn`);
      expect(write.code).not.toBe(0);
      expect(fs.existsSync(written)).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(secret, { force: true });
      fs.rmSync(written, { force: true });
    }
  });

  test("does not read or write host temp dirs (macOS)", async () => {
    if (platform !== "darwin" || !runnable) return;
    const workspace = tempDir();
    const marker = `osb-host-temp-${process.pid}-${Date.now()}`;
    const readMarker = `osb-host-temp-read-${process.pid}-${Date.now()}`;
    const target = path.join("/tmp", marker);
    const readTarget = path.join("/tmp", readMarker);
    fs.writeFileSync(readTarget, "host-temp-secret");
    fs.symlinkSync("/tmp", path.join(workspace, "tmp-link"));
    const { app, run } = await sandbox(workspace);
    try {
      const directRead = await run(`cat ${JSON.stringify(readTarget)} 2>&1`);
      expect(directRead.stdout).not.toContain("host-temp-secret");
      expect(directRead.stderr).not.toContain("host-temp-secret");

      const viaRead = await run(`cat tmp-link/${readMarker} 2>&1`);
      expect(viaRead.stdout).not.toContain("host-temp-secret");
      expect(viaRead.stderr).not.toContain("host-temp-secret");

      const direct = await run(`printf evil > ${JSON.stringify(target)}`);
      expect(direct.code).not.toBe(0);
      expect(fs.existsSync(target)).toBe(false);

      const viaLink = await run(`printf evil > tmp-link/${marker}`);
      expect(viaLink.code).not.toBe(0);
      expect(fs.existsSync(target)).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
      fs.rmSync(target, { force: true });
      fs.rmSync(readTarget, { force: true });
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

  test("keeps OpenCode and Git config read-only inside the workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const plugin = path.join(workspace, ".opencode", "plugin");
    fs.mkdirSync(plugin, { recursive: true });
    fs.writeFileSync(path.join(plugin, "existing.ts"), "export {}\n");
    fs.writeFileSync(path.join(workspace, "opencode.json"), "{}\n");
    fs.mkdirSync(path.join(workspace, ".git", "hooks"), { recursive: true });
    fs.mkdirSync(path.join(workspace, ".git", "objects"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".git", "config"), "[core]\n");
    fs.mkdirSync(path.join(workspace, ".git", "info"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".git", "info", "attributes"), "* text=auto\n");
    fs.writeFileSync(path.join(workspace, ".gitmodules"), '[submodule "x"]\n');
    fs.writeFileSync(path.join(workspace, ".gitattributes"), "* text=auto\n");
    fs.writeFileSync(path.join(workspace, ".envrc"), "export A=1\n");
    fs.mkdirSync(path.join(workspace, ".claude"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".claude", "settings.json"), "{}\n");
    fs.mkdirSync(path.join(workspace, ".agents"), { recursive: true });
    fs.writeFileSync(path.join(workspace, ".agents", "config.json"), "{}\n");
    const { app, run } = await sandbox(workspace);
    try {
      const read = await run("cat .opencode/plugin/existing.ts");
      expect(read.code).toBe(0);
      expect(read.stdout).toContain("export {}");

      for (const target of [
        ".opencode/plugin/evil.ts",
        "opencode.json",
        ".git/hooks/pre-commit",
        ".git/config",
        ".git/info/attributes",
        ".gitmodules",
        ".gitattributes",
        ".envrc",
        ".claude/settings.json",
        ".agents/config.json",
      ]) {
        const result = await run(`printf nope > ${target}`);
        expect(result.code).not.toBe(0);
      }
      expect(fs.existsSync(path.join(plugin, "evil.ts"))).toBe(false);
      expect(fs.readFileSync(path.join(workspace, "opencode.json"), "utf8")).toBe("{}\n");
      expect(fs.readFileSync(path.join(workspace, ".git", "config"), "utf8")).toBe("[core]\n");

      // Git still needs to write its index and objects inside .git.
      const gitWrite = await run("printf index > .git/index; printf obj > .git/objects/new");
      expect(gitWrite.code).toBe(0);
      expect(fs.readFileSync(path.join(workspace, ".git", "index"), "utf8")).toBe("index");
      expect(fs.readFileSync(path.join(workspace, ".git", "objects", "new"), "utf8")).toBe("obj");

      // A hardlink to a protected file must not become a writable alias.
      const link = await run("ln .git/config config2 && printf 'EVIL' > config2; true");
      expect(link.stdout).not.toContain("EVIL");
      expect(fs.existsSync(path.join(workspace, "config2"))).toBe(false);
      expect(fs.readFileSync(path.join(workspace, ".git", "config"), "utf8")).toBe("[core]\n");

      const linkConfig = await run("ln opencode.json opencode2 && printf 'EVIL' > opencode2; true");
      expect(fs.existsSync(path.join(workspace, "opencode2"))).toBe(false);
      expect(fs.readFileSync(path.join(workspace, "opencode.json"), "utf8")).toBe("{}\n");
      expect(linkConfig.stdout).not.toContain("EVIL");

      const linkPlugin = await run(
        "ln .opencode/plugin/existing.ts plugin-alias && printf 'EVIL' > plugin-alias; true"
      );
      expect(fs.existsSync(path.join(workspace, "plugin-alias"))).toBe(false);
      expect(fs.readFileSync(path.join(plugin, "existing.ts"), "utf8")).toBe("export {}\n");
      expect(linkPlugin.stdout).not.toContain("EVIL");

      expect(fs.readFileSync(path.join(workspace, ".git", "info", "attributes"), "utf8")).toBe(
        "* text=auto\n"
      );
      expect(fs.readFileSync(path.join(workspace, ".gitmodules"), "utf8")).toBe(
        '[submodule "x"]\n'
      );
      expect(fs.readFileSync(path.join(workspace, ".claude", "settings.json"), "utf8")).toBe(
        "{}\n"
      );
      expect(fs.readFileSync(path.join(workspace, ".agents", "config.json"), "utf8")).toBe("{}\n");

      const configBefore = fs.readFileSync(path.join(workspace, ".git", "config"), "utf8");
      const rename = await run(
        "mv .git .git-old; printf '[core]\\n\\thooksPath = .evil\\n' > .git-old/config; mv .git-old .git; printf 'rename-done\\n'"
      );
      expect(rename.stdout).toContain("rename-done");
      // Linux pins .git as a mountpoint; macOS denies the directory entry.
      // Either way the host must keep the original config and no hook.
      expect(fs.readFileSync(path.join(workspace, ".git", "config"), "utf8")).toBe(configBefore);
      expect(fs.existsSync(path.join(workspace, ".git", "hooks", "pre-commit"))).toBe(false);

      const renameProtected = await run(
        "mv .opencode .opencode-old && { mkdir -p .opencode-old/plugin; printf nope > .opencode-old/plugin/evil.ts; mv .opencode-old .opencode; }; mv opencode.json opencode.json-old && { printf 'EVIL' > opencode.json-old; mv opencode.json-old opencode.json; }; true"
      );
      expect(renameProtected.stdout).not.toContain("nope");
      expect(fs.existsSync(path.join(workspace, ".opencode-old", "plugin", "evil.ts"))).toBe(false);
      expect(fs.existsSync(path.join(workspace, ".opencode", "plugin", "evil.ts"))).toBe(false);
      const config = path.join(workspace, "opencode.json");
      const movedConfig = path.join(workspace, "opencode.json-old");
      if (fs.existsSync(config)) {
        expect(fs.readFileSync(config, "utf8")).toBe("{}\n");
      } else {
        // macOS has no mountpoints; a rename may succeed, but the original
        // content must remain unchanged and no new config may be planted.
        expect(fs.existsSync(movedConfig)).toBe(true);
        expect(fs.readFileSync(movedConfig, "utf8")).toBe("{}\n");
      }

      const normal = await run("printf ok > notes.txt");
      expect(normal.code).toBe(0);
      expect(fs.readFileSync(path.join(workspace, "notes.txt"), "utf8")).toBe("ok");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("keeps an explicitly readable .git subtree read-only", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const objects = path.join(workspace, ".git", "objects");
    fs.mkdirSync(objects, { recursive: true });
    fs.writeFileSync(path.join(objects, "existing"), "ok");
    const { app, run } = await sandbox(workspace, { readablePaths: [objects] });
    try {
      const read = await run("cat .git/objects/existing");
      expect(read.stdout).toBe("ok");
      const write = await run("printf nope > .git/objects/pwned");
      expect(write.code).not.toBe(0);
      expect(fs.existsSync(path.join(objects, "pwned"))).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("keeps nested .git metadata read-only", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const nested = path.join(workspace, "nested", ".git");
    fs.mkdirSync(path.join(nested, "hooks"), { recursive: true });
    fs.writeFileSync(path.join(nested, "config"), "[core]\n");
    const { app, run } = await sandbox(workspace);
    try {
      const read = await run("cat nested/.git/config");
      expect(read.stdout).toBe("[core]\n");

      for (const target of ["nested/.git/config", "nested/.git/hooks/pre-commit"]) {
        const result = await run(`printf nope > ${target}`);
        expect(result.code).not.toBe(0);
      }
      expect(fs.readFileSync(path.join(nested, "config"), "utf8")).toBe("[core]\n");
      expect(fs.existsSync(path.join(nested, "hooks", "pre-commit"))).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("pins every parent directory of nested .git entries", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    fs.mkdirSync(path.join(workspace, "sub"));
    fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../../gone\n");
    fs.mkdirSync(path.join(workspace, "deep", "a", "b"), { recursive: true });
    fs.writeFileSync(path.join(workspace, "deep", "a", "b", ".git"), "gitdir: ../../../../gone\n");
    const { app, run } = await sandbox(workspace);
    try {
      const result = await run("mv sub sub-old");
      expect(result.code).not.toBe(0);
      expect(fs.existsSync(path.join(workspace, "sub-old"))).toBe(false);
      expect(fs.readFileSync(path.join(workspace, "sub", ".git"), "utf8")).toBe(
        "gitdir: ../../gone\n"
      );

      const deep = await run("mv deep deep-old");
      expect(deep.code).not.toBe(0);
      expect(fs.existsSync(path.join(workspace, "deep-old"))).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("keeps parent pins with a read-only child mount", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    fs.mkdirSync(path.join(workspace, "sub", "ro"), { recursive: true });
    fs.writeFileSync(path.join(workspace, "sub", ".git"), "gitdir: ../../gone\n");
    const { app, run } = await sandbox(workspace, {
      readablePaths: [path.join(workspace, "sub", "ro")],
    });
    try {
      const result = await run("mv sub sub-old");
      expect(result.code).not.toBe(0);
      expect(fs.existsSync(path.join(workspace, "sub-old"))).toBe(false);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("hides denied paths from reads and writes", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    fs.writeFileSync(path.join(workspace, ".env"), "SECRET=dotenv\n");
    fs.mkdirSync(path.join(workspace, "secrets"));
    fs.writeFileSync(path.join(workspace, "secrets", "token"), "SECRET=token\n");
    const { app, run } = await sandbox(workspace, {
      deniedPaths: [".env", path.join(workspace, "secrets")],
    });
    try {
      const dotenv = await run("cat .env 2>&1");
      expect(dotenv.stdout).not.toContain("SECRET=dotenv");
      expect(dotenv.stderr).not.toContain("SECRET=dotenv");

      const token = await run("cat secrets/token 2>&1");
      expect(token.stdout).not.toContain("SECRET=token");
      expect(token.stderr).not.toContain("SECRET=token");

      const writeDotenv = await run("printf nope > .env");
      expect(writeDotenv.code).not.toBe(0);
      expect(fs.readFileSync(path.join(workspace, ".env"), "utf8")).toBe("SECRET=dotenv\n");

      await run("printf nope > secrets/new");
      // Linux masks a denied directory with an empty tmpfs, so the write may
      // succeed inside the sandbox; it must never reach the host.
      expect(fs.existsSync(path.join(workspace, "secrets", "new"))).toBe(false);
      expect(fs.readFileSync(path.join(workspace, "secrets", "token"), "utf8")).toBe(
        "SECRET=token\n"
      );

      const link = await run("ln .env .env2 && cat .env2; true");
      expect(fs.existsSync(path.join(workspace, ".env2"))).toBe(false);
      expect(link.stdout).not.toContain("SECRET=dotenv");

      const normal = await run("printf ok > notes.txt");
      expect(normal.code).toBe(0);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("masks denied paths in system roots", async () => {
    if (!runnable) return;
    const hosts = fs.readFileSync("/etc/hosts", "utf8");
    const marker = hosts
      .split("\n")
      .map((line) => line.trim())
      .find((line) => line !== "" && !line.startsWith("#"));
    if (marker === undefined) return;
    const workspace = tempDir();
    const { app, run } = await sandbox(workspace, { deniedPaths: ["/etc/hosts"] });
    try {
      const result = await run("cat /etc/hosts 2>&1");
      expect(result.stdout).not.toContain(marker);
      expect(result.stderr).not.toContain(marker);
      expect(fs.readFileSync("/etc/hosts", "utf8")).toBe(hosts);
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("masks a denied parent even when a writable child is mounted", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const parent = outsideDir("osb-denied-parent-");
    const build = path.join(parent, "build");
    fs.mkdirSync(build);
    fs.writeFileSync(path.join(build, "ok"), "visible");
    const { app, run } = await sandbox(workspace, {
      writablePaths: [build],
      deniedPaths: [parent],
    });
    try {
      const read = await run(`cat ${JSON.stringify(path.join(build, "ok"))} 2>&1`);
      expect(read.stdout).not.toContain("visible");
      expect(read.stderr).not.toContain("visible");

      await run(`printf nope > ${JSON.stringify(path.join(build, "new"))}`);
      expect(fs.existsSync(path.join(build, "new"))).toBe(false);
      expect(fs.readFileSync(path.join(build, "ok"), "utf8")).toBe("visible");
    } finally {
      app.dispose();
      fs.rmSync(workspace, { recursive: true, force: true });
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
