import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { contains, mountRoots, resolveCwd, resolveLayout } from "../src/paths.ts";

function tempDir(prefix = "osb-paths-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function withDir(run: (dir: string) => void): void {
  const dir = tempDir();
  try {
    run(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe("resolveLayout", () => {
  test("resolves a normal workspace and mounts", () => {
    withDir((workspace) => {
      const writable = tempDir("osb-rw-");
      const readable = tempDir("osb-ro-");
      try {
        const layout = resolveLayout(workspace, {
          writablePaths: [writable],
          readablePaths: [readable],
        });
        expect(layout.workspace).toBe(workspace);
        expect(layout.writablePaths).toEqual([writable]);
        expect(layout.readablePaths).toEqual([readable]);
        expect(layout.hostHome).toBe(fs.realpathSync.native(os.homedir()));
      } finally {
        fs.rmSync(writable, { recursive: true, force: true });
        fs.rmSync(readable, { recursive: true, force: true });
      }
    });
  });

  test("rejects the filesystem root", () => {
    expect(() => resolveLayout("/", { writablePaths: [], readablePaths: [] })).toThrow();
  });

  test("rejects the host home as the workspace", () => {
    expect(() => resolveLayout(os.homedir(), { writablePaths: [], readablePaths: [] })).toThrow(
      /host home/
    );
  });

  test("does not trust a spoofed HOME for the host-home guard", () => {
    const id = typeof process.getuid === "function" ? process.getuid() : undefined;
    let realHome = fs.realpathSync.native(os.homedir());
    if (id !== undefined) {
      try {
        for (const line of fs.readFileSync("/etc/passwd", "utf8").split("\n")) {
          const fields = line.split(":");
          if (fields.length >= 6 && fields[2] === String(id) && fields[5] !== "") {
            realHome = fs.realpathSync.native(fields[5]);
            break;
          }
        }
      } catch {
        // fall back to the parent environment
      }
    }
    const fake = tempDir("osb-fakehome-");
    const script = [
      `import { resolveLayout } from ${JSON.stringify(path.resolve(import.meta.dir, "../src/paths.ts"))};`,
      "try {",
      `  resolveLayout(${JSON.stringify(realHome)}, { writablePaths: [], readablePaths: [] });`,
      '  console.log("ALLOWED");',
      "  process.exit(0);",
      "} catch {",
      '  console.log("REJECTED");',
      "  process.exit(7);",
      "}",
    ].join("\n");
    try {
      const result = Bun.spawnSync({
        cmd: [process.execPath, "-e", script],
        cwd: path.resolve(import.meta.dir, ".."),
        env: { ...process.env, HOME: fake, USER: "spoofed-user" },
        stdout: "pipe",
        stderr: "pipe",
      });
      expect(result.stdout.toString()).toContain("REJECTED");
      expect(result.exitCode).toBe(7);
    } finally {
      fs.rmSync(fake, { recursive: true, force: true });
    }
  });

  test("rejects an ancestor of the host home", () => {
    const home = fs.realpathSync.native(os.homedir());
    const parent = path.dirname(home);
    // The filesystem root is covered separately; use the immediate parent.
    expect(() => resolveLayout(parent, { writablePaths: [], readablePaths: [] })).toThrow(
      /contains the host home/
    );
  });

  test("rejects a symlink to / as a writable path", () => {
    withDir((workspace) => {
      const link = path.join(workspace, "root-link");
      fs.symlinkSync("/", link);
      expect(() => resolveLayout(workspace, { writablePaths: [link], readablePaths: [] })).toThrow(
        /filesystem root/
      );
    });
  });

  test("rejects the host home as an extra mount", () => {
    withDir((workspace) => {
      expect(() =>
        resolveLayout(workspace, { writablePaths: [os.homedir()], readablePaths: [] })
      ).toThrow(/host home/);
    });
  });

  test("rejects host system paths as writable", () => {
    expect(() => resolveLayout("/etc", { writablePaths: [], readablePaths: [] })).toThrow(
      /system path/
    );
    withDir((workspace) => {
      expect(() =>
        resolveLayout(workspace, { writablePaths: ["/etc"], readablePaths: [] })
      ).toThrow(/system path/);
      expect(() =>
        resolveLayout(workspace, { writablePaths: ["/usr/local"], readablePaths: [] })
      ).toThrow(/system path/);
    });
  });

  test("rejects credential directories as workspace or writable mount", () => {
    const home = tempDir("osb-home-");
    const workspace = path.join(home, "project");
    fs.mkdirSync(workspace);
    const sensitive = [".ssh", ".aws", ".local/state/opencode", ".config/opencode"];
    for (const relative of sensitive) {
      fs.mkdirSync(path.join(home, relative), { recursive: true });
    }
    try {
      for (const relative of sensitive) {
        const target = path.join(home, relative);
        expect(() => resolveLayout(target, { writablePaths: [], readablePaths: [] }, home)).toThrow(
          /credential directory/
        );
        expect(() =>
          resolveLayout(workspace, { writablePaths: [target], readablePaths: [] }, home)
        ).toThrow(/credential directory/);
      }
      const layout = resolveLayout(
        workspace,
        { writablePaths: [], readablePaths: [path.join(home, ".ssh")] },
        home
      );
      expect(layout.readablePaths).toEqual([path.join(home, ".ssh")]);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  test("rejects missing mounts instead of silently skipping them", () => {
    withDir((workspace) => {
      expect(() =>
        resolveLayout(workspace, {
          writablePaths: ["/definitely/not/a/mount"],
          readablePaths: [],
        })
      ).toThrow(/does not exist/);
    });
  });
});

describe("resolveCwd", () => {
  test("accepts the workspace, subdirectories and extra mounts", () => {
    withDir((workspace) => {
      const sub = path.join(workspace, "sub");
      fs.mkdirSync(sub);
      const extra = tempDir("osb-extra-");
      try {
        const layout = resolveLayout(workspace, { writablePaths: [extra], readablePaths: [] });
        expect(resolveCwd(layout, undefined)).toBe(workspace);
        expect(resolveCwd(layout, "sub")).toBe(sub);
        expect(resolveCwd(layout, extra)).toBe(extra);
      } finally {
        fs.rmSync(extra, { recursive: true, force: true });
      }
    });
  });

  test("rejects paths outside every mount", () => {
    withDir((workspace) => {
      const layout = resolveLayout(workspace, { writablePaths: [], readablePaths: [] });
      expect(() => resolveCwd(layout, os.tmpdir())).toThrow(/outside/);
      expect(() => resolveCwd(layout, "..")).toThrow(/outside/);
    });
  });

  test("rejects a symlink that escapes the workspace", () => {
    withDir((workspace) => {
      const layout = resolveLayout(workspace, { writablePaths: [], readablePaths: [] });
      const link = path.join(workspace, "escape");
      fs.symlinkSync("/etc", link);
      expect(() => resolveCwd(layout, "escape")).toThrow(/outside/);
    });
  });

  test("rejects a missing working directory", () => {
    withDir((workspace) => {
      const layout = resolveLayout(workspace, { writablePaths: [], readablePaths: [] });
      expect(() => resolveCwd(layout, "missing")).toThrow(/does not exist/);
    });
  });
});

describe("contains", () => {
  test("matches the root and descendants, not prefixes", () => {
    expect(contains("/a", "/a")).toBe(true);
    expect(contains("/a", "/a/b")).toBe(true);
    expect(contains("/a", "/ab")).toBe(false);
    expect(contains("/a", "/a/b")).toBe(true);
  });
});

test("mountRoots is workspace first", () => {
  withDir((workspace) => {
    const layout = resolveLayout(workspace, { writablePaths: [], readablePaths: [] });
    expect(mountRoots(layout)[0]).toBe(workspace);
  });
});
