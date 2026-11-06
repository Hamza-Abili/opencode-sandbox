import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolveSandboxBinary } from "../src/binary.ts";
import { createLegacyServer } from "../src/legacy.ts";
import { probe } from "../src/probe.ts";

function tempDir(prefix = "osb-v1-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

const platform = process.platform === "darwin" ? "darwin" : "linux";
const binary = resolveSandboxBinary(platform);
const required =
  platform === "linux"
    ? process.env.SANDBOX_REQUIRE_BWRAP === "1"
    : process.env.SANDBOX_REQUIRE_SANDBOX_EXEC === "1";
const available = binary.ok ? (await probe(platform, binary.path)).available : false;
const runnable = available || required;

describe("V1 adapter", () => {
  test("rewrites the command to the wrapper and keeps the workdir", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const hooks = await createLegacyServer({ worktree: workspace }, {});
    try {
      const args: { command: string; workdir?: string } = { command: "echo original" };
      await hooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: "c" }, { args });
      expect(args.command).toContain(" -c ");
      expect(args.command).toContain("echo original");
      expect(args.command.startsWith("'")).toBe(true);
      const wrapper = args.command.slice(1, args.command.indexOf("' -c "));
      expect(fs.existsSync(wrapper)).toBe(true);
      expect(fs.statSync(wrapper).mode & 0o111).toBeGreaterThan(0);
    } finally {
      await hooks.dispose?.();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("is idempotent for a replayed hook", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const hooks = await createLegacyServer({ worktree: workspace }, {});
    try {
      const args: { command: string } = { command: "echo original" };
      const input = { tool: "bash", sessionID: "s", callID: "c" };
      await hooks["tool.execute.before"]?.(input, { args });
      const once = args.command;
      await hooks["tool.execute.before"]?.(input, { args });
      expect(args.command).toBe(once);
    } finally {
      await hooks.dispose?.();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("prefers the project directory over a worktree of /", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const hooks = await createLegacyServer({ directory: workspace, worktree: "/" }, {});
    try {
      const args = { command: "echo original" };
      await hooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: "c" }, { args });
      expect(args.command).toContain("echo original");
    } finally {
      await hooks.dispose?.();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("leaves non-shell tools untouched", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const hooks = await createLegacyServer({ worktree: workspace }, {});
    try {
      const args = { command: "echo untouched" };
      await hooks["tool.execute.before"]?.({ tool: "read", sessionID: "s", callID: "c" }, { args });
      expect(args.command).toBe("echo untouched");
    } finally {
      await hooks.dispose?.();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("fails closed for the host home workspace", async () => {
    const hooks = await createLegacyServer({ worktree: os.homedir() }, {});
    const args = { command: "true" };
    await expect(
      hooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: "c" }, { args })
    ).rejects.toThrow(/host home/);
  });

  test("fails closed when a workdir escapes the workspace", async () => {
    if (!runnable) return;
    const workspace = tempDir();
    const hooks = await createLegacyServer({ worktree: workspace }, {});
    try {
      const args = { command: "true", workdir: path.dirname(workspace) };
      await expect(
        hooks["tool.execute.before"]?.({ tool: "bash", sessionID: "s", callID: "c" }, { args })
      ).rejects.toThrow(/outside/);
    } finally {
      await hooks.dispose?.();
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });
});
