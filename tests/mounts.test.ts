import { describe, expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mountPlan, pathDepth } from "../src/mounts.ts";
import { resolveLayout } from "../src/paths.ts";
import type { SandboxLayout } from "../src/types.ts";

function tempDir(prefix = "osb-mounts-"): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

function layoutFor(
  workspace: string,
  writablePaths: string[] = [],
  readablePaths: string[] = []
): SandboxLayout {
  return resolveLayout(workspace, { writablePaths, readablePaths });
}

describe("mountPlan", () => {
  test("orders broad to narrow so the workspace survives a readable parent", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    fs.mkdirSync(workspace);
    try {
      const plan = mountPlan(layoutFor(workspace, [], [parent]));
      expect(plan.map((entry) => entry.path)).toEqual([parent, workspace]);
      expect(plan.map((entry) => entry.mode)).toEqual(["ro", "rw"]);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("keeps a readable subdirectory read-only after the workspace", () => {
    const workspace = tempDir();
    const vendor = path.join(workspace, "vendor");
    fs.mkdirSync(vendor);
    try {
      const plan = mountPlan(layoutFor(workspace, [], [vendor]));
      expect(plan.map((entry) => entry.path)).toEqual([workspace, vendor]);
      expect(plan.map((entry) => entry.mode)).toEqual(["rw", "ro"]);
    } finally {
      fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  test("a writable child wins over a readable parent", () => {
    const parent = tempDir();
    const workspace = path.join(parent, "ws");
    const cache = path.join(parent, "cache");
    fs.mkdirSync(workspace);
    fs.mkdirSync(cache);
    try {
      const plan = mountPlan(layoutFor(workspace, [cache], [parent]));
      const index = (target: string): number => plan.findIndex((entry) => entry.path === target);
      expect(plan[index(parent)]?.mode).toBe("ro");
      expect(plan[index(cache)]?.mode).toBe("rw");
      expect(plan[index(workspace)]?.mode).toBe("rw");
      expect(index(parent)).toBeLessThan(index(cache));
      expect(index(parent)).toBeLessThan(index(workspace));
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });

  test("rejects a path that is both writable and readable", () => {
    const layout: SandboxLayout = {
      workspace: "/workspace",
      hostHome: "/home/user",
      writablePaths: ["/shared"],
      readablePaths: ["/shared"],
    };
    expect(() => mountPlan(layout)).toThrow(/both writable and readable/);
  });

  test("counts path segments for ordering", () => {
    expect(pathDepth("/")).toBe(0);
    expect(pathDepth("/a")).toBe(1);
    expect(pathDepth("/a/b")).toBe(2);
  });
});
