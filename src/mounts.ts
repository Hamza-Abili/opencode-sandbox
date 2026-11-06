/**
 * opencode-sandbox — deterministic mount precedence.
 *
 * Both engines consume the same plan. Mounts are applied from the broadest to
 * the narrowest path, so a more specific mount wins: on Linux a later bind
 * shadows an earlier one, and on macOS the last matching Seatbelt rule wins.
 *
 * The workspace is always read-write. `writablePaths` are read-write;
 * `readablePaths` are read-only, including when they are a subdirectory of the
 * workspace. A readable path that is only an ancestor of the workspace does
 * not make the workspace read-only, because the workspace entry is narrower.
 * The same path cannot appear in both writable and readable sets, and the
 * workspace cannot be listed as readable; `resolveLayout` enforces both.
 */

import path from "node:path";
import type { SandboxLayout } from "./types.ts";

export type MountMode = "rw" | "ro";

export interface MountEntry {
  path: string;
  mode: MountMode;
}

/** Number of path segments; used only for broad-to-narrow ordering. */
export function pathDepth(value: string): number {
  return value.split(path.sep).filter(Boolean).length;
}

/** Validated user mounts, broad to narrow and deduplicated. */
export function mountPlan(layout: SandboxLayout): MountEntry[] {
  const entries: MountEntry[] = [
    { path: layout.workspace, mode: "rw" },
    ...layout.writablePaths.map((value) => ({ path: value, mode: "rw" as const })),
    ...layout.readablePaths.map((value) => ({ path: value, mode: "ro" as const })),
  ];

  const byPath = new Map<string, MountEntry>();
  for (const entry of entries) {
    // Defense in depth: resolveLayout already rejects this, but a hand-built
    // layout must not silently pick one mode.
    const previous = byPath.get(entry.path);
    if (previous !== undefined && previous.mode !== entry.mode) {
      throw new Error(`${entry.path} is both writable and readable; choose one mount mode`);
    }
    byPath.set(entry.path, entry);
  }

  return [...byPath.values()].sort(
    (left, right) =>
      pathDepth(left.path) - pathDepth(right.path) || left.path.localeCompare(right.path)
  );
}
