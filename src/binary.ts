/**
 * opencode-sandbox — sandbox binary resolution.
 *
 * The binary is resolved once from fixed, root-owned absolute locations. It is
 * never looked up through PATH: a project dev shell or a writable directory
 * earlier in PATH must not be able to substitute an unsandboxing shim.
 */

import fs from "node:fs";
import type { Platform } from "./types.ts";

export type Resolved = { ok: true; path: string } | { ok: false; reason: string };

const BWRAP_CANDIDATES = [
  "/usr/bin/bwrap",
  "/bin/bwrap",
  "/usr/local/bin/bwrap",
  "/run/current-system/sw/bin/bwrap",
];

const SANDBOX_EXEC = "/usr/bin/sandbox-exec";

interface Candidate {
  path: string;
  reason?: string;
}

function inspect(pathname: string): Candidate {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(pathname);
  } catch {
    return { path: pathname, reason: "not found" };
  }
  if (!stat.isFile()) return { path: pathname, reason: "not a regular file" };
  if ((stat.mode & 0o111) === 0) return { path: pathname, reason: "not executable" };
  // setuid bubblewrap is a supported installation, but a user-writable
  // binary is not: the sandbox would trust whatever the user (or an agent
  // running as that user) wrote there.
  if (stat.uid !== 0 || (stat.mode & 0o022) !== 0) {
    return { path: pathname, reason: "not root-owned or group/world-writable" };
  }
  try {
    return { path: fs.realpathSync.native(pathname) };
  } catch {
    return { path: pathname, reason: "cannot resolve real path" };
  }
}

export function resolveSandboxBinary(platform: Platform): Resolved {
  const candidates = platform === "linux" ? BWRAP_CANDIDATES : [SANDBOX_EXEC];
  const failures: string[] = [];
  for (const candidate of candidates) {
    const result = inspect(candidate);
    if (result.reason === undefined) return { ok: true, path: result.path };
    failures.push(`${candidate} (${result.reason})`);
  }
  return {
    ok: false,
    reason:
      platform === "linux"
        ? `bubblewrap not found in a trusted location: ${failures.join(", ")}. Install it system-wide (sudo apt install bubblewrap).`
        : `sandbox-exec not found in a trusted location: ${failures.join(", ")}`,
  };
}
