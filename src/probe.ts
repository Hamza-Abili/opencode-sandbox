/**
 * opencode-sandbox — capability probe.
 *
 * `bwrap --version` (or the mere presence of `sandbox-exec`) is not enough:
 * a host can have the binary and still be unable to create a user namespace
 * (Ubuntu 24.04+ AppArmor restrictions). The probe creates a real sandbox.
 */

import type { Platform, ProbeResult } from "./types.ts";

const BWRAP_PROBE = [
  "--ro-bind",
  "/",
  "/",
  "--dev",
  "/dev",
  "--proc",
  "/proc",
  "--tmpfs",
  "/tmp",
  "--unshare-all",
  "--die-with-parent",
  "--",
  "/bin/sh",
  "-c",
  "exit 42",
];

const DARWIN_PROBE = [
  "(version 1)",
  "(deny default)",
  "(allow process-exec)",
  "(allow process-fork)",
  "(allow file-read*)",
  "(allow sysctl-read)",
  "(allow mach-lookup)",
].join("\n");

export interface ProcessOptions {
  timeoutMs?: number;
  cwd?: string;
}

/** Run a trusted absolute binary and capture its exit code and stderr. */
export async function runProcess(
  binary: string,
  args: string[],
  options: ProcessOptions = {}
): Promise<{ code: number; stderr: string }> {
  const child = Bun.spawn({
    cmd: [binary, ...args],
    cwd: options.cwd,
    stdout: "pipe",
    stderr: "pipe",
  });
  const timer = setTimeout(() => {
    try {
      child.kill();
    } catch {
      // already exited
    }
  }, options.timeoutMs ?? 5000);
  try {
    const code = await child.exited;
    const stderr = (await new Response(child.stderr).text()).trim();
    return { code, stderr };
  } finally {
    clearTimeout(timer);
  }
}

export async function probe(
  platform: Platform,
  binary: string,
  timeoutMs = 5000
): Promise<ProbeResult> {
  const args =
    platform === "linux" ? BWRAP_PROBE : ["-p", DARWIN_PROBE, "/bin/sh", "-c", "exit 42"];
  try {
    const result = await runProcess(binary, args, { timeoutMs });
    if (result.code === 42) return { available: true };
    return {
      available: false,
      reason:
        result.stderr === ""
          ? `${binary} did not execute the probe command (exit ${result.code})`
          : `${binary} cannot create a sandbox: ${result.stderr}`,
    };
  } catch (error) {
    return {
      available: false,
      reason: `${binary} is not runnable: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}
