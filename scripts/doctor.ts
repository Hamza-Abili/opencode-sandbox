#!/usr/bin/env bun
/**
 * opencode-sandbox doctor — non-destructive diagnostics.
 *
 * It creates a temporary runtime directory for the generated-wrapper probe and
 * removes it before exiting; the workspace and policy files are not modified.
 *
 * Usage:
 *   bunx --bun @hamzaabili/opencode-sandbox doctor [--workspace DIR] [--json]
 *
 * It resolves the trusted policy, builds the real layout, resolves the trusted
 * sandbox binary, and runs the real probe. No model or OpenCode server needed.
 */

import fs from "node:fs";
import path from "node:path";
import { resolveSandboxBinary } from "../src/binary.ts";
import { resolveLayout } from "../src/paths.ts";
import { resolveEffectiveOptions, trustedPolicyPaths } from "../src/policy.ts";
import type { Platform, SandboxLayout, SandboxOptions } from "../src/types.ts";
import { prepareRuntime } from "../src/wrapper.ts";
import { wslName } from "../src/wsl.ts";

interface Args {
  workspace: string;
  json: boolean;
  help: boolean;
}

function usage(exitCode = 2): never {
  const message = "Usage: opencode-sandbox doctor [--workspace DIR] [--json]";
  if (exitCode === 0) console.log(message);
  else console.error(message);
  process.exit(exitCode);
}

function parseArgs(argv: string[]): Args {
  const args: Args = { workspace: process.cwd(), json: false, help: false };
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index];
    if (value === "--json") args.json = true;
    else if (value === "--help" || value === "-h") args.help = true;
    else if (value === "doctor") continue;
    else if (value === "--workspace") {
      const next = argv[++index];
      if (next === undefined) usage();
      args.workspace = next;
    } else if (value.startsWith("--workspace=")) {
      args.workspace = value.slice("--workspace=".length);
    } else usage();
  }
  return args;
}

function version(): string {
  try {
    const file = path.resolve(import.meta.dir, "..", "package.json");
    return (JSON.parse(fs.readFileSync(file, "utf8")) as { version?: string }).version ?? "unknown";
  } catch {
    return "unknown";
  }
}

function binaryVersion(binary: string, platform: Platform): string | undefined {
  if (platform === "darwin") return undefined;
  try {
    const result = Bun.spawnSync({
      cmd: [binary, "--version"],
      stdout: "pipe",
      stderr: "ignore",
      timeout: 2000,
    });
    if (result.exitCode !== 0) return undefined;
    return result.stdout.toString().trim().split("\n")[0];
  } catch {
    return undefined;
  }
}

function policySummary(options: SandboxOptions) {
  return {
    network: options.network,
    mode: options.mode,
    toolGuard: options.toolGuard,
    webfetch: options.webfetch,
    webfetchAllowlist: options.webfetchAllowlist,
    shell: options.shell,
    writablePaths: options.writablePaths,
    readablePaths: options.readablePaths,
    passEnv: options.passEnv,
    deniedPaths: options.deniedPaths,
    unsandboxedCommandCount: options.unsandboxedCommands.length,
  };
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    usage(0);
  }

  let workspace: string;
  try {
    workspace = fs.realpathSync.native(path.resolve(args.workspace));
    if (!fs.statSync(workspace).isDirectory()) throw new Error("not a directory");
  } catch {
    console.error(`workspace is not a directory: ${args.workspace}`);
    return 2;
  }

  const policy = resolveEffectiveOptions({}, workspace);
  const paths = trustedPolicyPaths();
  const platform = process.platform as Platform;
  const wsl = wslName();

  let layout: SandboxLayout | undefined;
  let layoutError: string | undefined;
  try {
    layout = resolveLayout(workspace, policy.options);
  } catch (error) {
    layoutError = error instanceof Error ? error.message : String(error);
  }

  const supported = platform === "linux" || platform === "darwin";
  const resolved = supported ? resolveSandboxBinary(platform) : undefined;
  let prepared: Awaited<ReturnType<typeof prepareRuntime>> | undefined;
  if (supported && layout !== undefined) {
    try {
      prepared = await prepareRuntime(platform, layout, policy.options);
    } catch (error) {
      prepared = { ok: false, reason: error instanceof Error ? error.message : String(error) };
    }
  }
  const ready = prepared?.ok === true;
  if (prepared?.ok === true) prepared.runtime.dispose();
  const sandboxError =
    prepared?.ok === false ? prepared.reason : resolved?.ok === false ? resolved.reason : undefined;
  const protectedCount = layout?.protectedPaths.length ?? 0;
  const deniedCount = layout?.deniedPaths.length ?? 0;

  const report = {
    version: version(),
    platform,
    wsl,
    workspace,
    policyFiles: {
      user: {
        path: paths.user,
        used: policy.user.used,
        present: policy.user.present,
        ignored: policy.user.ignored,
      },
      system: {
        path: paths.system,
        used: policy.system.used,
        present: policy.system.present,
      },
    },
    policy: policySummary(policy.options),
    layout: layout === undefined ? undefined : { protected: protectedCount, denied: deniedCount },
    layoutError,
    sandbox: resolved?.ok
      ? {
          binary: resolved.path,
          version: binaryVersion(resolved.path, platform),
          probe: ready ? "pass" : "fail",
          probeError: ready ? undefined : sandboxError,
        }
      : {
          binary: undefined,
          error: resolved?.reason,
        },
    warnings: policy.warnings,
    errors: policy.errors,
  };

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(`opencode-sandbox doctor ${report.version}`);
    console.log(`platform: ${platform}${wsl === undefined ? "" : ` (wsl2: ${wsl})`}`);
    console.log(`workspace: ${workspace}`);
    const userState = policy.user.used
      ? "active"
      : policy.user.ignored
        ? "ignored (system policy invalid)"
        : policy.user.present
          ? "invalid"
          : "absent";
    console.log(`trusted policy: ${paths.user} (${userState})`);
    console.log(
      `system policy: ${paths.system} (${policy.system.used ? "active" : policy.system.present ? "invalid" : "absent"})`
    );
    console.log(
      `effective policy: network=${policy.options.network}, mode=${policy.options.mode}, ` +
        `toolGuard=${policy.options.toolGuard}, webfetch=${policy.options.webfetch}`
    );
    console.log(
      `mounts: writable=${policy.options.writablePaths.length}, readable=${policy.options.readablePaths.length}, ` +
        `passEnv=${policy.options.passEnv.length}, denied=${deniedCount}, protected=${protectedCount}, ` +
        `unsandboxed=${policy.options.unsandboxedCommands.length}`
    );
    console.log(`shell: ${policy.options.shell}`);
    if (resolved?.ok) {
      const version = binaryVersion(resolved.path, platform);
      console.log(
        `sandbox binary: ${resolved.path}${version === undefined ? "" : ` (${version})`}`
      );
      console.log(`probe: ${ready ? "pass" : "fail"}`);
      if (!ready && sandboxError !== undefined) {
        console.log(`probe error: ${sandboxError}`);
      }
    } else {
      console.log(`sandbox binary: ${resolved?.reason ?? "unsupported platform"}`);
    }
    if (layoutError !== undefined) console.log(`layout error: ${layoutError}`);
    for (const warning of policy.warnings) console.log(`warning: ${warning}`);
    for (const error of policy.errors) console.log(`error: ${error}`);
    if (!supported) {
      console.log("Windows native is not supported; run OpenCode inside WSL2 (see README).");
    } else if (layoutError !== undefined || policy.errors.length > 0) {
      console.log("next: fix the policy/layout errors above; the plugin fails closed.");
    } else if (!ready) {
      if (resolved?.ok) {
        console.log(
          "next: the sandbox binary exists but the generated wrapper failed; check the shell and paths above."
        );
      } else {
        console.log(
          platform === "linux"
            ? "next: install bubblewrap; on Ubuntu 24.04+ enable its AppArmor userns profile (see README)."
            : "next: reinstall the macOS command line tools; sandbox-exec is missing."
        );
      }
    } else {
      console.log("result: ready");
    }
  }

  if (!supported) return 1;
  if (layoutError !== undefined || policy.errors.length > 0) return 1;
  if (!ready) return 1;
  return 0;
}

process.exit(await main());
