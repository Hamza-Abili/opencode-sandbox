/**
 * opencode-sandbox — trusted policy resolution.
 *
 * OpenCode merges project config after user config, so `ctx.options` alone
 * cannot be trusted for security policy: a repository could otherwise set
 * `network: "allow"`, `toolGuard: "off"`, add `~/.ssh` as readable, or pass a
 * provider token. Security-widening settings therefore come only from a file
 * outside the workspace:
 *
 *   - user:    $OPENCODE_CONFIG_DIR/opencode-sandbox.json
 *              (default: ~/.config/opencode/opencode-sandbox.json)
 *   - system:  /etc/opencode/opencode-sandbox.json (Linux)
 *              /Library/Application Support/opencode/opencode-sandbox.json (macOS)
 *
 * The system file is a complete, root-owned baseline. The user file may widen
 * from the defaults; the system file caps it. Plugin options can only tighten
 * the result. A malformed trusted file is ignored in favour of the secure
 * defaults, never partially applied.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { type ParsedOptions, parseOptionsSafe } from "./options.ts";
import { contains } from "./path-utils.ts";
import { DEFAULT_OPTIONS, type SandboxOptions, type WebFetchMode } from "./types.ts";

const POLICY_FILENAME = "opencode-sandbox.json";
const MAX_POLICY_BYTES = 1_048_576;

const KNOWN_KEYS = new Set([
  "network",
  "mode",
  "writablePaths",
  "readablePaths",
  "passEnv",
  "shell",
  "toolGuard",
  "webfetch",
  "webfetchAllowlist",
  "deniedPaths",
  "unsandboxedCommands",
]);

export interface TrustedPolicyPaths {
  user: string;
  system: string;
}

/**
 * Resolve the two trusted policy locations. `OPENCODE_CONFIG_DIR` is honored
 * because OpenCode itself uses it for the user config directory.
 */
export function trustedPolicyPaths(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): TrustedPolicyPaths {
  const home = path.resolve(env.HOME ?? os.homedir());
  const configDir = path.resolve(
    env.OPENCODE_CONFIG_DIR ??
      path.join(env.XDG_CONFIG_HOME ?? path.join(home, ".config"), "opencode")
  );
  const user = path.join(configDir, POLICY_FILENAME);
  const system =
    platform === "darwin"
      ? path.join("/Library/Application Support/opencode", POLICY_FILENAME)
      : platform === "win32"
        ? path.join(env.ProgramData ?? "C:\\ProgramData", "opencode", POLICY_FILENAME)
        : path.join("/etc/opencode", POLICY_FILENAME);
  return { user, system };
}

export interface PolicySource {
  path: string;
  present: boolean;
  used: boolean;
  /** Present and parsed, but skipped because the system policy is invalid. */
  ignored: boolean;
}

export interface ResolvedPolicy {
  options: SandboxOptions;
  warnings: string[];
  errors: string[];
  user: PolicySource;
  system: PolicySource;
}

/** Log trusted-policy problems and the active file, never its contents. */
export function logPolicy(resolved: ResolvedPolicy): void {
  for (const error of resolved.errors) {
    console.error(`[opencode-sandbox] policy: ${error}`);
  }
  for (const warning of resolved.warnings) {
    console.warn(`[opencode-sandbox] policy: ${warning}`);
  }
  if (resolved.user.used) {
    console.log(`[opencode-sandbox] trusted policy: ${resolved.user.path}`);
  } else if (resolved.system.used) {
    console.log(`[opencode-sandbox] trusted policy: ${resolved.system.path}`);
  }
}

interface PolicyContext {
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  /** Test seam; defaults to the real effective uid. */
  uid?: number;
  /** Test seam for policy file locations. */
  paths?: TrustedPolicyPaths;
}

interface LoadedPolicy {
  options?: SandboxOptions;
  errors: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function realOr(value: string): string {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return path.resolve(value);
  }
}

function loadPolicy(
  pathname: string,
  workspace: string,
  kind: "user" | "system",
  uid: number | undefined
): LoadedPolicy {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(pathname);
  } catch {
    return { errors: [] };
  }
  if (!stat.isFile()) {
    return { errors: [`${pathname} is not a regular file; ignoring it`] };
  }
  if (stat.size > MAX_POLICY_BYTES) {
    return { errors: [`${pathname} is larger than ${MAX_POLICY_BYTES} bytes; ignoring it`] };
  }
  if (uid !== undefined) {
    if (kind === "system" && stat.uid !== 0) {
      return { errors: [`${pathname} is not root-owned; ignoring it`] };
    }
    if (kind === "user" && stat.uid !== uid) {
      return { errors: [`${pathname} is not owned by the current user; ignoring it`] };
    }
  }
  if ((stat.mode & 0o022) !== 0) {
    return { errors: [`${pathname} is group/world-writable; ignoring it`] };
  }
  if (contains(realOr(workspace), realOr(pathname))) {
    return { errors: [`${pathname} is inside the workspace; ignoring it`] };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(pathname, "utf8"));
  } catch (error) {
    return {
      errors: [
        `${pathname} is not valid JSON (${error instanceof Error ? error.message : String(error)}); ignoring it`,
      ],
    };
  }
  if (!isRecord(raw)) {
    return { errors: [`${pathname} must contain a JSON object; ignoring it`] };
  }

  const unknown = Object.keys(raw).filter((key) => !KNOWN_KEYS.has(key));
  if (unknown.length > 0) {
    return {
      errors: [
        `${pathname} has unknown option ${unknown.map((key) => JSON.stringify(key)).join(", ")}; ignoring it`,
      ],
    };
  }

  const parsed: ParsedOptions = parseOptionsSafe(raw, workspace);
  if (parsed.errors.length > 0) {
    return {
      errors: parsed.errors.map((message) => `${pathname}: ${message}; ignoring the file`),
    };
  }
  return { options: parsed.options, errors: [] };
}

function strictestWebfetch(
  left: WebFetchMode,
  leftAllowlist: readonly string[],
  right: WebFetchMode,
  rightAllowlist: readonly string[]
): { webfetch: WebFetchMode; allowlist: string[] } {
  if (left === "deny" || right === "deny") return { webfetch: "deny", allowlist: [] };
  const leftOpen = leftAllowlist.length === 0;
  const rightOpen = rightAllowlist.length === 0;
  if (leftOpen && rightOpen) return { webfetch: "allow", allowlist: [] };
  const narrower = leftOpen
    ? rightAllowlist
    : rightOpen
      ? leftAllowlist
      : leftAllowlist.filter((entry) => rightAllowlist.includes(entry));
  if (narrower.length === 0) return { webfetch: "deny", allowlist: [] };
  return { webfetch: "allow", allowlist: [...narrower] };
}

/** Intersect path/env lists: the system file is a cap, not an addition. */
function intersect(values: readonly string[], cap: readonly string[]): string[] {
  return values.filter((value) => cap.includes(value));
}

export function capBySystem(user: SandboxOptions, system: SandboxOptions): SandboxOptions {
  const webfetch = strictestWebfetch(
    user.webfetch,
    user.webfetchAllowlist,
    system.webfetch,
    system.webfetchAllowlist
  );
  return {
    network: system.network === "deny" ? "deny" : user.network,
    mode: system.mode === "enforce" ? "enforce" : user.mode,
    writablePaths: intersect(user.writablePaths, system.writablePaths),
    readablePaths: intersect(user.readablePaths, system.readablePaths),
    passEnv: intersect(user.passEnv, system.passEnv),
    shell: system.shell,
    toolGuard: system.toolGuard === "enforce" ? "enforce" : user.toolGuard,
    webfetch: webfetch.webfetch,
    webfetchAllowlist: webfetch.allowlist,
    deniedPaths: [...new Set([...user.deniedPaths, ...system.deniedPaths])],
    unsandboxedCommands: intersect(user.unsandboxedCommands, system.unsandboxedCommands),
  };
}

function widenWarning(option: string, userPath: string): string {
  return `${option} in plugin options cannot widen the sandbox; set it in ${userPath}`;
}

function trustedOnlyWarning(option: string, userPath: string): string {
  return `${option} is only read from the trusted policy; set it in ${userPath}`;
}

function tighten(
  effective: SandboxOptions,
  plugin: SandboxOptions,
  present: ReadonlySet<keyof SandboxOptions>,
  rawPlugin: unknown,
  userPath: string
): { options: SandboxOptions; warnings: string[] } {
  const warnings: string[] = [];
  const next: SandboxOptions = { ...effective };

  if (present.has("network")) {
    if (plugin.network === "deny") next.network = "deny";
    else if (plugin.network === "allow" && effective.network === "deny") {
      warnings.push(widenWarning("network", userPath));
    }
  }

  if (present.has("mode")) {
    if (plugin.mode === "enforce") next.mode = "enforce";
    else if (effective.mode === "enforce") warnings.push(widenWarning("mode", userPath));
  }

  if (present.has("toolGuard")) {
    if (plugin.toolGuard === "enforce") next.toolGuard = "enforce";
    else if (effective.toolGuard === "enforce") {
      warnings.push(widenWarning("toolGuard", userPath));
    }
  }

  if (present.has("webfetch") || present.has("webfetchAllowlist")) {
    if (next.toolGuard === "enforce") {
      const webfetch = strictestWebfetch(
        effective.webfetch,
        effective.webfetchAllowlist,
        plugin.webfetch,
        plugin.webfetchAllowlist
      );
      next.webfetch = webfetch.webfetch;
      next.webfetchAllowlist = webfetch.allowlist;
    } else {
      warnings.push(
        `webfetch restrictions in plugin options require toolGuard: "enforce" in ${userPath}; ignored`
      );
    }
  }

  if (present.has("writablePaths") && plugin.writablePaths.length > 0) {
    warnings.push(widenWarning("writablePaths", userPath));
  }
  if (present.has("readablePaths") && plugin.readablePaths.length > 0) {
    warnings.push(widenWarning("readablePaths", userPath));
  }
  if (present.has("passEnv") && plugin.passEnv.length > 0) {
    warnings.push(widenWarning("passEnv", userPath));
  }
  if (present.has("deniedPaths") && plugin.deniedPaths.length > 0) {
    warnings.push(trustedOnlyWarning("deniedPaths", userPath));
  }
  if (present.has("unsandboxedCommands") && plugin.unsandboxedCommands.length > 0) {
    warnings.push(widenWarning("unsandboxedCommands", userPath));
  }
  if (present.has("shell") && isRecord(rawPlugin) && plugin.shell !== effective.shell) {
    warnings.push(trustedOnlyWarning("shell", userPath));
  }

  return { options: next, warnings };
}

/**
 * Resolve the policy a sandbox instance will use. Plugin options can only
 * tighten the trusted baseline; security-widening values from a repository
 * config are ignored with a warning.
 */
export function resolveEffectiveOptions(
  rawPluginOptions: unknown,
  workspace: string,
  context: PolicyContext = {}
): ResolvedPolicy {
  const env = context.env ?? process.env;
  const platform = context.platform ?? process.platform;
  const uid = context.uid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  const paths = context.paths ?? trustedPolicyPaths(env, platform);
  const workspaceReal = realOr(workspace);

  const userLoaded = loadPolicy(paths.user, workspaceReal, "user", uid);
  const systemLoaded = loadPolicy(paths.system, workspaceReal, "system", uid);
  const errors = [...userLoaded.errors, ...systemLoaded.errors];
  const systemInvalid = systemLoaded.errors.length > 0;
  if (systemInvalid && userLoaded.options !== undefined) {
    errors.push(`${paths.user} ignored because the system policy is invalid`);
  }

  let effective: SandboxOptions = { ...DEFAULT_OPTIONS };
  if (systemInvalid) {
    // A system policy that is present but invalid must fail safe: do not let
    // the user file run without the administrator's cap.
    effective = { ...DEFAULT_OPTIONS };
  } else {
    if (userLoaded.options !== undefined) effective = { ...userLoaded.options };
    if (systemLoaded.options !== undefined)
      effective = capBySystem(effective, systemLoaded.options);
  }

  const plugin = parseOptionsSafe(rawPluginOptions, workspace);
  for (const error of plugin.errors) errors.push(`plugin options: ${error}`);

  // A malformed plugin option disables all of its tightening: never let a
  // fallback value silently change the trusted policy.
  const tightened =
    plugin.errors.length === 0
      ? tighten(effective, plugin.options, plugin.present, rawPluginOptions, paths.user)
      : { options: effective, warnings: [] };
  return {
    options: tightened.options,
    warnings: tightened.warnings,
    errors,
    user: {
      path: paths.user,
      present: userLoaded.options !== undefined || userLoaded.errors.length > 0,
      used: userLoaded.options !== undefined && !systemInvalid,
      ignored: userLoaded.options !== undefined && systemInvalid,
    },
    system: {
      path: paths.system,
      present: systemLoaded.options !== undefined || systemLoaded.errors.length > 0,
      used: systemLoaded.options !== undefined,
      ignored: false,
    },
  };
}
