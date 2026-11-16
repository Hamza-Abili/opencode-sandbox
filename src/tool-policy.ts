/**
 * opencode-sandbox — in-process tool policy.
 *
 * The OS sandbox covers shell commands. OpenCode's file tools and webfetch do
 * not go through the shell service, so V2 exposes a permission hook for them.
 * This module turns that hook into the same workspace policy:
 *
 *   - read/search: workspace, explicit mounts and the read-only system runtime;
 *   - write/edit/patch: workspace and explicit writable mounts only;
 *   - webfetch: allow, deny, or a hostname allowlist. The webfetch tool
 *     re-checks redirects; image-generator URLs are checked initially only.
 *
 * This is a policy guard, not an OS boundary. It protects against a
 * prompt-injected agent; it cannot contain a compromised OpenCode process or a
 * malicious plugin running in the same process. The shell sandbox remains the
 * kernel-enforced boundary.
 */

import fs from "node:fs";
import path from "node:path";
import { DARWIN_TOOL_READ } from "./darwin.ts";
import { type MountMode, mountPlan } from "./mounts.ts";
import { normalizeHostPattern } from "./options.ts";
import { canonicalTarget, resolvePathKernel } from "./path-utils.ts";
import { LINUX_SYSTEM_READ } from "./profile.ts";
import type { SandboxLayout, SandboxOptions } from "./types.ts";

export interface PermissionEvaluation {
  readonly action: string;
  readonly resources: readonly string[];
  readonly metadata?: Record<string, unknown>;
  effect: "allow" | "ask" | "deny";
  message?: string;
}

/** File and network tools governed by the in-process policy. */
export const GUARDED_TOOLS = new Set([
  "read",
  "write",
  "edit",
  "patch",
  "apply_patch",
  "glob",
  "grep",
  "webfetch",
  // Tools that use the guarded read/edit/webfetch actions but have no
  // dedicated permission action of their own.
  "image_generate",
  "worktree_remove",
  "opencode_worktree_remove",
]);

export function isGuardedTool(tool: string): boolean {
  return GUARDED_TOOLS.has(tool);
}

/** Permission actions covered by the in-process file/network policy. */
export const POLICY_ACTIONS = new Set([
  "read",
  "edit",
  "glob",
  "grep",
  "webfetch",
  // Primary action of image_generate; its read/edit/webfetch sub-actions are
  // already covered, but the provider call must fail closed too.
  "image_generate",
]);

/**
 * Deny every action the policy owns when the policy cannot be built (for
 * example because the workspace is invalid). Unknown actions are left to
 * OpenCode; the tool hook still blocks the fixed guarded-tool list.
 */
export function denyPolicyAction(event: PermissionEvaluation): void {
  if (!POLICY_ACTIONS.has(event.action)) return;
  event.effect = "deny";
  event.message = `[opencode-sandbox] sandbox unavailable; refusing ${event.action} (mode=enforce)`;
}

export interface ToolPolicy {
  /** Canonical workspace root. */
  readonly workspace: string;
  /** Lexical base OpenCode uses to resolve relative tool arguments. */
  readonly resolveBase: string;
  readonly hostHome: string;
  readonly readRoots: readonly string[];
  /** Broad-to-narrow mounts; the deepest match decides write access. */
  readonly mounts: ReadonlyArray<{ path: string; mode: MountMode }>;
  /** Workspace config executed by a host process later; writes are refused. */
  readonly protectedPaths: readonly string[];
  /** Paths hidden from reads and writes. */
  readonly deniedPaths: readonly string[];
  readonly webfetch: "allow" | "deny";
  readonly webfetchAllowlist: readonly string[];
}

function canonicalRoots(values: readonly string[], hostHome: string): string[] {
  const roots = new Set<string>();
  for (const value of values) {
    const absolute = path.resolve(value);
    if (absolute === "/" || absolute === hostHome || within(absolute, hostHome)) continue;
    roots.add(absolute);
    try {
      const real = fs.realpathSync.native(absolute);
      // A symlinked system/temp root must not turn into `/` or an ancestor of
      // the host home. Explicit paths inside the home (for example ~/.ssh as a
      // readable path) remain valid.
      if (real === "/" || real === hostHome || within(real, hostHome)) continue;
      roots.add(real);
    } catch {
      // A missing root cannot contain anything; keep the literal path.
    }
  }
  return [...roots];
}

/**
 * True when target is root or inside it. Both values are canonical absolute
 * paths; realpath resolves the on-disk case, so the comparison stays
 * case-sensitive even on a case-insensitive volume.
 */
function within(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return (
    relative === "" ||
    (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

/**
 * A `.git` below the workspace root is a nested repository/submodule. Its
 * config and hooks are executed by a later host Git command, so the file tools
 * must not write there. The root `.git` is writable (index, objects, refs).
 */
function nestedGitPath(target: string, workspace: string): boolean {
  const relative = path.relative(workspace, target);
  if (relative === "" || relative === ".." || relative.startsWith(`..${path.sep}`)) {
    return false;
  }
  if (path.isAbsolute(relative)) return false;
  return relative.split(path.sep).indexOf(".git") > 0;
}

function allowedBy(roots: readonly string[], target: string): boolean {
  return roots.some((root) => within(root, target));
}

/**
 * V2 resolves `~` through OpenCode's FileAccess helper, so the permission
 * resource is normally already absolute. V1 resolves every argument relative
 * to the project directory and treats `~` as a literal name; the V1 guard must
 * do the same or a `~/../..` argument would be checked against a different
 * path than the one the tool actually uses.
 */
function resolveResource(resource: string, policy: ToolPolicy, expandHome = true): string {
  if (expandHome && resource === "~") return policy.hostHome;
  if (expandHome && resource.startsWith("~/")) {
    return path.join(policy.hostHome, resource.slice(2));
  }
  return path.isAbsolute(resource) ? resource : path.resolve(policy.resolveBase, resource);
}

/**
 * Tools disagree on whether an absolute path is normalized lexically (V1
 * apply_patch, V2 FileAccess) or resolved by the kernel (V1 read/write/glob).
 * Check the lexical target and both kernel walkers; every candidate must pass,
 * so a path cannot be allowed by one interpretation while the tool uses the
 * other.
 */
function pathCandidates(resource: string, policy: ToolPolicy, expandHome = true): string[] {
  const resolved = resolveResource(resource, policy, expandHome);
  const lexical = path.resolve(resolved);
  return [...new Set([lexical, resolvePathKernel(resolved), resolvePathKernel(lexical)])];
}

function isReadAllowed(resource: string, policy: ToolPolicy, expandHome = true): boolean {
  try {
    return pathCandidates(resource, policy, expandHome).every((candidate) => {
      const target = canonicalTarget(candidate);
      if (policy.deniedPaths.some((root) => within(root, target))) return false;
      return allowedBy(policy.readRoots, target);
    });
  } catch {
    return false;
  }
}

function isWriteAllowed(resource: string, policy: ToolPolicy, expandHome = true): boolean {
  try {
    return pathCandidates(resource, policy, expandHome).every((candidate) => {
      const target = canonicalTarget(candidate);
      if (policy.deniedPaths.some((root) => within(root, target))) return false;
      if (policy.protectedPaths.some((root) => within(root, target))) return false;
      if (nestedGitPath(target, policy.workspace)) return false;
      let mode: MountMode | undefined;
      // mountPlan is broad-to-narrow; the deepest matching mount wins, exactly
      // like the Linux bind order and the macOS last-match Seatbelt rules.
      for (const mount of policy.mounts) {
        if (within(mount.path, target)) mode = mount.mode;
      }
      return mode === "rw";
    });
  } catch {
    return false;
  }
}

/**
 * The read tool loads nearby AGENTS.md files as synthetic instructions after a
 * successful internal read. That side effect has no permission check upstream,
 * so a workspace AGENTS.md symlink to a host secret would be read even when the
 * requested file is allowed. Reject the read when any discovered instruction
 * file falls outside the policy.
 */
function instructionLeak(
  resource: string,
  policy: ToolPolicy,
  expandHome = false,
  mode: "v1" | "v2" = "v1",
  internal = true
): string | undefined {
  try {
    if (!internal) return undefined;
    const lexical = path.resolve(resolveResource(resource, policy, expandHome));
    const target = canonicalTarget(lexical);
    const root = canonicalTarget(policy.resolveBase);
    const names = mode === "v2" ? ["AGENTS.md"] : ["AGENTS.md", "CLAUDE.md", "CONTEXT.md"];

    // V1 resolves the lexical path and walks only within the location prefix;
    // V2 resolves the canonical path, skips directory reads, and walks to the
    // location root (or to / for a canonical escape).
    let start: string;
    if (mode === "v2") {
      let info: fs.Stats;
      try {
        info = fs.statSync(target);
      } catch {
        return undefined; // missing target: the read fails before discovery
      }
      start = info.isDirectory() ? target : path.dirname(target);
    } else {
      let info: fs.Stats;
      try {
        info = fs.statSync(lexical);
      } catch {
        return undefined;
      }
      if (info.isDirectory()) return undefined;
      start = path.dirname(lexical);
    }

    const check = (current: string) => {
      for (const name of names) {
        const candidate = path.join(current, name);
        try {
          if (!fs.statSync(candidate).isFile()) continue;
          const real = canonicalTarget(candidate);
          if (real !== target && !isReadAllowed(candidate, policy, false)) return candidate;
        } catch {
          // No instruction file at this level.
        }
      }
      return undefined;
    };

    if (mode === "v1") {
      // V1 walks lexically and stops at the location root; it reads only the
      // first existing instruction filename at each level.
      const rootLex = path.resolve(policy.resolveBase);
      if (!start.startsWith(rootLex)) return undefined;
      let current = start;
      while (current.startsWith(rootLex) && current !== rootLex) {
        for (const name of names) {
          const candidate = path.join(current, name);
          let exists = false;
          try {
            // V1's existsSafe() accepts any type, including FIFOs/devices.
            fs.statSync(candidate);
            exists = true;
          } catch {
            // No instruction file with this name at this level.
          }
          if (!exists) continue;
          const real = canonicalTarget(candidate);
          if (real !== target && !isReadAllowed(candidate, policy, false)) return candidate;
          break; // upstream reads only the first existing name
        }
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
      }
      return undefined;
    }

    let current = start;
    while (true) {
      const currentReal = canonicalTarget(current);
      const aboveRoot = within(currentReal, root);
      // V2 filters out the root and any ancestor of it.
      if (!aboveRoot) {
        const leak = check(current);
        if (leak !== undefined) return leak;
      }
      if (currentReal === root || currentReal === path.sep) break;
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
    return undefined;
  } catch {
    return resource;
  }
}

function matchesHost(pattern: string, host: string): boolean {
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return host === base || host.endsWith(`.${base}`);
  }
  return host === pattern;
}

function isWebfetchAllowed(url: string, policy: ToolPolicy): boolean {
  // OpenCode's schedule pre-check uses "*" as a tool-selection sentinel, not a
  // URL. The actual URL is checked when the tool runs.
  if (url === "*") return policy.webfetch !== "deny";

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  if (policy.webfetch === "deny") return false;
  if (policy.webfetchAllowlist.length === 0) return true;

  const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
  return policy.webfetchAllowlist.some((pattern) => matchesHost(pattern, host));
}

function deny(event: PermissionEvaluation, reason: string): void {
  event.effect = "deny";
  event.message = `[opencode-sandbox] ${reason}`;
}

/**
 * Explain the exact policy that refused a path. Protected and denied paths are
 * not fixable with `writablePaths`, so do not suggest it for those.
 */
function denialReason(
  tool: string,
  resource: string,
  policy: ToolPolicy,
  write: boolean,
  expandHome = true
): string {
  let target = resource;
  try {
    target = canonicalTarget(resolveResource(resource, policy, expandHome));
  } catch {
    // Keep the user-supplied form in the message.
  }
  if (policy.deniedPaths.some((root) => within(root, target))) {
    return `${tool} denied: ${resource} is hidden by deniedPaths`;
  }
  if (write && nestedGitPath(target, policy.workspace)) {
    return `${tool} denied: ${resource} is a nested .git path; only the root .git is writable`;
  }
  if (write && policy.protectedPaths.some((root) => within(root, target))) {
    return `${tool} denied: ${resource} is a protected workspace config path and is read-only`;
  }
  return (
    `${tool} denied: ${resource} is outside the workspace and explicit mounts; ` +
    `add it to readablePaths/writablePaths or set toolGuard: "off"`
  );
}

/**
 * V2 permission hook: deny file access outside the workspace policy and
 * webfetch URLs outside the configured host policy. The `webfetch` tool checks
 * redirects through the same hook; `image_generate` checks its initial image
 * URL only and follows redirects internally.
 */
export function evaluatePermission(event: PermissionEvaluation, policy: ToolPolicy): void {
  if (event.effect === "deny") return;

  switch (event.action) {
    case "read": {
      const denied = event.resources.find(
        (resource) =>
          !isReadAllowed(resource, policy, false) ||
          instructionLeak(resource, policy, false, "v2", !path.isAbsolute(resource)) !== undefined
      );
      if (denied !== undefined) deny(event, denialReason("read", denied, policy, false, false));
      return;
    }
    case "edit": {
      const denied = event.resources.find((resource) => !isWriteAllowed(resource, policy, false));
      if (denied !== undefined) deny(event, denialReason("write", denied, policy, true, false));
      return;
    }
    case "glob":
    case "grep": {
      const raw = event.metadata?.path ?? event.metadata?.root;
      // Only a genuinely absent path falls back to the workspace. A literal
      // "undefined"/"null" is still a path and must be checked as one.
      const search = typeof raw === "string" && raw !== "" ? raw : ".";
      // FileAccess expands `~` for the actual search root.
      if (!isReadAllowed(search, policy, true)) {
        deny(event, denialReason(event.action, search, policy, false, true));
      }
      return;
    }
    case "webfetch": {
      const denied = event.resources.find((resource) => !isWebfetchAllowed(resource, policy));
      if (denied !== undefined) deny(event, `webfetch denied for ${denied}`);
      return;
    }
  }
}

function stringArg(args: Record<string, unknown>, key: string): string | undefined {
  const value = args[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

const PATCH_HEADERS = ["*** Add File:", "*** Update File:", "*** Delete File:", "*** Move to:"];

/**
 * Parse patch headers like the active OpenCode generation: V1 uses the exact
 * line prefix, V2 trims the line before matching.
 */
function patchTargets(text: string, mode: "v1" | "v2"): string[] {
  const targets: string[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    for (const header of PATCH_HEADERS) {
      // V2 trims Add/Update/Delete headers but only trimEnds `*** Move to:`.
      const line =
        mode === "v1" ? rawLine : header === "*** Move to:" ? rawLine.trimEnd() : rawLine.trim();
      if (!line.startsWith(header)) continue;
      const target = line.slice(header.length).trim();
      if (target !== "") targets.push(target);
      break;
    }
  }
  return targets;
}

/**
 * V1 fallback: `tool.execute.before` sees raw tool arguments. It covers the
 * same file tools and the initial webfetch URL, but not redirects (V1 has no
 * permission hook). Missing arguments are left to OpenCode's own validation.
 */
export function guardToolInput(
  tool: string,
  input: unknown,
  policy: ToolPolicy,
  mode: "v1" | "v2" = "v1"
): void {
  if (typeof input !== "object" || input === null || Array.isArray(input)) return;
  const args = input as Record<string, unknown>;
  const expandHome = mode === "v2";

  switch (tool) {
    case "read":
    case "write":
    case "edit": {
      // V2 only reads `path` from these tools; a stale `filePath` key is
      // ignored by the tool schema, so it must not satisfy the guard either.
      const target =
        mode === "v2"
          ? stringArg(args, "path")
          : (stringArg(args, "filePath") ?? stringArg(args, "path"));
      if (target === undefined) return;
      const internal =
        mode === "v2"
          ? within(policy.resolveBase, path.resolve(resolveResource(target, policy, expandHome)))
          : true;
      const allowed =
        tool === "read"
          ? isReadAllowed(target, policy, expandHome) &&
            instructionLeak(target, policy, expandHome, mode, internal) === undefined
          : isWriteAllowed(target, policy, expandHome);
      if (!allowed) {
        throw new Error(
          `[opencode-sandbox] ${denialReason(tool, target, policy, tool !== "read", expandHome)}`
        );
      }
      return;
    }
    case "patch":
    case "apply_patch": {
      const text = stringArg(args, "patchText");
      if (text === undefined) return;
      for (const target of patchTargets(text, mode)) {
        if (!isWriteAllowed(target, policy, expandHome)) {
          throw new Error(
            `[opencode-sandbox] ${denialReason(tool, target, policy, true, expandHome)}`
          );
        }
      }
      return;
    }
    case "glob":
    case "grep": {
      // V1 resolves the literal string. V2 glob normalizes "undefined"/"null"
      // to no path; V2 grep resolves the literal string.
      const raw = stringArg(args, "path");
      const search =
        mode === "v2" && tool === "glob" && (raw === "undefined" || raw === "null")
          ? "."
          : (raw ?? ".");
      if (!isReadAllowed(search, policy, expandHome)) {
        throw new Error(
          `[opencode-sandbox] ${denialReason(tool, search, policy, false, expandHome)}`
        );
      }
      return;
    }
    case "webfetch": {
      const url = stringArg(args, "url");
      if (url !== undefined && !isWebfetchAllowed(url, policy)) {
        throw new Error(`[opencode-sandbox] webfetch denied: ${url} is not allowed`);
      }
      return;
    }
  }
}

export function createToolPolicy(
  layout: SandboxLayout,
  options: SandboxOptions,
  platform: string = process.platform,
  resolveBase: string = layout.workspace
): ToolPolicy {
  const system = platform === "darwin" ? DARWIN_TOOL_READ : LINUX_SYSTEM_READ;
  const allowlist: string[] = [];
  let webfetch: "allow" | "deny" =
    options.webfetch === "allow" || options.webfetch === "deny" ? options.webfetch : "deny";
  const entries = Array.isArray(options.webfetchAllowlist) ? options.webfetchAllowlist : [];
  if (
    !Array.isArray(options.webfetchAllowlist) ||
    !entries.every((entry) => typeof entry === "string")
  ) {
    // A direct caller bypassed parseOptions; fail closed instead of turning a
    // malformed allowlist into allow-all.
    webfetch = "deny";
  } else {
    for (const entry of entries) {
      const normalized = normalizeHostPattern(entry);
      if (normalized === undefined) {
        webfetch = "deny";
        allowlist.length = 0;
        break;
      }
      allowlist.push(normalized);
    }
  }
  const mounts = mountPlan(layout);

  return {
    workspace: layout.workspace,
    resolveBase,
    hostHome: layout.hostHome,
    readRoots: canonicalRoots(
      [layout.workspace, ...layout.writablePaths, ...layout.readablePaths, ...system],
      layout.hostHome
    ),
    mounts,
    protectedPaths: layout.protectedPaths,
    deniedPaths: layout.deniedPaths,
    webfetch,
    webfetchAllowlist: allowlist,
  };
}
