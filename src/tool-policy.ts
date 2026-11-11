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
import os from "node:os";
import path from "node:path";
import { DARWIN_TOOL_READ } from "./darwin.ts";
import { type MountMode, mountPlan } from "./mounts.ts";
import { normalizeHostPattern } from "./options.ts";
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
  /** Lexical base OpenCode uses to resolve relative tool arguments. */
  readonly resolveBase: string;
  readonly hostHome: string;
  readonly readRoots: readonly string[];
  /** Broad-to-narrow mounts; the deepest match decides write access. */
  readonly mounts: ReadonlyArray<{ path: string; mode: MountMode }>;
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
 * Resolve a path the way the kernel does: walk components in order, expand a
 * symlink when it is encountered, then apply later `..` segments to the
 * resolved location. `path.resolve` alone is wrong because it collapses `..`
 * before following a symlink; a workspace link to `.` plus `../` would be
 * checked against a path the tool never opens.
 */
function resolvePathKernel(input: string): string {
  const absolute = path.isAbsolute(input) ? input : path.resolve(input);
  const parts = absolute.split(path.sep).filter(Boolean);
  const resolved: string[] = [];
  let links = 0;
  let index = 0;

  while (index < parts.length) {
    const part = parts[index++];
    if (part === ".") continue;
    if (part === "..") {
      resolved.pop();
      continue;
    }
    resolved.push(part);
    const current = path.sep + resolved.join(path.sep);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch {
      continue;
    }
    if (!stat.isSymbolicLink()) continue;
    if (++links > 40) throw new Error("too many symbolic links");

    const link = fs.readlinkSync(current);
    resolved.pop();
    const linkParts = link.split(path.sep).filter((item) => item !== "");
    if (path.isAbsolute(link)) resolved.length = 0;
    parts.splice(index, 0, ...linkParts);
  }
  return path.sep + resolved.join(path.sep);
}

/** Canonical absolute target; non-existent suffixes are resolved through the nearest existing ancestor. */
function canonicalTarget(input: string): string {
  const expanded = resolvePathKernel(input);
  try {
    return fs.realpathSync.native(expanded);
  } catch {
    // Fall through to the nearest existing ancestor.
  }

  let current = expanded;
  const suffix: string[] = [];
  while (true) {
    const parent = path.dirname(current);
    if (parent === current) return expanded;
    suffix.push(path.basename(current));
    try {
      return path.join(fs.realpathSync.native(parent), ...suffix.reverse());
    } catch {
      current = parent;
    }
  }
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

function allowedBy(roots: readonly string[], target: string): boolean {
  return roots.some((root) => within(root, target));
}

/**
 * OpenCode's temp directory, but only when it stays inside the canonical temp
 * base. `/tmp` is world-writable: a stale or attacker-created
 * `/tmp/opencode -> /` must not add `/` to the read roots.
 */
function openCodeTempRoot(hostHome: string): string | undefined {
  try {
    const base = fs.realpathSync.native(os.tmpdir());
    // A user-set TMPDIR inside the home directory would let a pre-existing
    // symlink turn the temp root into a credential directory.
    if (base === hostHome || within(hostHome, base)) return undefined;

    const entry = path.join(os.tmpdir(), "opencode");
    // OpenCode creates this as a directory. A symlink is stale/attacker
    // controlled and must not become a read root, even if it points inside the
    // temp base.
    try {
      if (fs.lstatSync(entry).isSymbolicLink()) return undefined;
    } catch {
      // Not created yet; the canonical candidate below is still checked.
    }

    const candidate = canonicalTarget(entry);
    if (candidate === base || !within(base, candidate)) return undefined;
    // Never add the host home, a descendant, or an ancestor through the temp
    // root; explicit readablePaths remain the way to grant those.
    if (candidate === hostHome || within(hostHome, candidate) || within(candidate, hostHome)) {
      return undefined;
    }
    return candidate;
  } catch {
    return undefined;
  }
}

/**
 * OpenCode retains truncated tool output under its data directory and tells
 * the model to read it. That one directory is read-only in the policy; the
 * rest of the data directory remains outside.
 */
function openCodeToolOutputRoot(hostHome: string): string | undefined {
  try {
    const dataHome = process.env.XDG_DATA_HOME;
    const data =
      dataHome !== undefined && path.isAbsolute(dataHome)
        ? path.resolve(dataHome)
        : path.join(hostHome, ".local", "share");
    const dataReal = canonicalTarget(data);
    const base = canonicalTarget(path.join(data, "opencode"));
    // `opencode` must stay inside the data root; a symlink to ~/.ssh must not
    // turn its tool-output child into a read root.
    if (base === dataReal || !within(dataReal, base)) return undefined;
    const entry = path.join(data, "opencode", "tool-output");
    try {
      if (fs.lstatSync(entry).isSymbolicLink()) return undefined;
    } catch {
      // Not created yet; the canonical candidate below is still checked.
    }
    const candidate = canonicalTarget(entry);
    if (candidate === base || !within(base, candidate)) return undefined;
    if (candidate === hostHome || within(candidate, hostHome)) return undefined;
    return candidate;
  } catch {
    return undefined;
  }
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
    return pathCandidates(resource, policy, expandHome).every((candidate) =>
      allowedBy(policy.readRoots, canonicalTarget(candidate))
    );
  } catch {
    return false;
  }
}

function isWriteAllowed(resource: string, policy: ToolPolicy, expandHome = true): boolean {
  try {
    return pathCandidates(resource, policy, expandHome).every((candidate) => {
      const target = canonicalTarget(candidate);
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
  event.message =
    `[opencode-sandbox] ${reason}; allow it explicitly with ` +
    `readablePaths/writablePaths/webfetchAllowlist, or set toolGuard: "off"`;
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
      if (denied !== undefined) deny(event, `read denied for ${denied}`);
      return;
    }
    case "edit": {
      const denied = event.resources.find((resource) => !isWriteAllowed(resource, policy, false));
      if (denied !== undefined) deny(event, `write denied for ${denied}`);
      return;
    }
    case "glob":
    case "grep": {
      const raw = event.metadata?.path ?? event.metadata?.root;
      // Only a genuinely absent path falls back to the workspace. A literal
      // "undefined"/"null" is still a path and must be checked as one.
      const search = typeof raw === "string" && raw !== "" ? raw : ".";
      // FileAccess expands `~` for the actual search root.
      if (!isReadAllowed(search, policy, true)) deny(event, `search denied for ${search}`);
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

function denial(tool: string, target: string): string {
  return (
    `[opencode-sandbox] ${tool} denied: ${target} is outside the workspace and explicit mounts; ` +
    `add it to readablePaths/writablePaths or set toolGuard: "off"`
  );
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
      if (!allowed) throw new Error(denial(tool, target));
      return;
    }
    case "patch":
    case "apply_patch": {
      const text = stringArg(args, "patchText");
      if (text === undefined) return;
      for (const target of patchTargets(text, mode)) {
        if (!isWriteAllowed(target, policy, expandHome)) throw new Error(denial(tool, target));
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
      if (!isReadAllowed(search, policy, expandHome)) throw new Error(denial(tool, search));
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
  const temp = openCodeTempRoot(layout.hostHome);
  const toolOutput = openCodeToolOutputRoot(layout.hostHome);
  const mounts = mountPlan(layout);

  return {
    resolveBase,
    hostHome: layout.hostHome,
    readRoots: canonicalRoots(
      [
        layout.workspace,
        ...layout.writablePaths,
        ...layout.readablePaths,
        ...system,
        // OpenCode stores generated and pasted images here; the read tool must
        // be able to open them even though it is outside the workspace.
        ...(temp === undefined ? [] : [temp]),
        // Truncated tool output is retained here and the model is told to read it.
        ...(toolOutput === undefined ? [] : [toolOutput]),
      ],
      layout.hostHome
    ),
    mounts,
    webfetch,
    webfetchAllowlist: allowlist,
  };
}
