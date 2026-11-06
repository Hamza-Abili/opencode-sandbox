/**
 * opencode-sandbox — path validation.
 *
 * Security rules that must hold before any profile is built:
 *   - the workspace is a real directory, not `/`;
 *   - the workspace is never the host home or an ancestor of it;
 *   - every extra mount is canonical (symlinks resolved) and exists;
 *   - reparse points that resolve to `/` are rejected;
 *   - a command working directory must be inside a mounted tree.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SandboxLayout } from "./types.ts";

function real(pathname: string): string {
  return fs.realpathSync.native(pathname);
}

function statOrNull(pathname: string): fs.Stats | null {
  try {
    return fs.statSync(pathname);
  } catch {
    return null;
  }
}

/** True when `target` is `root` or inside it (both canonical, absolute). */
export function contains(root: string, target: string): boolean {
  return (
    target === root || target.startsWith(root.endsWith(path.sep) ? root : `${root}${path.sep}`)
  );
}

/**
 * Credential directories that must never become the writable workspace or an
 * extra writable mount. A project opened inside one of these would otherwise
 * hand the agent control of `authorized_keys`, cloud credentials or OpenCode's
 * own auth store. Explicit read-only mounts remain available as a deliberate
 * user decision.
 */
const SENSITIVE_HOME_PATHS = [
  ".ssh",
  ".aws",
  ".azure",
  ".gnupg",
  ".kube",
  ".docker",
  ".password-store",
  ".config/gcloud",
  ".config/gh",
  ".config/opencode",
  ".local/share/opencode",
  ".local/state/opencode",
  "Library/Application Support/opencode",
  ".npmrc",
  ".netrc",
  ".git-credentials",
  "Library/Keychains",
];

/**
 * Host filesystem roots that must never be writable, whether as the workspace
 * or as an extra mount. A writable `/etc`, `/usr/local`, `/run` or `/nix/store`
 * is host compromise, not project sandboxing; read-only access remains
 * available through `readablePaths`.
 */
const SYSTEM_WRITE_ROOTS = [
  "/etc",
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/lib32",
  "/boot",
  "/dev",
  "/proc",
  "/sys",
  "/run",
  "/var",
  "/System",
  "/Library",
  "/Applications",
  "/private",
  "/nix/store",
  "/opt",
  "/usr/local",
];

/**
 * Explicit exceptions under the roots above: temp directories and the common
 * web document root. `/var/tmp` and `/tmp` are normal project/scratch
 * locations; `/var/lib`, `/var/log`, `/var/spool`, `/run` and the rest stay
 * protected by their parent roots.
 */
const SYSTEM_WRITE_ALLOW = [
  "/var/tmp",
  "/private/var/tmp",
  "/var/folders",
  "/private/var/folders",
  "/var/www",
  "/private/var/www",
  "/private/tmp",
];

function rejectSystemWritable(target: string, label: string): void {
  if (SYSTEM_WRITE_ALLOW.some((allowed) => contains(allowed, target))) return;
  for (const system of SYSTEM_WRITE_ROOTS) {
    if (contains(system, target) || contains(target, system)) {
      throw new Error(`${label} ${target} is a host system path; it cannot be writable`);
    }
  }
}

function sensitiveRoots(hostHome: string): string[] {
  const roots: string[] = [];
  for (const relative of SENSITIVE_HOME_PATHS) {
    const candidate = path.join(hostHome, relative);
    try {
      roots.push(real(candidate));
    } catch {
      // not present on this host
    }
  }
  return roots;
}

function rejectSensitive(target: string, homes: string[], label: string): void {
  for (const home of homes) {
    for (const sensitive of sensitiveRoots(home)) {
      if (contains(sensitive, target) || contains(target, sensitive)) {
        throw new Error(
          `${label} ${target} overlaps a credential directory; use a narrower project path`
        );
      }
    }
  }
}

function uid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

/** Parse the local passwd database; Bun's os.userInfo() follows $HOME. */
function passwdHome(): string | undefined {
  const id = uid();
  if (id === undefined) return undefined;
  try {
    for (const line of fs.readFileSync("/etc/passwd", "utf8").split("\n")) {
      const fields = line.split(":");
      if (fields.length < 6 || fields[2] !== String(id) || fields[5] === "") continue;
      try {
        return real(fields[5]);
      } catch {
        return undefined;
      }
    }
  } catch {
    // no local passwd file
  }
  return undefined;
}

function directoryServiceHome(): string | undefined {
  if (process.platform !== "darwin") return undefined;
  const id = uid();
  if (id === undefined) return undefined;
  try {
    // Resolve the username by UID, never from USER/os.userInfo(): Bun reads
    // both from the environment, which is exactly what an attacker can spoof.
    const list = Bun.spawnSync({
      cmd: ["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"],
      stdout: "pipe",
      stderr: "pipe",
      timeout: 2000,
    });
    if (list.exitCode === 0) {
      const username = list.stdout
        .toString()
        .split("\n")
        .map((line) => line.trim().split(/\s+/))
        .find((fields) => fields.length >= 2 && fields[1] === String(id))?.[0];
      if (username) {
        const read = Bun.spawnSync({
          cmd: ["/usr/bin/dscl", ".", "-read", `/Users/${username}`, "NFSHomeDirectory"],
          stdout: "pipe",
          stderr: "pipe",
          timeout: 2000,
        });
        if (read.exitCode === 0) {
          const match = read.stdout.toString().match(/NFSHomeDirectory:\s*(\S+)/);
          if (match?.[1]) return real(match[1]);
        }
      }
    }

    // Older macOS images may not expose dscl -list; dscacheutil is the
    // supported fallback and is also keyed by the numeric UID.
    const cache = Bun.spawnSync({
      cmd: ["/usr/bin/dscacheutil", "-q", "user", "-a", "uid", String(id)],
      stdout: "pipe",
      stderr: "pipe",
      timeout: 2000,
    });
    if (cache.exitCode === 0) {
      const match = cache.stdout.toString().match(/^dir:\s*(\S+)/m);
      if (match?.[1]) return real(match[1]);
    }
  } catch {
    // fall through to the environment
  }
  return undefined;
}

function environmentHome(): string | undefined {
  try {
    return real(os.homedir());
  } catch {
    return os.homedir();
  }
}

/**
 * Every home value the process could mean. The passwd/OpenDirectory value is
 * authoritative for the "host home" guard; the environment value is checked
 * too because a launcher may deliberately point HOME elsewhere.
 */
function homeDirectories(override?: string): string[] {
  if (override !== undefined) return [real(override)];
  const candidates = [passwdHome(), directoryServiceHome(), environmentHome()].filter(
    (value): value is string => value !== undefined
  );
  return [...new Set(candidates)];
}

function canonicalDirectory(pathname: string, label: string): string {
  let resolved: string;
  try {
    resolved = real(pathname);
  } catch {
    throw new Error(`${label} ${pathname} does not exist`);
  }
  if (resolved === "/") throw new Error(`${label} must not be the filesystem root`);
  const stat = statOrNull(resolved);
  if (stat === null || !stat.isDirectory())
    throw new Error(`${label} ${resolved} is not a directory`);
  return resolved;
}

function canonicalMount(pathname: string, label: string): string {
  let resolved: string;
  try {
    resolved = real(pathname);
  } catch {
    throw new Error(`${label} ${pathname} does not exist`);
  }
  if (resolved === "/") throw new Error(`${label} must not be the filesystem root`);
  if (statOrNull(resolved) === null) throw new Error(`${label} ${pathname} does not exist`);
  return resolved;
}

function validateMount(
  pathname: string,
  homes: string[],
  label: string,
  checkSensitive: boolean
): string {
  const resolved = canonicalMount(pathname, label);
  for (const home of homes) {
    if (resolved === home) throw new Error(`${label} must not be the host home`);
    if (contains(resolved, home)) {
      throw new Error(`${label} must not contain the host home (use a narrower path)`);
    }
  }
  if (checkSensitive) {
    rejectSensitive(resolved, homes, label);
    rejectSystemWritable(resolved, label);
  }
  return resolved;
}

/**
 * Resolve and validate everything the profile will mount.
 *
 * The workspace may be inside the home directory (the normal case) but never
 * equal to it and never an ancestor of it: in both cases `.ssh`, browser
 * profiles, cloud credentials and OpenCode's own config would become the
 * writable project.
 */
export function resolveLayout(
  workspace: string,
  options: {
    writablePaths: string[];
    readablePaths: string[];
  },
  homeOverride?: string
): SandboxLayout {
  const homes = homeDirectories(homeOverride);
  const hostHome = homes[0] ?? environmentHome();

  const root = canonicalDirectory(workspace, "workspace");
  for (const home of homes) {
    if (root === home) {
      throw new Error(
        "refusing to use the host home as the workspace; open OpenCode in a project directory"
      );
    }
    if (contains(root, home)) {
      throw new Error(
        `refusing to use ${root} as the workspace: it contains the host home and would expose credentials`
      );
    }
    rejectSensitive(root, [home], "workspace");
  }
  rejectSystemWritable(root, "workspace");

  const writable = new Set<string>();
  for (const item of options.writablePaths) {
    const resolved = validateMount(item, homes, "writable path", true);
    if (resolved !== root) writable.add(resolved);
  }

  const readable = new Set<string>();
  for (const item of options.readablePaths) {
    const resolved = validateMount(item, homes, "readable path", false);
    readable.add(resolved);
  }

  if (readable.has(root)) {
    throw new Error("the workspace cannot be listed as a readable path; it is always writable");
  }
  for (const target of readable) {
    if (writable.has(target)) {
      throw new Error(`path ${target} is both writable and readable; choose one`);
    }
  }

  return {
    workspace: root,
    hostHome,
    writablePaths: [...writable],
    readablePaths: [...readable],
  };
}

/** Mount roots a command may use as its working directory. */
export function mountRoots(layout: SandboxLayout): string[] {
  return [layout.workspace, ...layout.writablePaths, ...layout.readablePaths];
}

/**
 * Resolve a requested working directory and require it to be inside a mounted
 * tree. The wrapper repeats this check with the real process cwd (`pwd -P`) so
 * a symlink swapped after this call still cannot escape.
 */
export function resolveCwd(layout: SandboxLayout, cwd: string | undefined): string {
  const requested = cwd === undefined || cwd === "" ? layout.workspace : cwd;
  const absolute = path.resolve(layout.workspace, requested);
  let resolved: string;
  try {
    resolved = real(absolute);
  } catch {
    throw new Error(`working directory ${absolute} does not exist`);
  }
  const stat = statOrNull(resolved);
  if (stat === null || !stat.isDirectory()) {
    throw new Error(`working directory ${resolved} is not a directory`);
  }
  if (!mountRoots(layout).some((root) => contains(root, resolved))) {
    throw new Error(`working directory ${resolved} is outside the sandboxed workspace`);
  }
  return resolved;
}
