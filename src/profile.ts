/**
 * opencode-sandbox — bubblewrap profile builder (pure).
 *
 * The sandbox starts from an empty mount namespace: only the system runtime,
 * a synthetic home, the workspace (read-write) and explicitly allowed paths
 * are visible. Ambient environment variables are cleared and re-added from an
 * allowlist, so provider tokens and host secrets do not reach commands.
 *
 * No working directory is baked here: the generated wrapper uses the real
 * process cwd (`pwd -P`) after validating it, so OpenCode's own workdir
 * handling is preserved.
 */

import fs from "node:fs";
import path from "node:path";
import { mountPlan } from "./mounts.ts";
import { contains } from "./path-utils.ts";
import { ENV_ALLOWLIST, type LinuxProfileInput, RESERVED_ENV } from "./types.ts";

export const LINUX_SYSTEM_READ = [
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/lib32",
  "/etc",
  "/usr/local",
  "/opt",
  "/nix/store",
];

const DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin";

function visiblePath(layout: LinuxProfileInput["layout"], target: string): boolean {
  const roots = [
    ...LINUX_SYSTEM_READ,
    "/run/current-system",
    layout.workspace,
    ...layout.writablePaths,
    ...layout.readablePaths,
  ];
  return roots.some((root) => contains(root, target) || contains(target, root));
}

function lstatOrNull(target: string): fs.Stats | null {
  try {
    return fs.lstatSync(target);
  } catch {
    return null;
  }
}

function realpathOrNull(target: string): string | null {
  try {
    return fs.realpathSync.native(target);
  } catch {
    return null;
  }
}

/** Mirror a host path into the sandbox (symlink as symlink, directory read-only). */
function bindSystem(args: string[], target: string): void {
  const stat = lstatOrNull(target);
  if (stat === null) return;
  if (stat.isSymbolicLink()) {
    args.push("--symlink", fs.readlinkSync(target), target);
    return;
  }
  if (stat.isDirectory() || stat.isFile()) args.push("--ro-bind", target, target);
}

/** Keep only PATH entries that exist inside the sandbox, then add safe defaults. */
export function sandboxPath(hostPath: string | undefined, roots: readonly string[]): string {
  const kept: string[] = [];
  for (const entry of (hostPath ?? "").split(":")) {
    if (!path.isAbsolute(entry)) continue;
    if (roots.some((root) => entry === root || entry.startsWith(`${root}/`))) kept.push(entry);
  }
  for (const entry of DEFAULT_PATH.split(":")) kept.push(entry);
  return [...new Set(kept)].join(":");
}

const VISIBLE_PARENTS = [
  "/etc",
  "/tmp",
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib64",
  "/lib32",
  "/usr/local",
  "/opt",
  "/nix/store",
  "/home/sandbox",
];

function visibleParent(parent: string): boolean {
  if (parent === "/run") return true;
  return VISIBLE_PARENTS.some((root) => parent === root || parent.startsWith(`${root}/`));
}

function bindResolvConf(args: string[]): void {
  const resolved = realpathOrNull("/etc/resolv.conf");
  if (resolved === null || resolved === "/") return;
  try {
    if (!fs.statSync(resolved).isFile()) return;
  } catch {
    return;
  }
  const parent = path.dirname(resolved);
  if (!visibleParent(parent)) {
    let current = "";
    for (const part of parent.split("/").filter(Boolean)) {
      current += `/${part}`;
      if (current === "/run") continue;
      args.push("--dir", current);
    }
  }
  args.push("--ro-bind", resolved, resolved);
}

function envValue(args: string[], key: string, value: string | undefined): void {
  if (value === undefined) return;
  if (RESERVED_ENV.has(key)) return;
  args.push("--setenv", key, value);
}

export function buildLinuxProfile(input: LinuxProfileInput): string[] {
  const { layout } = input;
  const args: string[] = [
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    "--cap-drop",
    "ALL",
    "--hostname",
    "sandbox",
  ];
  if (input.network === "allow") args.push("--share-net");

  for (const target of LINUX_SYSTEM_READ) bindSystem(args, target);

  args.push("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/run");

  // NixOS exposes its system profile through /run; the symlink target lives
  // in /nix/store, which is mounted above.
  bindSystem(args, "/run/current-system");
  bindSystem(args, "/run/opengl-driver");

  // DNS needs the real resolv.conf target when the network is shared; /etc is
  // read-only and the symlink target usually lives under /run. Binding over
  // the /etc/resolv.conf symlink fails, so bind the resolved file and create
  // its parent directories inside the sandbox.
  if (input.network === "allow") bindResolvConf(args);

  // Synthetic home plus the XDG directories tools expect to exist.
  args.push("--dir", "/home/sandbox");
  for (const dir of [".cache", ".config", ".local", ".local/share", ".local/state"]) {
    args.push("--dir", `/home/sandbox/${dir}`);
  }

  // Broad to narrow: a later bind shadows an earlier one, so a more specific
  // writable path wins over a broader readable parent and a more specific
  // readable subdirectory overrides the writable workspace. Protected-path
  // ancestor directories are merged as rw pins so no ancestor can be renamed;
  // a more specific child mount is emitted after its pin and keeps its mode.
  const mounts = mountPlan(layout);
  const mountPaths = new Set(mounts.map((mount) => mount.path));
  const pinMode = (target: string): "rw" | "ro" => {
    let mode: "rw" | "ro" = "rw";
    for (const mount of mounts) {
      if (contains(mount.path, target)) mode = mount.mode;
    }
    return mode;
  };
  const pins = new Map<string, "rw" | "ro">();
  for (const target of layout.protectedPaths) {
    let current = path.dirname(target);
    while (current !== layout.workspace && contains(layout.workspace, current)) {
      if (!mountPaths.has(current) && !pins.has(current)) {
        try {
          if (fs.statSync(current).isDirectory()) pins.set(current, pinMode(current));
        } catch {
          // Missing ancestors cannot be pinned; the protected path is missing too.
        }
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  }
  const plan = [...mounts, ...[...pins].map(([pinPath, mode]) => ({ path: pinPath, mode }))].sort(
    (left, right) =>
      left.path.split(path.sep).length - right.path.split(path.sep).length ||
      left.path.localeCompare(right.path)
  );
  for (const mount of plan) {
    args.push(mount.mode === "rw" ? "--bind" : "--ro-bind", mount.path, mount.path);
  }

  // Config that a host process executes later (OpenCode/Git/direnv) must stay
  // read-only even when the workspace is writable. These binds come after the
  // mount plan so they also override a more specific writable child.
  for (const target of layout.protectedPaths) {
    let resolved: string;
    try {
      resolved = fs.realpathSync.native(target);
    } catch {
      // Missing protected paths cannot be bind-mounted; the tool guard still
      // denies writes through the file tools (documented Linux gap).
      continue;
    }
    // Never bind a path outside the workspace through a repository-controlled
    // parent symlink; protected binds are workspace-only.
    if (!contains(layout.workspace, resolved)) continue;
    args.push("--ro-bind", resolved, resolved);
  }

  // Denied files are replaced by /dev/null and denied directories by an empty
  // tmpfs. Apply them last so they win over every other mount. Paths outside
  // the mounted trees are not visible anyway and need no mask.
  for (const target of layout.deniedPaths) {
    let resolved: string;
    try {
      resolved = fs.realpathSync.native(target);
    } catch {
      continue;
    }
    if (!visiblePath(layout, resolved)) continue;
    let directory = false;
    try {
      directory = fs.statSync(resolved).isDirectory();
    } catch {
      continue;
    }
    if (directory) {
      args.push("--tmpfs", resolved);
    } else {
      args.push("--ro-bind", "/dev/null", resolved);
    }
  }

  const roots = [
    ...LINUX_SYSTEM_READ,
    "/run/current-system",
    layout.workspace,
    ...layout.writablePaths,
    ...layout.readablePaths,
  ];

  args.push("--clearenv");
  args.push("--setenv", "HOME", "/home/sandbox");
  args.push("--setenv", "TMPDIR", "/tmp");
  args.push("--setenv", "PATH", sandboxPath(input.env.PATH, roots));
  args.push("--setenv", "SHELL", input.shell);
  args.push("--setenv", "USER", "sandbox");
  args.push("--setenv", "LOGNAME", "sandbox");
  args.push("--setenv", "XDG_CACHE_HOME", "/home/sandbox/.cache");
  args.push("--setenv", "XDG_CONFIG_HOME", "/home/sandbox/.config");
  args.push("--setenv", "XDG_DATA_HOME", "/home/sandbox/.local/share");

  for (const key of ENV_ALLOWLIST) envValue(args, key, input.env[key]);
  for (const key of input.passEnv) envValue(args, key, input.env[key]);

  return args;
}
