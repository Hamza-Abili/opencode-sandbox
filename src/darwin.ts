/**
 * opencode-sandbox — macOS Seatbelt profile builder (pure).
 *
 * Native `sandbox-exec`, zero dependencies. The profile starts from deny
 * default: processes may exec and read the system runtime, the workspace, the
 * synthetic home and explicit paths. Writes are broad-to-narrow per-path
 * rules: the workspace, synthetic home and temp dirs are writable, while
 * explicit readable paths get a `deny file-write*` rule. The host home is not
 * readable, so `~/.ssh`, `~/.aws` and OpenCode's own credentials are outside
 * the boundary.
 *
 * Seatbelt is last matching rule wins: write rules are sorted by depth so a
 * more specific readable subdirectory overrides a broader writable mount, and
 * a more specific writable child re-allows its own subtree.
 */

import fs from "node:fs";
import path from "node:path";
import { type MountMode, mountPlan, pathDepth } from "./mounts.ts";
import { sandboxPath } from "./profile.ts";
import { type DarwinProfileInput, ENV_ALLOWLIST, RESERVED_ENV } from "./types.ts";

/**
 * Tool-guard read roots: the system runtime without the broad temp and device
 * trees. The file tools get OpenCode's own temp directory explicitly, so they
 * do not need `/tmp`, `/var/folders` or `/dev`.
 */
export const DARWIN_TOOL_READ = [
  "/System/Library",
  "/System/Cryptexes",
  "/System/Applications",
  "/System/Volumes/Preboot",
  "/System/DriverKit",
  "/usr",
  "/bin",
  "/sbin",
  "/Library",
  "/Applications",
  "/opt",
  "/usr/local",
  "/etc",
  "/private/etc",
  "/private/var/db",
  "/private/var/select",
  "/var/run",
  "/private/var/run",
  "/nix/store",
];

export const DARWIN_SYSTEM_READ = [
  // Never grant "/System": on macOS the data volume is mounted at
  // /System/Volumes/Data, which would expose /Users/<user> and every secret.
  "/System/Library",
  "/System/Cryptexes",
  "/System/Applications",
  "/System/Volumes/Preboot",
  "/System/DriverKit",
  "/usr",
  "/bin",
  "/sbin",
  "/Library",
  "/Applications",
  "/opt",
  "/usr/local",
  "/etc",
  "/private/etc",
  "/private/var/db",
  "/private/var/select",
  "/var/run",
  "/private/var/run",
  "/tmp",
  "/private/tmp",
  "/var/folders",
  "/private/var/folders",
  "/dev",
  "/nix/store",
];

const DEV_WRITE = ["/dev/null", "/dev/tty", "/dev/stdout", "/dev/stderr", "/dev/dtracehelper"];

function literal(value: string): string {
  return JSON.stringify(value);
}

function subpath(value: string): string {
  return `(subpath ${literal(value)})`;
}

function existing(target: string): boolean {
  try {
    fs.lstatSync(target);
    return true;
  } catch {
    return false;
  }
}

/** Include both the alias and its canonical target; Seatbelt matches strings. */
function addPath(set: Set<string>, target: string): void {
  if (!existing(target)) return;
  set.add(target);
  try {
    set.add(fs.realpathSync.native(target));
  } catch {
    // keep the alias only
  }
  // resolveLayout returns canonical /private/... paths; a process may still
  // use the /var, /tmp or /etc alias, which Seatbelt treats as a different
  // string. Add the alias too when it exists.
  if (target.startsWith("/private/")) {
    const alias = target.slice("/private".length);
    if (existing(alias)) set.add(alias);
  }
}

function readRoots(input: DarwinProfileInput): string[] {
  const roots = new Set<string>();
  for (const target of DARWIN_SYSTEM_READ) addPath(roots, target);
  addPath(roots, input.layout.workspace);
  addPath(roots, input.home);
  // A writable path is read-write on Linux; keep the same semantics here.
  for (const target of input.layout.writablePaths) addPath(roots, target);
  for (const target of input.layout.readablePaths) addPath(roots, target);
  return [...roots];
}

interface WriteRule {
  path: string;
  mode: MountMode;
  priority: number;
}

/**
 * Add a path and its canonical target. Seatbelt matches strings, so both the
 * alias and the real path need a rule. A user mount (priority 1) overrides a
 * default home/temp write root (priority 0) for the same path.
 */
function addWriteRule(
  rules: Map<string, WriteRule>,
  target: string,
  mode: MountMode,
  priority: number
): void {
  if (!existing(target)) return;
  const candidates = [target];
  try {
    const real = fs.realpathSync.native(target);
    if (real !== target) candidates.push(real);
  } catch {
    // keep the literal path only
  }
  if (target.startsWith("/private/")) {
    const alias = target.slice("/private".length);
    if (existing(alias)) candidates.push(alias);
  }
  for (const candidate of candidates) {
    const previous = rules.get(candidate);
    if (previous === undefined || priority >= previous.priority) {
      rules.set(candidate, { path: candidate, mode, priority });
    }
  }
}

/**
 * Write rules in broad-to-narrow order. Seatbelt is last-match-wins, so a
 * readable subdirectory denies writes after the writable workspace allows
 * them, while a writable child of a readable parent re-allows its own subtree.
 */
function writeRules(input: DarwinProfileInput): WriteRule[] {
  const rules = new Map<string, WriteRule>();
  addWriteRule(rules, input.home, "rw", 0);
  for (const target of ["/tmp", "/private/tmp", "/var/folders", "/private/var/folders"]) {
    addWriteRule(rules, target, "rw", 0);
  }
  for (const mount of mountPlan(input.layout)) {
    addWriteRule(rules, mount.path, mount.mode, 1);
  }
  return [...rules.values()].sort(
    (left, right) =>
      pathDepth(left.path) - pathDepth(right.path) || left.path.localeCompare(right.path)
  );
}

export function buildDarwinProfile(input: DarwinProfileInput): string {
  const reads = readRoots(input);
  const writes = writeRules(input);
  const rules: string[] = [
    "(version 1)",
    "(deny default)",
    "",
    "; Process and IPC basics",
    "(allow process-exec)",
    "(allow process-fork)",
    "(allow process-info* (target same-sandbox))",
    "(allow signal (target same-sandbox))",
    "(allow mach-priv-task-port (target same-sandbox))",
    "(allow user-preference-read)",
    "(allow ipc-posix-shm)",
    "(allow ipc-posix-sem)",
    "(allow sysctl-read)",
    "(deny sysctl-read",
    '  (sysctl-name "kern.procargs")',
    '  (sysctl-name "kern.procargs2")',
    ")",
    "(allow mach-lookup",
    '  (global-name "com.apple.audio.systemsoundserver")',
    '  (global-name "com.apple.distributed_notifications@Uv3")',
    '  (global-name "com.apple.FontObjectsServer")',
    '  (global-name "com.apple.fonts")',
    '  (global-name "com.apple.logd")',
    '  (global-name "com.apple.lsd.mapdb")',
    '  (global-name "com.apple.PowerManagement.control")',
    '  (global-name "com.apple.system.logger")',
    '  (global-name "com.apple.system.notification_center")',
    '  (global-name "com.apple.system.opendirectoryd.libinfo")',
    '  (global-name "com.apple.system.opendirectoryd.membership")',
    '  (global-name "com.apple.bsd.dirhelper")',
    '  (global-name "com.apple.securityd.xpc")',
    '  (global-name "com.apple.coreservices.launchservicesd")',
    '  (global-name "com.apple.SecurityServer")',
    ")",
    "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
    "(allow iokit-open",
    '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
    '  (iokit-registry-entry-class "RootDomainUserClient")',
    '  (iokit-user-client-class "IOSurfaceSendRight")',
    ")",
    "(allow iokit-get-properties)",
    "(allow file-ioctl)",
    "(allow pseudo-tty)",
    "",
    "; Metadata everywhere (stat/traverse), contents only from allowlisted roots",
    "(allow file-read-metadata)",
    `(allow file-read* (literal "/"))`,
    `(allow file-read* ${reads.map(subpath).join(" ")})`,
    "",
    "; Writes: broad to narrow; the last matching rule wins",
    ...writes.map(
      (rule) => `(${rule.mode === "rw" ? "allow" : "deny"} file-write* ${subpath(rule.path)})`
    ),
    `(allow file-write* ${DEV_WRITE.filter(existing)
      .map((item) => `(literal ${literal(item)})`)
      .join(" ")})`,
    '(allow file-read* file-write* (regex #"^/dev/ttys"))',
  ];

  if (input.network === "allow") {
    rules.push(
      "",
      "; Network explicitly allowed: DNS and TLS Mach services",
      "(allow mach-lookup",
      '  (global-name "com.apple.networkd")',
      '  (global-name "com.apple.networkd.settings")',
      '  (global-name "com.apple.SystemConfiguration.configd")',
      '  (global-name "com.apple.SystemConfiguration.DNSConfiguration")',
      '  (global-name "com.apple.dnssd.service")',
      '  (global-name "com.apple.TrustEvaluationAgent")',
      '  (global-name "com.apple.trustd")',
      '  (global-name "com.apple.trustd.agent")',
      ")",
      "(allow network*)"
    );
  }

  return rules.join("\n");
}

/** Environment handed to `env -i`; never the ambient one. */
export function darwinEnvironment(input: DarwinProfileInput): Record<string, string> {
  const env: Record<string, string> = {
    HOME: input.home,
    TMPDIR: path.join(input.home, "tmp"),
    PATH: sandboxPath(input.env.PATH, [
      ...DARWIN_SYSTEM_READ,
      input.layout.workspace,
      input.home,
      ...input.layout.writablePaths,
      ...input.layout.readablePaths,
    ]),
    SHELL: input.shell,
    USER: "sandbox",
    LOGNAME: "sandbox",
    XDG_CACHE_HOME: path.join(input.home, ".cache"),
    XDG_CONFIG_HOME: path.join(input.home, ".config"),
    XDG_DATA_HOME: path.join(input.home, ".local", "share"),
    XDG_RUNTIME_DIR: path.join(input.home, "tmp"),
  };

  for (const key of ENV_ALLOWLIST) {
    const value = input.env[key];
    if (value !== undefined) env[key] = value;
  }
  for (const key of input.passEnv) {
    if (RESERVED_ENV.has(key)) continue;
    const value = input.env[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}
