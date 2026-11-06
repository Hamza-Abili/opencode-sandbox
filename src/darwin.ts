/**
 * opencode-sandbox — macOS Seatbelt profile builder (pure).
 *
 * Native `sandbox-exec`, zero dependencies. The profile starts from deny
 * default: processes may exec, read the system runtime, the workspace and the
 * explicitly allowed paths, but write only inside the workspace, a synthetic
 * home and the OS temp dirs. The host home is not readable, so `~/.ssh`,
 * `~/.aws` and OpenCode's own credentials are outside the boundary.
 *
 * Seatbelt is the last matching rule wins, so allow rules are grouped before
 * the final deny-sensitive layer (none is needed: the host home is simply not
 * in the allowlist).
 */

import fs from "node:fs";
import path from "node:path";
import { sandboxPath } from "./profile.ts";
import { type DarwinProfileInput, ENV_ALLOWLIST, RESERVED_ENV } from "./types.ts";

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
}

function readRoots(input: DarwinProfileInput): string[] {
  const roots = new Set<string>();
  for (const target of DARWIN_SYSTEM_READ) addPath(roots, target);
  addPath(roots, input.layout.workspace);
  addPath(roots, input.home);
  for (const target of input.layout.readablePaths) addPath(roots, target);
  return [...roots];
}

function writeRoots(input: DarwinProfileInput): string[] {
  const roots = new Set<string>();
  addPath(roots, input.layout.workspace);
  addPath(roots, input.home);
  addPath(roots, "/tmp");
  addPath(roots, "/var/folders");
  for (const target of input.layout.writablePaths) addPath(roots, target);
  return [...roots];
}

export function buildDarwinProfile(input: DarwinProfileInput): string {
  const reads = readRoots(input);
  const writes = writeRoots(input);
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
    "; Writes are restricted to the workspace, the synthetic home and temp",
    `(allow file-write* ${writes.map(subpath).join(" ")})`,
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
