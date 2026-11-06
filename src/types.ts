/**
 * opencode-sandbox — shared types.
 */

export type NetworkMode = "deny" | "allow";
export type SandboxMode = "enforce" | "permissive";
export type Platform = "linux" | "darwin";

export interface SandboxOptions {
  /** Network access inside the sandbox. Default: deny. */
  network: NetworkMode;
  /**
   * enforce (default): refuse shell execution when the sandbox is
   * unavailable. permissive: run unsandboxed with a warning.
   */
  mode: SandboxMode;
  /** Extra host paths writable inside the sandbox (canonical paths). */
  writablePaths: string[];
  /** Extra host paths readable inside the sandbox (canonical paths). */
  readablePaths: string[];
  /** Environment variables copied into the sandbox (default: none). */
  passEnv: string[];
  /** Shell used inside the sandbox. Absolute path. */
  shell: string;
}

/** Validated, canonical paths the sandbox is built around. */
export interface SandboxLayout {
  /** Canonical workspace root (mounted read-write). */
  workspace: string;
  /** Canonical host home (never mounted). */
  hostHome: string;
  /** Canonical extra read-write mounts. */
  writablePaths: string[];
  /** Canonical extra read-only mounts. */
  readablePaths: string[];
}

export interface ProbeResult {
  available: boolean;
  reason?: string;
}

export interface LinuxProfileInput {
  layout: SandboxLayout;
  network: NetworkMode;
  passEnv: string[];
  shell: string;
  env: Record<string, string | undefined>;
}

export interface DarwinProfileInput extends LinuxProfileInput {
  /** Synthetic home inside the sandbox. */
  home: string;
}

export const DEFAULT_OPTIONS: SandboxOptions = {
  network: "deny",
  mode: "enforce",
  writablePaths: [],
  readablePaths: [],
  passEnv: [],
  shell: "/bin/bash",
};

/** Keys the sandbox always controls; `passEnv` may not override them. */
export const RESERVED_ENV = new Set([
  "HOME",
  "TMPDIR",
  "PATH",
  "SHELL",
  "USER",
  "LOGNAME",
  "PWD",
  "OLDPWD",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_RUNTIME_DIR",
]);

/** Environment variables copied when present (never credentials). */
export const ENV_ALLOWLIST = ["TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"] as const;
