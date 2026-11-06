/**
 * opencode-sandbox — option resolution.
 *
 * Unknown or malformed values fall back to the secure defaults. Paths are
 * expanded here; `paths.ts` resolves and validates them against the host.
 */

import fs from "node:fs";
import path from "node:path";
import { DEFAULT_OPTIONS, type SandboxOptions } from "./types.ts";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function stringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value as string[];
}

export function expandPath(value: string, cwd: string): string {
  if (value === "~") return process.env.HOME ?? value;
  if (value.startsWith("~/")) return path.join(process.env.HOME ?? "", value.slice(2));
  return path.isAbsolute(value) ? path.normalize(value) : path.resolve(cwd, value);
}

function defaultShell(): string {
  if (fs.existsSync("/bin/bash")) return "/bin/bash";
  if (fs.existsSync("/bin/sh")) return "/bin/sh";
  return DEFAULT_OPTIONS.shell;
}

export function parseOptions(raw: unknown, cwd: string): SandboxOptions {
  const record = isRecord(raw) ? raw : {};

  const writable = new Set<string>();
  for (const value of stringList(record.writablePaths) ?? []) {
    const expanded = expandPath(value, cwd);
    if (expanded !== "/") writable.add(expanded);
  }

  const readable = new Set<string>();
  for (const value of stringList(record.readablePaths) ?? []) {
    const expanded = expandPath(value, cwd);
    if (expanded !== "/") readable.add(expanded);
  }

  const passEnv = new Set<string>();
  for (const key of stringList(record.passEnv) ?? []) {
    if (ENV_NAME.test(key)) passEnv.add(key);
  }

  const shell =
    typeof record.shell === "string" && path.isAbsolute(record.shell)
      ? record.shell
      : defaultShell();

  return {
    network: record.network === "allow" ? "allow" : DEFAULT_OPTIONS.network,
    mode: record.mode === "permissive" ? "permissive" : DEFAULT_OPTIONS.mode,
    writablePaths: [...writable],
    readablePaths: [...readable],
    passEnv: [...passEnv],
    shell,
  };
}
