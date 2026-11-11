/**
 * opencode-sandbox — option resolution.
 *
 * Malformed values fall back to secure defaults. Security-sensitive options
 * record an error instead of silently widening the policy: callers that can
 * keep running (the plugin setup) log it and keep the fail-closed fallback;
 * `parseOptions` remains the strict form for tests and embedders.
 */

import fs from "node:fs";
import path from "node:path";
import {
  DEFAULT_OPTIONS,
  type SandboxOptions,
  type ToolGuardMode,
  type WebFetchMode,
} from "./types.ts";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

function stringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value as string[];
}

/**
 * Normalize a webfetch host entry. Accepts `example.com`, `*.example.com` and
 * `.example.com` (the last two both mean apex plus subdomains). Returns
 * undefined for anything that is not a plain hostname pattern.
 */
export function normalizeHostPattern(value: string): string | undefined {
  let entry = value.trim().toLowerCase();
  if (entry.endsWith(".")) entry = entry.slice(0, -1);
  if (entry === "") return undefined;

  let wildcard = false;
  if (entry.startsWith("*.")) {
    wildcard = true;
    entry = entry.slice(2);
  } else if (entry.startsWith(".")) {
    wildcard = true;
    entry = entry.slice(1);
  }

  const labels = entry.split(".");
  if (labels.length === 0 || !labels.every((label) => HOST_LABEL.test(label))) return undefined;
  return wildcard ? `*.${entry}` : entry;
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

export interface ParsedOptions {
  options: SandboxOptions;
  errors: string[];
}

/**
 * Parse options without throwing. Invalid security-sensitive values produce an
 * error and a fail-closed fallback so the caller can keep the shell sandbox
 * installed instead of disabling the plugin.
 */
export function parseOptionsSafe(raw: unknown, cwd: string): ParsedOptions {
  const record = isRecord(raw) ? raw : {};
  const errors: string[] = [];

  const writable = new Set<string>();
  const writableValues = record.writablePaths === undefined ? [] : stringList(record.writablePaths);
  if (writableValues === undefined) {
    errors.push("writablePaths must be an array of strings");
  } else {
    for (const value of writableValues) {
      const expanded = expandPath(value, cwd);
      if (expanded !== "/") writable.add(expanded);
    }
  }

  const readable = new Set<string>();
  const readableValues = record.readablePaths === undefined ? [] : stringList(record.readablePaths);
  if (readableValues === undefined) {
    errors.push("readablePaths must be an array of strings");
  } else {
    for (const value of readableValues) {
      const expanded = expandPath(value, cwd);
      if (expanded !== "/") readable.add(expanded);
    }
  }

  const passEnv = new Set<string>();
  const passEnvValues = record.passEnv === undefined ? [] : stringList(record.passEnv);
  if (passEnvValues === undefined) {
    errors.push("passEnv must be an array of strings");
  } else {
    for (const key of passEnvValues) {
      if (ENV_NAME.test(key)) passEnv.add(key);
    }
  }

  let shell = defaultShell();
  if (record.shell !== undefined) {
    if (typeof record.shell === "string" && path.isAbsolute(record.shell)) {
      shell = record.shell;
    } else {
      errors.push("shell must be an absolute path");
    }
  }

  let network = DEFAULT_OPTIONS.network;
  if (record.network !== undefined) {
    if (record.network === "deny" || record.network === "allow") {
      network = record.network;
    } else {
      errors.push('network must be "deny" or "allow"');
    }
  }

  let mode = DEFAULT_OPTIONS.mode;
  if (record.mode !== undefined) {
    if (record.mode === "enforce" || record.mode === "permissive") {
      mode = record.mode;
    } else {
      errors.push('mode must be "enforce" or "permissive"');
    }
  }

  let toolGuard: ToolGuardMode = DEFAULT_OPTIONS.toolGuard;
  if (record.toolGuard !== undefined) {
    if (record.toolGuard === "enforce" || record.toolGuard === "off") {
      toolGuard = record.toolGuard;
    } else {
      errors.push('toolGuard must be "enforce" or "off"');
    }
  }

  let webfetch: WebFetchMode = DEFAULT_OPTIONS.webfetch;
  if (record.webfetch !== undefined) {
    if (record.webfetch === "allow" || record.webfetch === "deny") {
      webfetch = record.webfetch;
    } else {
      errors.push('webfetch must be "allow" or "deny"');
      webfetch = "deny";
    }
  }

  const webfetchAllowlist = new Set<string>();
  if (record.webfetchAllowlist !== undefined) {
    const entries = stringList(record.webfetchAllowlist);
    if (entries === undefined) {
      errors.push("webfetchAllowlist must be an array of hostnames");
      webfetch = "deny";
    } else {
      for (const [index, value] of entries.entries()) {
        const normalized = normalizeHostPattern(value);
        if (normalized === undefined) {
          // Do not echo the value: a malformed URL may contain a credential.
          errors.push(`webfetchAllowlist entry ${index + 1} is not a hostname`);
          webfetch = "deny";
          webfetchAllowlist.clear();
          break;
        }
        webfetchAllowlist.add(normalized);
      }
    }
  }

  if (toolGuard === "off" && (webfetch === "deny" || webfetchAllowlist.size > 0)) {
    errors.push('webfetch options require toolGuard: "enforce"');
    toolGuard = "enforce";
  }

  return {
    options: {
      network,
      mode,
      writablePaths: [...writable],
      readablePaths: [...readable],
      passEnv: [...passEnv],
      shell,
      toolGuard,
      webfetch,
      webfetchAllowlist: [...webfetchAllowlist],
    },
    errors,
  };
}

/** Strict form: throws when a security-sensitive option is malformed. */
export function parseOptions(raw: unknown, cwd: string): SandboxOptions {
  const parsed = parseOptionsSafe(raw, cwd);
  if (parsed.errors.length > 0) throw new Error(parsed.errors.join("; "));
  return parsed.options;
}
