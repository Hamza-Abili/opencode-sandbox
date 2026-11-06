/**
 * opencode-sandbox — POSIX shell quoting.
 *
 * Used only where a command string is unavoidable (the V1 adapter). Every
 * token is single-quoted so the host shell treats it as data.
 */

export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function shellJoin(tokens: readonly string[]): string {
  return tokens.map(shellQuote).join(" ");
}
