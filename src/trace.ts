/**
 * opencode-sandbox — opt-in JSONL tracing (`OSB_TRACE`).
 *
 * Debug only. It is written by the host plugin process, never by sandboxed
 * commands, and must point outside any writable sandbox path to be trustworthy.
 */

import fs from "node:fs";

export function trace(step: string, data?: Record<string, unknown>): void {
  const file = process.env.OSB_TRACE;
  if (file === undefined || file === "") return;
  try {
    fs.appendFileSync(file, `${JSON.stringify({ at: new Date().toISOString(), step, data })}\n`);
  } catch {
    // tracing must never affect execution
  }
}
