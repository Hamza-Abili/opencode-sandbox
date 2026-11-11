/**
 * opencode-sandbox — plugin entry.
 *
 * One package, two OpenCode generations:
 *   - V2 calls `setup(ctx)` and installs a shell-executable hook;
 *   - V1 calls `server(input, options)` and rewrites `bash` commands with the
 *     same native sandbox wrapper.
 *
 * The V1 path is documented as lower-fidelity for permission rules; V2 keeps
 * the original command for permissions and history.
 */

import { createSandbox, type V2Context } from "./app.ts";
import { createLegacyServer, type V1Hooks, type V1PluginInput } from "./legacy.ts";
import { parseOptionsSafe } from "./options.ts";

async function setup(input: unknown): Promise<() => void> {
  const ctx = (await Promise.resolve(input ?? {})) as V2Context;
  const directory = ctx.location?.directory ?? process.cwd();
  const parsed = parseOptionsSafe(ctx.options, directory);
  for (const error of parsed.errors) {
    console.error(`[opencode-sandbox] invalid option: ${error}`);
  }
  try {
    const app = await createSandbox(ctx, parsed.options);
    return () => app.dispose();
  } catch (error) {
    console.error(`[opencode-sandbox] setup failed: ${String(error)}`);
    if (parsed.options.mode === "enforce") throw error;
    return () => {};
  }
}

async function server(input: V1PluginInput, options?: unknown): Promise<V1Hooks> {
  return await createLegacyServer(input, options);
}

export const plugin = {
  id: "opencode-sandbox",
  setup,
  server,
};

export default plugin;

// Older V1 loaders discover a named `server` export; newer V1 and V2 use the
// default object above.
export { server };
