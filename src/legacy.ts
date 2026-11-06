/**
 * opencode-sandbox — OpenCode V1 adapter.
 *
 * V1 has no shell-executable hook. The only supported integration point is
 * `tool.execute.before`, which can rewrite the command string. The command is
 * therefore rewritten to invoke the same generated wrapper:
 *
 *   wrapper -c '<original command>'
 *
 * The sandbox boundary is identical, and the wrapper re-validates the real
 * working directory. The one V1 limitation is that OpenCode V1 parses the
 * rewritten string for its permission rules and records it in history; V2
 * keeps both on the original command. Use V2 when permission-rule fidelity
 * matters.
 */

import { isShellTool } from "./app.ts";
import { parseOptions } from "./options.ts";
import { resolveCwd, resolveLayout } from "./paths.ts";
import { shellQuote } from "./quote.ts";
import { trace } from "./trace.ts";
import type { SandboxLayout, SandboxOptions } from "./types.ts";
import { prepareRuntime } from "./wrapper.ts";

export interface V1PluginInput {
  directory?: unknown;
  worktree?: unknown;
}

export interface V1ToolBeforeInput {
  tool: string;
  sessionID: string;
  callID: string;
}

export interface V1ToolBeforeOutput {
  args: unknown;
}

export interface V1Hooks {
  "tool.execute.before"?: (input: V1ToolBeforeInput, output: V1ToolBeforeOutput) => Promise<void>;
  dispose?: () => Promise<void>;
}

function commandArgs(output: V1ToolBeforeOutput): {
  command?: string;
  workdir?: string;
} {
  const value = output.args;
  if (typeof value !== "object" || value === null) return {};
  const record = value as { command?: unknown; workdir?: unknown };
  return {
    command: typeof record.command === "string" ? record.command : undefined,
    workdir: typeof record.workdir === "string" ? record.workdir : undefined,
  };
}

function blocking(reason: string): V1Hooks {
  const message = `[opencode-sandbox] ${reason}; refusing to run shell commands (mode=enforce)`;
  console.error(message);
  return {
    "tool.execute.before": async (input) => {
      if (isShellTool(input.tool)) throw new Error(message);
    },
  };
}

/** Build the V1 hook object. Exported for tests; `index.ts` wires it. */
export async function createLegacyServer(
  input: V1PluginInput,
  rawOptions?: unknown
): Promise<V1Hooks> {
  // `directory` is the project the user opened; `worktree` can be `/` for a
  // project that is not inside a git repository. Prefer the former.
  const workspace =
    typeof input.directory === "string"
      ? input.directory
      : typeof input.worktree === "string"
        ? input.worktree
        : process.cwd();
  const options: SandboxOptions = parseOptions(rawOptions, workspace);

  let layout: SandboxLayout;
  try {
    layout = resolveLayout(workspace, options);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    if (options.mode === "permissive") {
      console.warn(
        `[opencode-sandbox] ${reason}; mode=permissive, running shell commands unsandboxed`
      );
      return {};
    }
    return blocking(reason);
  }

  if (process.platform !== "linux" && process.platform !== "darwin") {
    const reason = `unsupported platform ${process.platform}`;
    if (options.mode === "permissive") {
      console.warn(
        `[opencode-sandbox] ${reason}; mode=permissive, running shell commands unsandboxed`
      );
      return {};
    }
    return blocking(reason);
  }

  const prepared = await prepareRuntime(process.platform, layout, options);
  if (!prepared.ok) {
    if (options.mode === "permissive") {
      console.warn(
        `[opencode-sandbox] ${prepared.reason}; mode=permissive, running shell commands unsandboxed`
      );
      return {};
    }
    return blocking(prepared.reason);
  }

  const prefix = `${shellQuote(prepared.runtime.wrapper)} -c `;
  const hooks: V1Hooks = {
    "tool.execute.before": async (toolInput, output) => {
      if (!isShellTool(toolInput.tool)) return;
      const args = commandArgs(output);
      if (args.command === undefined || args.command === "") return;
      if (args.command.startsWith(prefix)) return;
      if (args.workdir !== undefined) resolveCwd(layout, args.workdir);
      const record = output.args as { command: string };
      record.command = `${prefix}${shellQuote(args.command)}`;
      trace("sandboxed-v1", { tool: toolInput.tool, workdir: args.workdir });
    },
    dispose: async () => {
      prepared.runtime.dispose();
      trace("dispose-v1");
    },
  };

  console.log(
    `[opencode-sandbox] ready v1 (platform=${process.platform}, ` +
      `sandbox=${process.platform === "linux" ? "bwrap" : "seatbelt"}, ` +
      `network=${options.network}, mode=${options.mode}, workspace=${layout.workspace})`
  );
  trace("ready-v1", {
    platform: process.platform,
    binary: prepared.runtime.binary,
    network: options.network,
    mode: options.mode,
    workspace: layout.workspace,
  });
  return hooks;
}
