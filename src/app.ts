/**
 * opencode-sandbox — OpenCode V2 application.
 *
 * The sandbox is installed through `ctx.shell.hook("create.before")`: only the
 * shell executable is replaced with the generated wrapper. `command`, `cwd`,
 * timeout, permissions and session history keep the original values.
 */

import { resolveCwd, resolveLayout } from "./paths.ts";
import { trace } from "./trace.ts";
import type { SandboxLayout, SandboxOptions } from "./types.ts";
import { prepareRuntime } from "./wrapper.ts";

export interface ShellCreateEvent {
  command: string;
  cwd: string;
  timeout: number;
  shell: string;
  env: Record<string, string | undefined>;
}

export interface Registration {
  dispose(): Promise<void>;
}

export interface ShellContext {
  hook(
    name: "create.before",
    callback: (event: ShellCreateEvent) => Promise<void> | void
  ): Promise<Registration>;
}

export interface ToolContext {
  hook(
    name: "execute.before",
    callback: (event: { tool: string }) => Promise<void> | void
  ): Promise<Registration>;
}

export interface V2Context {
  location?: { directory?: string };
  options?: unknown;
  shell?: ShellContext;
  tool?: ToolContext;
}

export interface SandboxApp {
  dispose(): void;
}

export function isShellTool(tool: string): boolean {
  return tool === "shell" || tool === "bash";
}

function disposeRegistration(registration: Registration): void {
  void Promise.resolve()
    .then(() => registration.dispose())
    .catch((error) => console.error(`[opencode-sandbox] hook dispose failed: ${String(error)}`));
}

async function unavailable(
  ctx: V2Context,
  options: SandboxOptions,
  reason: string
): Promise<SandboxApp> {
  if (options.mode === "permissive") {
    console.warn(
      `[opencode-sandbox] ${reason}; mode=permissive, running shell commands unsandboxed`
    );
    trace("unavailable", { reason, mode: options.mode });
    return { dispose() {} };
  }
  return await failClosedAsync(ctx, reason);
}

/**
 * Refuse shell calls when the sandbox cannot be installed. A shell hook is
 * preferred because it also covers the TUI terminal; if that surface is
 * unavailable, the tool hook at least blocks every agent shell call. Hook
 * registration is awaited: setup must not report success before the refusal
 * exists, otherwise a fast first command could slip past.
 */
export async function failClosedAsync(ctx: V2Context, reason: string): Promise<SandboxApp> {
  const message = `[opencode-sandbox] ${reason}; refusing to run shell commands (mode=enforce)`;
  const blocking = () => {
    throw new Error(message);
  };
  console.error(message);

  const failures: string[] = [];
  if (ctx.shell !== undefined) {
    try {
      const registration = await ctx.shell.hook("create.before", blocking);
      trace("blocked", { reason });
      return { dispose: () => disposeRegistration(registration) };
    } catch (error) {
      failures.push(`shell hook: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (ctx.tool !== undefined) {
    try {
      const registration = await ctx.tool.hook("execute.before", (event) => {
        if (isShellTool(event.tool)) blocking();
      });
      trace("blocked", { reason });
      return { dispose: () => disposeRegistration(registration) };
    } catch (error) {
      failures.push(`tool hook: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  throw new Error(
    `${message}. No enforceable shell or tool hook is available${failures.length > 0 ? ` (${failures.join("; ")})` : ""}.`
  );
}

export async function createSandbox(ctx: V2Context, options: SandboxOptions): Promise<SandboxApp> {
  const workspace = ctx.location?.directory ?? process.cwd();

  let layout: SandboxLayout;
  try {
    layout = resolveLayout(workspace, options);
  } catch (error) {
    return await unavailable(ctx, options, error instanceof Error ? error.message : String(error));
  }

  if (process.platform !== "linux" && process.platform !== "darwin") {
    return await unavailable(ctx, options, `unsupported platform ${process.platform}`);
  }
  const platform = process.platform;

  const prepared = await prepareRuntime(platform, layout, options);
  if (!prepared.ok) return await unavailable(ctx, options, prepared.reason);

  if (ctx.shell === undefined) {
    prepared.runtime.dispose();
    return await unavailable(ctx, options, "this host exposes no ctx.shell.hook surface");
  }

  try {
    const registration = await ctx.shell.hook("create.before", (event) => {
      // Fail here, before OpenCode spawns anything, with a readable reason.
      // The wrapper validates the real cwd again at execution time.
      const cwd = resolveCwd(layout, event.cwd);
      event.shell = prepared.runtime.wrapper;
      trace("sandboxed", { cwd, network: options.network, platform });
    });

    console.log(
      `[opencode-sandbox] ready (platform=${platform}, sandbox=${platform === "linux" ? "bwrap" : "seatbelt"}, ` +
        `network=${options.network}, mode=${options.mode}, workspace=${layout.workspace})`
    );
    trace("ready", {
      platform,
      sandbox: platform === "linux" ? "bwrap" : "seatbelt",
      binary: prepared.runtime.binary,
      network: options.network,
      mode: options.mode,
      workspace: layout.workspace,
    });

    return {
      dispose() {
        disposeRegistration(registration);
        prepared.runtime.dispose();
        trace("dispose");
      },
    };
  } catch (error) {
    prepared.runtime.dispose();
    const reason = `cannot register the shell hook: ${error instanceof Error ? error.message : String(error)}`;
    return await unavailable(ctx, options, reason);
  }
}
