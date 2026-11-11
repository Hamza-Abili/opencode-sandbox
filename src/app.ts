/**
 * opencode-sandbox — OpenCode V2 application.
 *
 * The sandbox is installed through `ctx.shell.hook("create.before")`: only the
 * shell executable is replaced with the generated wrapper. `command`, `cwd`,
 * timeout, permissions and session history keep the original values.
 */

import { resolveCwd, resolveLayout } from "./paths.ts";
import {
  createToolPolicy,
  denyPolicyAction,
  evaluatePermission,
  guardToolInput,
  isGuardedTool,
  type PermissionEvaluation,
} from "./tool-policy.ts";
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
    callback: (event: { tool: string; input?: unknown }) => Promise<void> | void
  ): Promise<Registration>;
}

export interface PermissionContext {
  hook(
    name: "evaluate",
    callback: (event: PermissionEvaluation) => Promise<void> | void
  ): Promise<Registration>;
}

export interface V2Context {
  location?: { directory?: string };
  options?: unknown;
  permission?: PermissionContext;
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
  reason: string,
  permissionGuard?: (event: PermissionEvaluation) => void
): Promise<SandboxApp> {
  if (options.mode === "permissive") {
    console.warn(
      `[opencode-sandbox] ${reason}; mode=permissive, running shell commands unsandboxed`
    );
    trace("unavailable", { reason, mode: options.mode });
    return { dispose() {} };
  }
  return await failClosedAsync(ctx, reason, options.toolGuard === "enforce", permissionGuard);
}

/**
 * Refuse shell calls and guarded tools when the sandbox cannot be installed.
 * A shell hook is preferred because it also covers the TUI terminal; the tool
 * hook additionally blocks file tools and the agent shell. Hook registration
 * is awaited: setup must not report success before the refusal exists,
 * otherwise a fast first command could slip past.
 */
export async function failClosedAsync(
  ctx: V2Context,
  reason: string,
  blockTools = true,
  permissionGuard?: (event: PermissionEvaluation) => void
): Promise<SandboxApp> {
  const shellMessage = `[opencode-sandbox] ${reason}; refusing to run shell commands (mode=enforce)`;
  const toolMessage = `[opencode-sandbox] ${reason}; refusing to run guarded tools (mode=enforce)`;
  const blockShell = () => {
    throw new Error(shellMessage);
  };
  const blockGuardedTool = () => {
    throw new Error(toolMessage);
  };
  console.error(shellMessage);

  const disposers: Array<() => void> = [];
  const failures: string[] = [];
  let shellBlocked = false;
  let toolsBlocked = false;

  if (ctx.shell !== undefined) {
    try {
      const registration = await ctx.shell.hook("create.before", blockShell);
      disposers.push(() => disposeRegistration(registration));
      shellBlocked = true;
    } catch (error) {
      failures.push(`shell hook: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (ctx.tool !== undefined) {
    try {
      const registration = await ctx.tool.hook("execute.before", (event) => {
        if (isShellTool(event.tool)) blockShell();
        if (blockTools && isGuardedTool(event.tool)) blockGuardedTool();
      });
      disposers.push(() => disposeRegistration(registration));
      shellBlocked = true;
      toolsBlocked = blockTools;
    } catch (error) {
      failures.push(`tool hook: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (blockTools && permissionGuard !== undefined && ctx.permission !== undefined) {
    try {
      const registration = await ctx.permission.hook("evaluate", permissionGuard);
      disposers.push(() => disposeRegistration(registration));
      toolsBlocked = true;
    } catch (error) {
      failures.push(`permission hook: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (!shellBlocked) {
    for (const dispose of disposers) dispose();
    throw new Error(
      `${shellMessage}. No enforceable shell or tool hook is available${failures.length > 0 ? ` (${failures.join("; ")})` : ""}.`
    );
  }
  if (blockTools && !toolsBlocked) {
    console.error(
      "[opencode-sandbox] guarded file tools could not be blocked; only shell commands are refused"
    );
  }
  trace("blocked", { reason });
  return {
    dispose() {
      for (const dispose of disposers) dispose();
    },
  };
}

type ToolGuardState = "policy" | "blocked" | "off" | "unavailable";

/**
 * Install the in-process policy. If the permission hook is unavailable or
 * registration fails, block the guarded tools through the tool hook instead
 * of disabling the whole plugin. The shell sandbox is installed separately so
 * a tool-guard problem never removes the kernel-enforced shell boundary.
 */
async function installToolGuard(
  ctx: V2Context,
  options: SandboxOptions,
  layout: SandboxLayout,
  platform: string,
  resolveBase: string
): Promise<{
  policy?: Registration;
  tool?: Registration;
  blocked?: Registration;
  state: ToolGuardState;
}> {
  if (options.toolGuard === "off") return { state: "off" };

  if (ctx.permission !== undefined) {
    try {
      const policy = createToolPolicy(layout, options, platform, resolveBase);
      const registration = await ctx.permission.hook("evaluate", (event) => {
        evaluatePermission(event, policy);
      });
      let tool: Registration | undefined;
      if (ctx.tool !== undefined) {
        try {
          tool = await ctx.tool.hook("execute.before", (event) => {
            guardToolInput(event.tool, event.input, policy, "v2");
          });
        } catch (error) {
          console.error(
            `[opencode-sandbox] cannot register the pre-execution tool check: ${error instanceof Error ? error.message : String(error)}`
          );
        }
      }
      return { policy: registration, tool, state: "policy" };
    } catch (error) {
      console.error(
        `[opencode-sandbox] cannot register the tool guard: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  } else {
    console.error(
      '[opencode-sandbox] toolGuard is "enforce" but this host exposes no ctx.permission.hook'
    );
  }

  if (ctx.tool !== undefined) {
    try {
      const message =
        '[opencode-sandbox] tool guard unavailable; refusing guarded tools (set toolGuard: "off" to disable the guard)';
      const registration = await ctx.tool.hook("execute.before", (event) => {
        if (isGuardedTool(event.tool)) throw new Error(message);
      });
      return { blocked: registration, state: "blocked" };
    } catch (error) {
      console.error(
        `[opencode-sandbox] cannot register the blocking tool hook: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  console.error(
    "[opencode-sandbox] tool guard is enforced but no tool hook can block file tools; file tools remain unguarded"
  );
  return { state: "unavailable" };
}

export async function createSandbox(ctx: V2Context, options: SandboxOptions): Promise<SandboxApp> {
  const workspace = ctx.location?.directory ?? process.cwd();

  let layout: SandboxLayout;
  try {
    layout = resolveLayout(workspace, options);
  } catch (error) {
    return await unavailable(
      ctx,
      options,
      error instanceof Error ? error.message : String(error),
      options.toolGuard === "enforce" ? denyPolicyAction : undefined
    );
  }

  if (process.platform !== "linux" && process.platform !== "darwin") {
    return await unavailable(
      ctx,
      options,
      `unsupported platform ${process.platform}`,
      options.toolGuard === "enforce" ? denyPolicyAction : undefined
    );
  }
  const platform = process.platform;

  const guard = await installToolGuard(ctx, options, layout, platform, workspace);
  const guardDisposers: Array<() => void> = [];
  if (guard.policy !== undefined) {
    const registration = guard.policy;
    guardDisposers.push(() => disposeRegistration(registration));
  }
  if (guard.tool !== undefined) {
    const registration = guard.tool;
    guardDisposers.push(() => disposeRegistration(registration));
  }
  if (guard.blocked !== undefined) {
    const registration = guard.blocked;
    guardDisposers.push(() => disposeRegistration(registration));
  }

  let runtime: { dispose(): void } | undefined;
  const failClosed = async (reason: string): Promise<SandboxApp> => {
    if (options.mode === "permissive") {
      console.warn(
        `[opencode-sandbox] ${reason}; mode=permissive, running shell commands unsandboxed`
      );
      runtime?.dispose();
      runtime = undefined;
      for (const dispose of guardDisposers) dispose();
      trace("unavailable", { reason, mode: options.mode });
      return { dispose() {} };
    }

    try {
      const alreadyGuarded = guard.state === "policy" || guard.state === "blocked";
      const blockTools = options.toolGuard === "enforce" && !alreadyGuarded;
      const blocked = await failClosedAsync(ctx, reason, blockTools);
      runtime?.dispose();
      runtime = undefined;
      return {
        dispose() {
          blocked.dispose();
          for (const dispose of guardDisposers) dispose();
          trace("dispose");
        },
      };
    } catch (error) {
      runtime?.dispose();
      for (const dispose of guardDisposers) dispose();
      throw error;
    }
  };

  const prepared = await prepareRuntime(platform, layout, options);
  if (!prepared.ok) return await failClosed(prepared.reason);
  runtime = prepared.runtime;

  if (ctx.shell === undefined) {
    return await failClosed("this host exposes no ctx.shell.hook surface");
  }

  try {
    const registration = await ctx.shell.hook("create.before", (event) => {
      // Fail here, before OpenCode spawns anything, with a readable reason.
      // The wrapper validates the real cwd again at execution time.
      const cwd = resolveCwd(layout, event.cwd);
      event.shell = prepared.runtime.wrapper;
      trace("sandboxed", { cwd, network: options.network, platform });
    });

    const toolGuard = guard.state === "policy" ? "enforce" : guard.state;
    const webfetch =
      guard.state !== "policy"
        ? guard.state === "blocked"
          ? "blocked"
          : "unguarded"
        : options.webfetch === "deny"
          ? "deny"
          : options.webfetchAllowlist.length > 0
            ? `allowlist(${options.webfetchAllowlist.length})`
            : "allow";

    console.log(
      `[opencode-sandbox] ready (platform=${platform}, sandbox=${platform === "linux" ? "bwrap" : "seatbelt"}, ` +
        `network=${options.network}, mode=${options.mode}, toolGuard=${toolGuard}, ` +
        `webfetch=${webfetch}, workspace=${layout.workspace})`
    );
    trace("ready", {
      platform,
      sandbox: platform === "linux" ? "bwrap" : "seatbelt",
      binary: prepared.runtime.binary,
      network: options.network,
      mode: options.mode,
      toolGuard,
      webfetch: options.webfetch,
      webfetchAllowlist: options.webfetchAllowlist.length,
      workspace: layout.workspace,
    });

    return {
      dispose() {
        disposeRegistration(registration);
        for (const dispose of guardDisposers) dispose();
        prepared.runtime.dispose();
        trace("dispose");
      },
    };
  } catch (error) {
    const reason = `cannot register the shell hook: ${error instanceof Error ? error.message : String(error)}`;
    return await failClosed(reason);
  }
}
