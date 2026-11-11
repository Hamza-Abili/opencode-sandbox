/**
 * Live smoke test against a real OpenCode installation.
 *
 * Starts an ephemeral `opencode serve` in a project directory (isolated
 * HOME/XDG, random password) and asserts:
 *   1. the plugin is active in `/api/plugin`;
 *   2. the sandbox probe succeeded and the shell hook was registered.
 *
 * No model or API key is needed. Command execution inside the sandbox is
 * covered by the real bwrap/Seatbelt integration tests.
 *
 * Usage: bun run smoke   (or OPENCODE_BIN=/path bun run smoke)
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PLUGIN_ROOT = process.env.PLUGIN_SPEC ?? path.resolve(import.meta.dir, "..");
const OPENCODE = process.env.OPENCODE_BIN ?? "opencode";
const password = crypto.randomUUID();
const port = 49700 + (process.pid % 200);

const root = fs.mkdtempSync(path.join(os.tmpdir(), "osb-smoke-"));
const project = path.join(root, "project");
const env: NodeJS.ProcessEnv = Object.fromEntries(
  Object.entries(process.env).filter(
    ([key]) => !key.startsWith("OPENCODE_") && !key.startsWith("XDG_")
  )
);
env.HOME = path.join(root, "home");
env.XDG_CONFIG_HOME = path.join(root, "config");
env.XDG_DATA_HOME = path.join(root, "data");
env.XDG_CACHE_HOME = path.join(root, "cache");
env.XDG_RUNTIME_DIR = path.join(root, "runtime");
env.OSB_TRACE = path.join(root, "trace.jsonl");
env.OPENCODE_SERVER_PASSWORD = password;

for (const dir of [env.HOME, env.XDG_CONFIG_HOME, env.XDG_DATA_HOME, env.XDG_CACHE_HOME, project]) {
  fs.mkdirSync(dir as string, { recursive: true });
}

fs.mkdirSync(path.join(env.XDG_CONFIG_HOME as string, "opencode"), { recursive: true });
fs.writeFileSync(
  path.join(env.XDG_CONFIG_HOME as string, "opencode", "opencode.json"),
  JSON.stringify({
    $schema: "https://opencode.ai/config.json",
    plugins: [
      {
        package: PLUGIN_ROOT,
        options: { network: "deny", mode: "enforce" },
      },
    ],
  })
);

const child = Bun.spawn({
  cmd: [OPENCODE, "serve", "--port", String(port)],
  cwd: project,
  env,
  stdout: "ignore",
  stderr: "pipe",
});

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

let stopped = false;
function stop(): void {
  if (stopped) return;
  stopped = true;
  try {
    child.kill();
  } catch {
    // already exited
  }
}

process.on("exit", () => {
  stop();
  if (process.env.OSB_KEEP_SMOKE === "1") {
    console.error(`smoke root kept at ${root}`);
    return;
  }
  fs.rmSync(root, { recursive: true, force: true });
});

const auth = `Basic ${Buffer.from(`opencode:${password}`).toString("base64")}`;

async function request(
  pathname: string,
  init: RequestInit = {}
): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`http://127.0.0.1:${port}${pathname}`, {
    ...init,
    headers: {
      authorization: auth,
      ...(init.body === undefined ? {} : { "content-type": "application/json" }),
    },
    signal: AbortSignal.timeout(3000),
  });
  const text = await response.text();
  return { status: response.status, body: text === "" ? undefined : JSON.parse(text) };
}

async function api(pathname: string): Promise<{ status: number; body: unknown }> {
  return await request(pathname);
}

async function waitFor<T>(
  label: string,
  probe: () => Promise<T | undefined>,
  timeoutMs = 30_000
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      const stderr = (await new Response(child.stderr).text()).trim();
      fail(`OpenCode server exited before ${label}: ${stderr || `exit ${child.exitCode}`}`);
    }
    const value = await probe().catch(() => undefined);
    if (value !== undefined) return value;
    Bun.sleepSync(500);
  }
  fail(`timed out waiting for ${label}`);
}

type PluginInfo = { id: string; state?: { status?: string; message?: string } };

const plugins = await waitFor("the plugin", async () => {
  const response = await api("/api/plugin");
  if (response.status !== 200) return undefined;
  const data = (response.body as { data?: PluginInfo[] }).data ?? [];
  return data.some(
    (plugin) => plugin.id === "opencode-sandbox" && plugin.state?.status === "active"
  )
    ? data
    : undefined;
});
const plugin = plugins.find((candidate) => candidate.id === "opencode-sandbox");
console.log(`PASS plugin: ${plugin?.id} state=${plugin?.state?.status}`);

type Trace = { step: string; data?: Record<string, unknown> };
const trace = await waitFor("the sandbox hook trace", async () => {
  if (!fs.existsSync(env.OSB_TRACE as string)) return undefined;
  const lines = fs
    .readFileSync(env.OSB_TRACE as string, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Trace);
  return lines.some((entry) => entry.step === "ready") ? lines : undefined;
});

const ready = trace.find((entry) => entry.step === "ready");
if (ready === undefined) fail(`sandbox did not report ready: ${JSON.stringify(trace)}`);
if (ready.data?.workspace === undefined)
  fail(`sandbox ready trace has no workspace: ${JSON.stringify(ready)}`);
if (ready.data?.network !== "deny") fail(`unexpected network mode: ${JSON.stringify(ready)}`);
if (ready.data?.toolGuard !== "enforce")
  fail(`tool guard was not registered: ${JSON.stringify(ready)}`);
const workspace = ready.data.workspace as string;
console.log(
  `PASS trace: ${ready.data?.sandbox ?? "sandbox"} ready, toolGuard=enforce, workspace=${workspace}`
);

const created = await request("/api/session", { method: "POST", body: "{}" });
if (created.status !== 200) fail(`session creation failed: ${created.status}`);
const sessionID = (created.body as { data?: { id?: string } }).data?.id;
if (sessionID === undefined)
  fail(`session creation returned no id: ${JSON.stringify(created.body)}`);

type ShellMessage = {
  type?: string;
  status?: string;
  exit?: number;
  command?: string;
  output?: { output?: string };
};

async function shellCommand(command: string): Promise<ShellMessage> {
  const shell = await request(`/api/session/${sessionID}/shell`, {
    method: "POST",
    body: JSON.stringify({ command }),
  });
  if (shell.status !== 204) {
    fail(`live shell call failed: ${shell.status} ${JSON.stringify(shell.body)}`);
  }
  return await waitFor(`the live shell result for ${JSON.stringify(command)}`, async () => {
    const response = await api(`/api/session/${sessionID}/message`);
    if (response.status !== 200) return undefined;
    const data = (response.body as { data?: ShellMessage[] }).data ?? [];
    return data.find(
      (entry) => entry.type === "shell" && entry.status === "exited" && entry.command === command
    );
  });
}

const command = "printf smoke-ok; pwd";
const message = await shellCommand(command);
if (message.command !== command) {
  fail(`history command changed: ${JSON.stringify(message.command)}`);
}
if (message.exit !== 0) fail(`live sandboxed command exited ${message.exit}`);
if (!message.output?.output?.includes("smoke-ok")) {
  fail(`live sandboxed command produced no marker: ${JSON.stringify(message.output)}`);
}
if (!message.output.output.includes(workspace)) {
  fail(`live sandboxed command ran outside the workspace: ${JSON.stringify(message.output)}`);
}

// Live boundary check: a host-home secret must not be readable and the
// server's password must not leak into the sandbox.
const secret = path.join(env.HOME as string, "osb-smoke-secret");
fs.writeFileSync(secret, "smoke-host-secret", { mode: 0o600 });
const boundaryCommand = `cat ${JSON.stringify(secret)}; printf 'cat=%s\\n' "$?"; printenv OPENCODE_SERVER_PASSWORD; printf 'env=%s\\n' "$?"`;
const boundary = await shellCommand(boundaryCommand);
if (boundary.output?.output?.includes("smoke-host-secret")) {
  fail("host-home secret leaked into the sandbox");
}
if (!boundary.output?.output?.includes("cat=1")) {
  fail(`host-home read was not refused: ${JSON.stringify(boundary.output)}`);
}
if (!boundary.output?.output?.includes("env=1")) {
  fail(`server password leaked into the sandbox: ${JSON.stringify(boundary.output)}`);
}
fs.rmSync(secret, { force: true });
console.log("PASS live boundary: host-home secret unreadable, server password cleared");

const allTrace = fs
  .readFileSync(env.OSB_TRACE as string, "utf8")
  .trim()
  .split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line) as Trace);
const sandboxed = allTrace.find((entry) => entry.step === "sandboxed");
if (sandboxed === undefined) fail(`no live sandbox trace: ${JSON.stringify(allTrace)}`);
if (sandboxed.data?.cwd !== workspace) {
  fail(`live sandbox cwd mismatch: ${JSON.stringify(sandboxed)}`);
}

console.log("PASS live shell: command history preserved, cwd confined, sandbox hook applied");
console.log(`PASS live smoke against ${OPENCODE}`);
stop();
