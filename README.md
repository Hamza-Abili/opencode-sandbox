# opencode-sandbox

[![CI](https://github.com/Hamza-Abili/opencode-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/Hamza-Abili/opencode-sandbox/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40hamzaabili/opencode-sandbox)](https://www.npmjs.com/package/@hamzaabili/opencode-sandbox)
[![npm downloads](https://img.shields.io/npm/dt/%40hamzaabili/opencode-sandbox)](https://www.npmjs.com/package/@hamzaabili/opencode-sandbox)
[![GitHub stars](https://img.shields.io/github/stars/Hamza-Abili/opencode-sandbox?style=social)](https://github.com/Hamza-Abili/opencode-sandbox/stargazers)
[![license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/Hamza-Abili/opencode-sandbox/blob/main/LICENSE)

**Native command sandbox for OpenCode V1 and V2.**

Every shell command runs inside the OS sandbox: [bubblewrap](https://github.com/containers/bubblewrap)
on Linux and **Seatbelt** (`sandbox-exec`) on macOS. The workspace is writable,
the system is read-only, `$HOME` is synthetic, ambient secrets are cleared, and
the network is denied by default. **Fail-closed**: if the sandbox cannot be
created, commands are refused — never silently run unsandboxed.

Zero runtime dependencies. No helper daemon. No proxy. No SRT.

The V2 path uses `ctx.shell.hook("create.before")` and replaces **only the
shell executable** with a generated wrapper. The command, working directory,
timeout, permission rules and session history keep their original values.
The V1 path uses the legacy `tool.execute.before` hook; see [V1](#opencode-v1)
for its one documented limitation.

## Requirements

- **Linux**: `bubblewrap` installed system-wide. Debian/Ubuntu:
  `sudo apt install bubblewrap`.
  On Ubuntu 24.04+ unprivileged user namespaces are restricted by AppArmor;
  enable the `bwrap-userns-restrict` profile as documented by bubblewrap.
- **macOS**: built-in `/usr/bin/sandbox-exec` (Seatbelt). Works on current
  macOS releases; the CI matrix runs the real macOS integration tests on a
  GitHub macOS runner.
- **Windows**: not supported; the plugin fails closed.

The plugin probes a **real** sandbox at startup and reports the exact failure
instead of assuming the binary is usable. The sandbox binary is resolved from
fixed root-owned absolute locations, never through `PATH`.

## Install (OpenCode V2)

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "@hamzaabili/opencode-sandbox",
      "options": {
        "network": "deny"
      }
    }
  ]
}
```

Restart OpenCode. On load the plugin logs:

```
[opencode-sandbox] ready (platform=linux, sandbox=bwrap, network=deny, mode=enforce, workspace=/path/to/project)
```

## Install (OpenCode V1)

V1 uses the same package; the default export exposes both `setup()` for V2 and
`server()` for V1. Enable it with the V1 plugin list (an options tuple is
optional):

```jsonc
{
  "plugin": [
    ["@hamzaabili/opencode-sandbox", { "network": "deny" }]
  ]
}
```

### OpenCode V1

V1 has no shell-executable hook. The adapter rewrites the command string to

```
'/path/to/opencode-sandbox-wrapper' -c '<original command>'
```

The sandbox boundary is identical, and the wrapper re-validates the real
working directory. The limitation is V1's own parser: OpenCode V1 evaluates
its permission rules and records history against the rewritten command string,
not the original one, so command-level deny/ask rules on the original command
are not preserved. Use V2 when permission-rule fidelity matters. The adapter
is tested against OpenCode 1.19.5; the package declares `>=1.19 <2 || >=2.0`.

## Options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `network` | `"deny" \| "allow"` | `"deny"` | `deny` removes the network namespace (Linux) / denies all network operations (macOS). `allow` shares the host network. There is intentionally no domain allowlist: a real allowlist needs a TLS-intercepting proxy, which would add a dependency and a certificate authority to trust. |
| `mode` | `"enforce" \| "permissive"` | `"enforce"` | `enforce` refuses shell commands when the sandbox is unavailable. `permissive` runs unsandboxed with a warning — explicit opt-out only. |
| `writablePaths` | `string[]` | `[]` | Extra host paths writable inside the sandbox. Must exist; canonicalised (symlinks resolved); `/`, the host home and its ancestors, credential directories and host system paths are rejected. |
| `readablePaths` | `string[]` | `[]` | Extra host paths readable inside the sandbox. Root, host home and ancestors are rejected; explicit credential/system paths are allowed read-only as a trust decision. |
| `passEnv` | `string[]` | `[]` | Environment variables copied from the plugin process into the sandbox. Reserved keys (`HOME`, `PATH`, `TMPDIR`, `XDG_*`, …) cannot be overridden. |
| `shell` | `string` | `/bin/bash` (or `/bin/sh`) | Absolute shell used **inside** the sandbox. |

Paths are canonicalised when the layout is built. Missing paths are an error,
not a silent skip: a sandbox with a mistyped mount would otherwise look
protected while the path is invisible. Writable host system paths are rejected;
projects under `/opt`, `/usr/local`, `/System`, `/Library` or `/nix/store` must
be moved (read-only access can be granted with `readablePaths`).

## What is sandboxed

- **All shell-service commands on V2**: the agent's `shell` tool and the
  terminal/TUI shell both go through `Shell.create`, which is where the hook
  is installed.
- **V1**: the agent's `bash` tool (`shell` on newer V1 builds). The terminal
  shell bypasses the V1 tool hook; that is a V1 API limitation.
- **Filesystem (Linux)**: only `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc`,
  `/usr/local`, `/opt`, `/nix/store` and the explicitly allowed paths are
  visible. The workspace is read-write; everything else is read-only or
  invisible. `/tmp` is a private tmpfs; the host home is not mounted.
- **Filesystem (macOS)**: Seatbelt allowlist for the system runtime, the
  workspace, the synthetic home and explicit paths. Reads of the host home are
  denied; writes are limited to the workspace, synthetic home, temp dirs and
  explicit writable paths.
- **Environment**: cleared and rebuilt from `PATH`, `TERM`, locale, `TZ`, a
  synthetic `HOME` plus `passEnv`. `--clearenv` is used on Linux; `env -i` on
  macOS.
- **Process**: `--unshare-all`, `--cap-drop ALL`, `--die-with-parent`,
  `--new-session` (Linux); Seatbelt confinement is inherited by every child
  (macOS).
- **Network**: denied by default.

## What is **not** sandboxed

- File tools (`read`, `write`, `edit`, `patch`), MCP servers, LSP servers,
  formatters, `webfetch`/`websearch`, subagents and any process that does not
  go through the shell service. OpenCode's own permission system remains the
  control for those tools; this plugin is deliberately a **command** sandbox.
- The kernel: this is isolation, not virtualization.
- The workspace contents: a malicious `package.json` script is sandboxed when
  it runs through the shell, but the files themselves are trusted input.
- `network: "allow"`, `writablePaths`, `readablePaths` and `passEnv` widen the
  boundary by explicit user decision.
- Windows.

## Why this one

| | opencode-sandbox (V1) | this plugin |
| --- | --- | --- |
| OpenCode V2 | ❌ ([#91](https://github.com/isanchez31/opencode-sandbox-plugin/issues/91)) | ✅ native `ctx.shell.hook` |
| OpenCode V1 | ✅ | ✅ legacy adapter |
| Runtime dependencies | `@anthropic-ai/sandbox-runtime` | **zero** |
| Linux engine | bwrap via SRT | bwrap directly |
| macOS engine | Seatbelt via SRT | Seatbelt profile generated natively |
| V2 permissions/history | n/a | original command preserved |
| Network | proxy + domain allowlist | deny or allow (no proxy) |
| Defaults | permissive/enforce modes | fail-closed, network denied, env cleared |

The project deliberately does **one** thing: put the shell behind the OS
sandbox. It does not ship a management UI, a proxy, or a second permission
system.

## Verification

The suite runs real sandboxes, not mocks:

- Linux: workspace writes, host-path denial, host-home invisibility, environment
  scrubbing, network denial, extra mount opt-in, working-directory handling and
  wrapper escape refusal.
- macOS: the same suite on a real GitHub macOS runner via `/usr/bin/sandbox-exec`.
- Live smoke: an ephemeral `opencode serve` runs a real shell command through the
  V2 hook, asserts history kept the original command, and verifies a host-home
  secret and the server password stay outside the sandbox.
- Unit tests: profile construction, path validation (root/home/symlink
  escapes), option parsing, fail-closed paths, V1 adapter and idempotence.

```bash
bun install
bun run ci      # biome + tsc + 72 tests (real sandbox integration included)
bun run smoke   # live OpenCode 2.x shell + boundary check (OPENCODE_BIN to override)
```

CI makes a working sandbox a hard requirement
(`SANDBOX_REQUIRE_BWRAP=1` on Linux,
`SANDBOX_REQUIRE_SANDBOX_EXEC=1` on macOS), so integration tests cannot silently
skip. The tagged release is gated on the same Ubuntu+macOS matrix before npm
publish.

## Development

```
src/
  app.ts       V2 shell hook, fail-closed paths
  legacy.ts    V1 adapter (documented caveat)
  paths.ts     workspace/home/mount validation
  profile.ts   Linux bwrap profile
  darwin.ts    macOS Seatbelt profile
  wrapper.ts   generated wrapper + runtime directory
  binary.ts    trusted absolute binary resolution
  probe.ts     real sandbox probe
  options.ts   secure defaults
  index.ts     dual V1/V2 entrypoint
```

MIT licensed.
