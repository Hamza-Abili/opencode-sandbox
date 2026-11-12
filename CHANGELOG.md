# Changelog

## 0.2.1 — documentation correction only

- No runtime changes. Corrected the nono comparison in the README:
  `--standalone` is the full-containment recommendation because OpenCode's
  background daemon owns tool execution; the `OPENCODE_DISABLE_PROJECT_CONFIG`
  workaround is no longer assumed to be current. See the README for the
  daemon-level explanation.

## 0.2.0 — in-process tool guard

- **Tool guard on V2, enabled by default.** A new `ctx.permission.hook`
  applies the workspace policy to OpenCode's file tools and `webfetch`:
  `read`/`glob`/`grep` may touch the workspace, `writablePaths`,
  `readablePaths` and the read-only system runtime; `write`/`edit`/`patch`
  may touch only the workspace and `writablePaths`. Paths outside the policy
  are denied with a readable message.
- **`webfetch` policy.** `webfetch: "deny"` blocks the tool;
  `webfetchAllowlist` restricts it to hostnames (`*.example.com` matches the
  apex and subdomains). The `webfetch` tool checks redirects through the same
  permission hook, so an allowed host cannot redirect around the list.
  `image_generate` checks only its initial image URL; its redirects are not
  re-checked.
- **Symlink-aware checks.** Targets are resolved component by component,
  including broken links, before the path policy is applied. A symlink inside
  the workspace cannot point a file tool at `~/.ssh`.
- **V1 best-effort guard.** The legacy `tool.execute.before` hook checks file
  arguments (including `apply_patch`), patch headers with the V1 parser's
  prefix/trim rules, and the initial `webfetch` URL. V1 has no redirect hook,
  so redirects are not covered there.
- **Fail closed without losing the shell sandbox.** If the V2 permission hook
  is unavailable or registration fails, the plugin keeps the shell sandbox and
  blocks the guarded tools through the tool hook. If an option is malformed,
  it logs the error and falls back to `toolGuard: "enforce"` /
  `webfetch: "deny"`; a configuration typo never disables the plugin.
  `toolGuard: "off"` restores the 0.1 shell-only behavior.
- README and SECURITY document the policy layer, its limits (in-process, not
  OS-enforced; MCP/LSP/websearch/image generation remain outside), and the
  tradeoff against whole-process sandboxes such as nono and OpenShell.
- 152 tests, including tool-policy symlink/broken-link escapes, mount policy,
  webfetch allowlists and the V1 adapter. The live smoke now asserts that the
  V2 tool guard is registered.

### Compatibility watchdog automation

- `upstream-watch` now closes its own compatibility loop: it installs the
  exact new OpenCode version, runs `bun run compat` (CI plus live smoke),
  opens a docs-only pull request that moves the `tested on X.Y.Z;` README
  anchor, and comments the evidence. Merging the PR updates the anchor and
  closes the issue; a failed check leaves it open for the next daily run.
  The anchor never moves backwards.

## 0.1.2 — packaging and discoverability only

- No runtime changes: `src/` and `index.ts` are identical to 0.1.1.
- Added `homepage` and search keywords (`command-sandbox`, `agent-sandbox`,
  `linux`) to `package.json`, and a short cross-link section for the other
  plugins by the same author.

## 0.1.1 — mount precedence and boundary hardening

- **Deterministic mount precedence.** Both engines now apply mounts from the
  broadest to the narrowest path. A specific readable subdirectory overrides the
  writable workspace; a readable ancestor no longer makes the workspace
  read-only; a writable child wins over a readable parent. The same path cannot
  be both writable and readable, and the workspace cannot be listed as
  readable: contradictory configurations fail at setup.
- **Readable paths are really read-only on macOS.** Seatbelt write rules are
  emitted broad-to-narrow with `deny file-write*` for readable paths, matching
  the Linux bind order. Writable paths are also readable on macOS (previously
  they were write-only), and they are added to the sandbox `PATH` roots.
- **System-write guard covers `/run` and `/var` subtrees.** `/run`, `/var/lib`,
  `/var/log`, `/var/spool`, `/private/var/...` and the other system roots are
  rejected as workspace or writable mounts. `/tmp`, `/var/tmp`,
  `/private/var/tmp`, `/var/folders`, `/private/var/folders` and `/var/www`
  remain explicit writable exceptions.
- **macOS credential guard.** `~/Library/Application Support/opencode` is now a
  protected credential directory, alongside the XDG stores and `~/.ssh`.
- **Exact-wrapper probe.** Setup now runs the generated wrapper with
  `-c 'exit 42'` after writing it, so a broken profile, mount or configured
  `shell` fails closed before the first command instead of surfacing later.
- **Compatibility watch and packaging.** Added the upstream OpenCode
  compatibility workflow and README anchor; `scripts/` is included in the npm
  package so the published `smoke` script is runnable. Documentation now
  states the mount-precedence rules, the system-root exceptions and the
  subagent shell/file-tool distinction.
- 90 tests, including real bwrap integration, macOS profile rules and a
  failing-shell setup test.

## 0.1.0 — first release

- OpenCode **V1 and V2** from one package: V2 uses `ctx.shell.hook("create.before")`
  and replaces only the shell executable; V1 uses the documented
  `tool.execute.before` adapter.
- **Linux** engine: native bubblewrap. Read-only system runtime, writable
  workspace, private `/tmp`, synthetic `$HOME`, XDG dirs, cleared environment,
  `--unshare-all`, `--cap-drop ALL`, `--die-with-parent`, `--new-session`.
- **macOS** engine: native Seatbelt (`sandbox-exec`) profile generated with
  zero dependencies. Deny-default read allowlist, writable workspace/synthetic
  home/temp, environment cleared with `env -i`, network denied by default.
- **Fail-closed**: trusted absolute binary resolution, real sandbox probe, and
  a blocking hook when the sandbox cannot be installed. `mode: "permissive"`
  is the only explicit opt-out.
- Workspace safety: rejects `/`, the host home and ancestors of the host home;
  extra mounts are canonicalised and validated; symlinks cannot turn into `/`.
- Working directory fidelity: the original `cwd`/`workdir` is preserved and
  re-validated by the wrapper with `pwd -P`.
- V2 permission/history fidelity: the command string is never rewritten.
- Optional `OSB_TRACE` JSONL debug events (no command text).
- 72 tests including real bwrap integration and a real macOS CI job; live V2
  smoke against OpenCode 2.2.5 executing a sandboxed shell command and checking
  history, cwd, host-home denial and environment clearing.
- Windows fails closed.
