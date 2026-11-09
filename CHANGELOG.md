# Changelog

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
