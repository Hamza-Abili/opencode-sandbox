# Changelog

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
