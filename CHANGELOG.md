# Changelog

## 0.3.0 — trusted policy and workspace hardening

Security release. Versions up to and including 0.2.1 read security policy from
the merged OpenCode plugin options, which a repository's own `opencode.json`
can override. A cloned repository could therefore set `network: "allow"`,
`mode: "permissive"`, `toolGuard: "off"`, add `~/.ssh` as readable, or pass a
provider token. A sandboxed command could also write `.opencode/plugin/*.ts`,
`.git/hooks`, `opencode.json` or `.envrc`, which a host process executes later.

- **Trusted policy outside the workspace.** Widening options are read only from
  `$OPENCODE_CONFIG_DIR/opencode-sandbox.json` (default
  `~/.config/opencode/opencode-sandbox.json`) and the root-owned system file
  (`/etc/opencode/opencode-sandbox.json` on Linux,
  `/Library/Application Support/opencode/opencode-sandbox.json` on macOS).
  The system file caps the user file; plugin options can only tighten the
  result. Invalid, unknown-key, group/world-writable, foreign-owned, or
  workspace-local policy files are ignored with an error, never partially
  applied. A present-but-invalid **system** file also disables the user file,
  so an administrator typo cannot remove the cap.
- **Protected workspace config.** `.opencode`, `opencode.json`,
  `opencode.jsonc`, `.claude`, `.agents`, `.git/config`,
  `.git/config.worktree`, `.git/hooks`, `.git/info/attributes`, `.git/modules`, `.git/worktrees`,
  `.gitmodules`, `.gitattributes` and `.envrc` are read-only inside the
  sandbox and write-denied by the tool guard. Existing linked-worktree
  `config.worktree` files are covered. Any symlink inside a
  repository-controlled protected tree (`.opencode`, `.claude`, `.agents`) is
  rejected at setup; a real `node_modules` directory is skipped, but a symlink
  named `node_modules` is rejected, and a protected path with a symlinked
  parent is rejected. A bounded workspace scan protects every existing nested
  `.git` entry (submodule pointer files, absorbed worktrees, nested
  repositories). A `.git` pointer to the main repository's `.git/modules` or
  `.git/worktrees` outside the workspace is allowed (not writable); a pointer
  to another in-workspace path outside those trees, through a mutable workspace
  child, or into a writable mount is rejected. The file tools refuse writes to
  any nested `.git` while the root `.git` stays writable.
  `.git/hooks`/`.git/modules`/`.git/worktrees` roots are protected but not
  recursively scanned.
  A symlinked `.git/hooks` directory is rejected at setup.
  On Linux, `.git` is pinned as a mountpoint (rename-proof) and explicit
  read-only `.git/...` mounts keep precedence. macOS denies the `.git` and
  protected directory entries against rename and denies `file-link` to
  protected/denied paths. This closes the existing-path "plant a plugin/hook
  and wait for restart/commit" escalation; platform residuals are listed
  below.
- **Tool-guard temp reads removed.** Host `<os.tmpdir>/opencode` and OpenCode's
  retained `tool-output` directory are no longer automatic read roots. They can
  contain other sessions' images or truncated output; add one to
  `readablePaths` if needed. This also keeps the macOS tool guard consistent
  with the shell's host-temp isolation.
- **`deniedPaths`.** Trusted-only list of paths hidden from the sandbox
  (`read` and `write` denied). Existing files are masked, including system
  roots; existing directories become empty tmpfs mounts; a denied parent masks
  a writable child; missing paths under symlinked parents and broken final
  symlink targets are resolved through the nearest existing ancestor. On Linux
  a missing/broken target cannot be masked until it exists; the tool guard still
  denies it. Use it for `.env`, `secrets/` and similar.
- **`unsandboxedCommands`.** Trusted-only exact/`prefix *` commands that run
  on the host. The matcher rejects `;`, `&`, `|`, backtick, `$`, `(`, `)`,
  `<`, `>` and newlines, so an entry cannot authorize a chained command. A
  `prefix *` entry authorizes all arguments and the command inherits the host
  environment and cwd. Matches are logged by pattern index, never with the
  command or pattern text.
- **macOS host temp isolation.** Host `/tmp`, `/private/tmp`, `/var/folders`
  and `/private/var/folders` are neither readable nor writable; the synthetic
  home's `tmp` is `TMPDIR`. Workspace symlinks to the host home or host temp
  are denied by resolved-path rules; integration tests cover reads and writes.
- **WSL2.** Windows is supported through WSL2; the startup log reports the WSL
  distro and native `win32` fails closed with a WSL2 hint. The doctor reports
  the same and points at the AppArmor/userns check.
- **`doctor`.** `bunx --bun @hamzaabili/opencode-sandbox doctor [--json]` prints
  the platform/WSL state, trusted policy status, effective policy, mount
  counts, trusted binary and a real **generated-wrapper** probe (including the
  configured shell). Exit codes are 0/1/2.
- **V1 replay safety.** A caller-supplied command that starts with the
  generated wrapper prefix is refused instead of trusted. A replay is accepted
  only when both the OpenCode call ID and the exact rewritten command match;
  a fresh command under an old call ID is wrapped again (or refused if it
  claims to be a wrapper). This closes a V1 host escape available from the
  command string recorded in history.
- **Tests.** 216 tests, including a live smoke with a hostile project config,
  protected/denied integration on real bwrap/Seatbelt, policy precedence,
  unsafe-file rejection, unsandboxed pattern matching and WSL detection.
- **Migration (breaking).** Move `network: "allow"`, `mode: "permissive"`,
  `toolGuard: "off"`, `writablePaths`, `readablePaths`, `passEnv`, `shell`,
  `deniedPaths` and `unsandboxedCommands` from the plugin entry to the trusted
  user file. Tightening values can stay in the plugin entry. The plugin logs a
  warning for each ignored widening option.

### Known residual

- A project config can still **remove** the plugin
  (`"plugins": []`); this is an OpenCode plugin-loading limitation
  ([opencode#57687](https://github.com/anomalyco/opencode/issues/57687)).
  Managed hosts can pin the plugin in `/etc/opencode/opencode.json`; use a
  whole-process sandbox for hostile repositories.
- On Linux, a protected or denied path that does not exist cannot be
  bind-mounted. The tool guard still denies the file tools; create the path
  before relying on the shell gap being closed.
- A nested repository with its own checked-out submodules/worktrees is not
  supported; open it at its root.
- `.git/hooks` and `.git/modules` are protected as roots but not recursively
  scanned. A user-created hook symlink into the workspace remains writable;
  keep hook targets outside the workspace. A nested `.git` created after setup
  is denied to the file tools but remains a shell missing-path residual.
- On macOS, Seatbelt rules are path-based: pre-existing hardlink aliases and
  nested `.gitattributes` files are not contained. New `file-link` calls to
  protected/denied paths are denied. Use a whole-process sandbox for hostile
  code on macOS.

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
