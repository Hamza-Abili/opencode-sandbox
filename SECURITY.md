# Security

The product **is** the boundary. Treat every claim here as load-bearing.

## Model

- **Default deny.** `network` defaults to `"deny"`; the sandbox starts from an
  empty mount namespace (Linux) or a deny-default Seatbelt profile (macOS).
  Only the system runtime, the workspace, a synthetic home and explicit extra
  mounts are visible.
- **No ambient secrets.** The environment is cleared (`--clearenv` on Linux,
  `env -i` on macOS) and rebuilt from a small allowlist plus `passEnv`.
  Provider tokens and host secrets do not reach commands unless the user
  explicitly passes them.
- **Trusted policy outside the workspace.** Security-widening settings
  (`network: "allow"`, `mode: "permissive"`, `toolGuard: "off"`,
  `writablePaths`, `readablePaths`, `passEnv`, `shell`, `deniedPaths`,
  `unsandboxedCommands`) are read only from
  `$OPENCODE_CONFIG_DIR/opencode-sandbox.json` (default
  `~/.config/opencode/opencode-sandbox.json`) or the root-owned system file.
  A repository's `opencode.json` can only tighten the result. Trusted files
  that are invalid JSON, contain unknown keys, are group/world-writable, are
  owned by another user, or live inside the workspace are ignored in favour of
  the secure defaults. Keep the user file outside sandbox-writable temp
  directories (on macOS, not under `/tmp` or `/var/folders`); the default
  `~/.config/opencode` is outside the sandbox. If the **system** file is
  present but invalid, the user file is ignored too, so an administrator typo
  cannot remove the cap. The system file is a complete baseline that caps the
  user file.
- **Protected workspace config.** A sandboxed command can write the workspace
  but not the files a host process executes later: `.opencode`,
  `opencode.json`, `opencode.jsonc`, `.claude`, `.agents`, `.git/config`,
  `.git/config.worktree`, `.git/hooks`, `.git/info/attributes`, `.git/modules`, `.git/worktrees`,
  existing `.git/worktrees/*/config.worktree` files, `.gitattributes`,
  `.gitmodules` and `.envrc`. Existing paths are read-only mounts (Linux) or
  write-denied by Seatbelt (macOS); the tool guard refuses writes even to paths
  that do not exist yet. Every symlink inside a repository-controlled protected
  tree (`.opencode`, `.claude`, `.agents`) is rejected at setup; a real
  `node_modules` directory is skipped, but a symlink named `node_modules` is
  rejected, and a protected path with a symlinked parent is rejected. A
  bounded workspace scan protects every existing nested `.git` entry: submodule
  pointer files, absorbed worktrees and nested repositories. A `.git` pointer
  may target the main repository's `.git/modules` or `.git/worktrees` outside
  the workspace (outside the sandbox and not inside a writable mount); a
  pointer to another in-workspace path outside those trees, a pointer whose raw
  path traverses a mutable workspace child, or one into a writable mount, is
  rejected. Symlinks inside a nested `.git` are rejected. The root `.git` stays writable for Git;
  the file tools refuse any nested `.git` write. On Linux, every protected-path
  ancestor directory is pinned as a mountpoint; macOS emits entry-deny rules for
  the same ancestors, so they cannot be renamed around the read-only bind.
  `.gitmodules` is protected.
  `.git/hooks`, `.git/modules` and
  `.git/worktrees` are protected as roots but not recursively scanned (host-owned; a user hook symlink may target
  a workspace path, which remains writable). A symlinked `.git/hooks` directory
  itself is rejected at setup; replace it with a real directory. Nested `.gitattributes` files are
  not individually protected. On macOS, Seatbelt denies `file-link` to protected/denied paths;
  pre-existing hardlink aliases remain a limitation (see Known limitations).
- **Denied paths.** `deniedPaths` from the trusted file are hidden from the
  shell and refused by the tool guard for reads and writes, including files in
  system roots, missing paths resolved through the nearest existing ancestor,
  and broken final symlink targets. Existing files are masked; existing directories become empty tmpfs
  mounts, so writes there are ephemeral and never reach the host. A denied path
  that is a parent of a writable mount masks the child too. Relative paths
  resolve against the workspace. On Linux, a missing or broken target cannot be
  masked until it exists; the tool guard still denies it.
- **Unsandboxed commands.** Only exact `unsandboxedCommands` entries from the
  trusted file run on the host shell. A command containing `;`, `&`, `|`, a
  backtick, `$`, `(`, `)`, `<`, `>` or a newline never matches. A `prefix *`
  entry authorizes all arguments of that command; the command inherits the host
  environment and cwd. The shortcut is logged in `OSB_TRACE` by pattern index,
  never with the command or pattern text. This is an explicit user trust
  decision, not a sandbox boundary.
- **No host home.** `$HOME` is a synthetic directory inside the sandbox; the
  host home and `~/.ssh`/`~/.aws`/cloud credentials are not mounted (Linux) or
  are outside the read allowlist (macOS).
- **Workspace guards.** A real sandbox is only built when the workspace is a
  directory, not `/`, not the host home, not an ancestor of the host home and
  not a host system or credential directory. Extra mounts must exist, are
  canonicalised, and may not be `/`, the host home, an ancestor of it, a
  credential directory or a host system path when writable. Protected system
  roots include `/run` and `/var` subtrees; `/tmp`, `/var/tmp`,
  `/private/var/tmp`, `/var/folders`, `/private/var/folders` and `/var/www` are
  the explicit writable exceptions. `/var/www` is only a convenience
  exception: do not grant it if a host web server executes files from that
  tree, because a writable document root is host code execution outside the
  sandbox. Credential directories include `~/.ssh`, cloud stores, OpenCode's
  XDG stores and `~/Library/Application Support/opencode` on macOS. The same
  path cannot be both writable and readable; the workspace is always writable.
- **Mount precedence.** Mounts are applied from broad to narrow; a more
  specific path wins. A readable subdirectory is read-only even inside the
  workspace, while a readable ancestor does not make the workspace or a more
  specific writable child read-only. Contradictory configurations (the same
  path in both lists, or the workspace as readable) are rejected at setup. The
  same plan drives Linux bind order and the macOS last-matching Seatbelt rule.
- **Fail-closed.** A real sandbox is probed at startup, then the generated
  wrapper is executed with `-c 'exit 42'`. If the binary, generated profile,
  mount, shell, layout or hook registration fails, shell commands are refused
  (`mode: "enforce"`). A shell hook also covers the TUI terminal; the tool-hook
  fallback blocks every agent shell call. If the host exposes no hook surface
  at all, setup fails loudly. `mode: "permissive"` is an explicit opt-out that
  runs shell commands unsandboxed with a warning; when the shell sandbox cannot
  be installed it also skips the tool guard.
- **Trusted binary.** bwrap/sandbox-exec is resolved once from fixed
  root-owned, non-group/world-writable absolute paths. `PATH` shims cannot
  substitute an unsandboxing binary.
- **V2 permission fidelity.** The V2 hook replaces only the shell executable.
  `event.command` is untouched, so OpenCode evaluates permission rules and
  records history against the original command. The working directory is
  validated both in the hook and again by the wrapper using `pwd -P`.
- **Tool guard (V2).** File tools and `webfetch` are checked against the same
  workspace policy by a permission hook. This is a policy layer, not an OS
  boundary; see [Tool guard](#tool-guard-v2).
- **Working directory confinement.** The wrapper refuses to run when the real
  working directory is outside the workspace or an explicit mount, including
  after a symlink swap between validation and execution.
- **Capabilities and namespaces.** `--unshare-all`, `--cap-drop ALL`,
  `--die-with-parent`, `--new-session` are always set on Linux. Seatbelt
  confinement is inherited by every child process on macOS.
- **Platforms.** Linux and macOS are supported natively. Windows is supported
  through **WSL2** (the distro is a normal Linux host). Native `win32` fails
  closed with a WSL2 hint; it has no native backend in this package.
- **No secret audit log.** There is no command log. The optional `OSB_TRACE`
  JSONL is debug-only and records events and unsandboxed pattern indexes, not
  command text or pattern values.

## V1 adapter

V1 has no shell-executable hook, so `tool.execute.before` rewrites the command
string to invoke the same wrapper. The sandbox boundary is identical, but
OpenCode V1 parses the rewritten string for its own permission rules and
records it in history; command-level deny/ask rules on the original command
are therefore not preserved. This is an upstream API limitation, not a
sandbox escape. Use V2 for permission-rule fidelity. The same hook applies the
best-effort file guard (including `apply_patch`) and the initial `webfetch`
check; V1 has no redirect hook. The V1 terminal shell is not covered by the
tool hook.

## Tool guard (V2)

The shell sandbox is kernel-enforced; the tool guard is not. It is an
in-process permission hook for OpenCode's file tools and `webfetch`:

- `read`/`glob`/`grep` may touch the workspace, `writablePaths`,
  `readablePaths` and the read-only system runtime. Host temp and OpenCode's
  retained tool-output directory are not readable by default; add one to
  `readablePaths` if needed;
- `write`/`edit`/`patch` (and V1 `apply_patch`) may touch only the workspace
  and `writablePaths`; protected workspace config and `deniedPaths` are always
  refused, including when the path does not exist yet;
- `deniedPaths` are refused for reads as well;
- `webfetch` is allow, deny, or hostname-allowlisted, and OpenCode checks every
  redirect through the same hook;
- symlinks, including broken links, are resolved component by component before
  the policy check.

It protects against prompt injection and misconfigured permissions, not against
a compromised OpenCode process or a malicious plugin running in the same
process. The V1 `tool.execute.before` guard is best-effort and does not see
`webfetch` redirects. MCP, LSP, `websearch`, image generation and non-shell
subprocesses remain outside. `webfetch` defaults to `"allow"`; use `"deny"` or
a non-empty `webfetchAllowlist` when exfiltration is in scope.

## Known limitations

- The **shell service** is OS-sandboxed. On V2, file tools and `webfetch` are
  policy-guarded in-process; on V1 they are best-effort. MCP servers, LSP
  servers, formatters, `websearch`, the image-generation provider call,
  subagents' other tools and processes outside the shell service remain outside
  the OS boundary. Local image inputs and image URLs still go through the same
  `read`/`webfetch` policy. The tool guard is not a substitute for a
  whole-process sandbox when the threat includes a compromised OpenCode.
- The tool guard resolves symlinks but not hard links or a path swapped after
  the check. A same-process attacker able to race the check is out of scope.
  On Linux, protected paths are separate mounts, so a new hardlink across them
  fails. On macOS, the profile denies `file-link` to protected/denied paths,
  but pre-existing hardlink aliases remain a path-based limitation; use a
  whole-process sandbox for hostile code.
- OpenCode management tools that use the `edit` permission for paths outside
  the workspace, such as `worktree_remove`, are denied while the tool guard is
  enforced. Manage worktrees outside OpenCode or set `toolGuard: "off"` if that
  workflow is required.
- On a V2 build that exposes neither `ctx.permission.hook` nor `ctx.tool.hook`,
  the shell sandbox remains active but file tools cannot be guarded. The plugin
  logs this at startup; `toolGuard: "enforce"` is best-effort on such a host.
- On a V2 build that has the permission hook but no `ctx.tool.hook`, the
  `write`/`edit`/`patch` tools may open a target before the permission hook
  denies the write. The write itself is denied; the pre-read contents are not
  returned to the model.
- OpenCode's retained tool-output directory is **not** readable by the tool
  policy by default. Add it to `readablePaths` if you need truncated results;
  it may contain output from other sessions of the same user.
- OpenCode management tools that do not assert a permission, such as
  `worktree_create` and `session_move`, are outside the tool policy.
- OpenCode's project instruction/config loader (`AGENTS.md`,
  `.opencode/opencode.json`, project plugins) runs in the host process outside
  the tool guard. The read tool's `AGENTS.md` discovery is checked, but
  bootstrap and reload reads are not. Protected paths stop a **sandboxed
  command** from planting those files; a repository that already ships a
  malicious plugin or config is trusted code before this plugin loads. Use a
  whole-process sandbox for that threat.
- An OpenCode project config can **remove** a plugin before it runs
  (`"plugins": []` or `"-@hamzaabili/opencode-sandbox"`). No plugin can make
  itself non-removable today
  ([opencode#57687](https://github.com/anomalyco/opencode/issues/57687)).
  Managed hosts can pin the plugin in `/etc/opencode/opencode.json`; for
  hostile repositories use a whole-process sandbox. The trusted policy limits
  what a loaded plugin may do, not whether it loads.
- On Linux, a protected or denied path that does not exist cannot be
  bind-mounted, so a shell command can create it. The tool guard still denies
  the file tools. On macOS, Seatbelt denies the write even when the path is
  missing. Create the file/directory before relying on the Linux gap being
  closed.
- On macOS, Seatbelt rules are path-based. The profile denies `file-link` to
  protected/denied paths and denies the `.git` and protected directory entries
  against rename, but pre-existing hardlink aliases and nested
  `.gitattributes` remain out of scope. Use a whole-process sandbox for hostile
  code on macOS. Linux pins protected entries as mounts, so a new cross-mount
  hardlink fails (`EXDEV`).
- The protected/denied sets are path-based on both platforms: pre-existing
  hardlinks or aliases outside the named paths are not detected.
- Existing nested `.git` entries inside the workspace are protected by a
  bounded scan; a `.git` pointer to another in-workspace path outside
  `.git/modules` is rejected. The root `.git` stays writable for Git. A nested
  `.git` created after setup remains a shell missing-path residual; a submodule
  not checked out at setup is the same class.
- When OpenCode is opened in a subdirectory of a repository, sibling submodules
  outside that workspace are repository content the sandbox cannot write; they
  are not individually protected and remain trusted-repository input.
- A submodule `.git` pointer that does not exist at setup is a missing protected
  path on Linux; the tool guard denies it, but the shell gap remains until it
  exists.
- A workspace with more than 50,000 entries (excluding `node_modules`) fails
  closed rather than skipping nested `.git` protection.
- An allowed `.git/modules` or `.git/worktrees` pointer target that does not
  exist at setup is the same Linux missing-path class; the tool guard denies
  writes, but the shell can create the target until it exists.
- A nested repository with its own checked-out submodules/worktrees is not
  supported; open it at its root.
- `.git/hooks` is protected as a root but not recursively scanned. If a user
  symlinks a hook into the workspace, that target is writable by the sandbox;
  keep hook targets outside the workspace.
- V1 replay tracking is bounded to keep memory small; a replay evicted from the
  bound is refused, never run unsandboxed.
- `unsandboxedCommands` runs the matching command on the host by explicit user
  decision. The matcher is conservative (no metacharacters, no chained
  commands), but the authorized command itself is not sandboxed. Keep the list
  narrow and review it.
- `deniedPaths` masks existing files/directories. A missing denied path is
  enforced by the tool guard only; the shell cannot be masked until it exists.
- V1 `webfetch` redirects are not covered by the tool guard; only the initial
  URL is checked.
- The `webfetch` tool checks every redirect through the permission hook. The
  `image_generate` tool checks its input image URL only once, then follows
  redirects internally; an allowed host can redirect an image URL to a host
  outside the allowlist. Use `webfetch: "deny"` when image URL exfiltration is
  in scope.
- Do not run OpenCode as root. The workspace and credential guard is scoped to
  the home of the user running OpenCode and the listed system roots; a
  root-run process broadens what is readable and writable, including other
  users' homes.
- bwrap and Seatbelt share the host kernel: this is isolation, not
  virtualization. A kernel exploit is out of scope.
- Linux mounts `/etc` read-only. World-readable files there (and the workspace
  itself) remain visible; do not place secrets in a world-readable `/etc` file
  or in the workspace.
- macOS read access is allowlisted to the system runtime, workspace, synthetic
  home and explicit readable paths; metadata (`stat`) is allowed
  globally so path resolution works. File contents outside the allowlist are
  denied. Host temp dirs are not visible; writes are limited to the workspace,
  synthetic home (including its tmp) and explicit writable paths. `TMPDIR`
  points at the synthetic home temp. The allowlist includes read-only system trees such as `/Library`,
  `/private/var/db`, `/opt` and `/usr/local`; they are not the host home, but
  they may contain application data or package-manager configuration.
- `network: "allow"` shares the whole host network. There is no shell-network
  domain allowlist and no TLS-intercepting proxy; use the OS firewall or a VM
  if you need per-host shell egress control. `webfetchAllowlist` filters the
  `webfetch` tool by hostname; it is not a proxy and does not govern shell
  egress.
- Explicit `writablePaths`, `readablePaths` and `passEnv` are trust decisions.
- Windows is unsupported and fails closed.
- The startup probe proves the sandbox can be created at load time. A later
  per-command failure is reported by the command itself (the wrapper exits
  non-zero); it is never silently retried unsandboxed.

## Reporting

Report vulnerabilities privately via GitHub's "Report a vulnerability" flow on
the repository. Do not open a public issue for a suspected sandbox escape.
