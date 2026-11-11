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
- **No secret audit log.** There is no command log. The optional `OSB_TRACE`
  JSONL is debug-only and records events, not command text.

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
  `readablePaths`, the read-only system runtime and OpenCode's temp directory
  (`<os.tmpdir>/opencode`, used for generated images);
- `write`/`edit`/`patch` (and V1 `apply_patch`) may touch only the workspace
  and `writablePaths`; OpenCode's image generator may still write its default
  output under its own temp directory when no model-selected path is given;
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
  the check. A same-process attacker able to race the check is out of scope;
  the OS shell sandbox remains the stronger boundary.
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
- OpenCode's retained tool-output directory is read-only in the tool policy so
  the model can open truncated results. It may contain output from other
  sessions of the same user; it is not a cross-user boundary.
- OpenCode management tools that do not assert a permission, such as
  `worktree_create` and `session_move`, are outside the tool policy.
- OpenCode's project instruction/config loader (`AGENTS.md`,
  `.opencode/opencode.json`, project plugins) runs in the host process outside
  the tool guard. The read tool's `AGENTS.md` discovery is checked, but
  bootstrap and reload reads are not. A workspace-writable symlink or config
  file can therefore be loaded before the policy sees it; use a whole-process
  sandbox for that threat.
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
  home, temp dirs and explicit readable paths; metadata (`stat`) is allowed
  globally so path resolution works. File contents outside the allowlist are
  denied. The allowlist includes read-only system trees such as `/Library`,
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
