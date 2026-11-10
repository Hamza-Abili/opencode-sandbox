# Distribution notes

Prepared submission payloads. Both directories are curated; a premature or
low-quality submission is worse than waiting.

## opencode.cafe

Submission page: <https://opencode.cafe/submit> (Clerk login required).

| Field | Value |
| --- | --- |
| Type | `plugin` |
| Product ID | `@hamzaabili/opencode-sandbox` |
| Display name | `OpenCode Sandbox` |
| Repository | `https://github.com/Hamza-Abili/opencode-sandbox` |
| Homepage | `https://www.npmjs.com/package/@hamzaabili/opencode-sandbox` |
| Tags | `sandbox, security, bubblewrap, seatbelt, command-sandbox, v1, v2` |

Description:

> Native command sandbox for OpenCode V1 and V2 agent shell commands. Commands
> run inside bubblewrap on Linux or Seatbelt on macOS: read-only system,
> writable workspace, synthetic HOME, cleared ambient secrets, network denied
> by default. Fail-closed with a real startup probe and zero runtime
> dependencies. On V1 the plugin covers the agent's bash tool, not the
> interactive terminal shell.

Installation:

```sh
opencode plugin add @hamzaabili/opencode-sandbox@0.1.2
```

or, for V1:

```jsonc
{
  "plugin": [["@hamzaabili/opencode-sandbox", { "network": "deny" }]]
}
```

## awesome-opencode

Guidelines: <https://github.com/awesome-opencode/awesome-opencode/blob/main/contributing.md>

**Eligibility gate:** the repository must be at least 30 days old and have at
least 25 stars. Check both before submitting.

File: `data/plugins/opencode-sandbox.yaml`

```yaml
name: OpenCode Sandbox
repo: https://github.com/Hamza-Abili/opencode-sandbox
tagline: Native bubblewrap/Seatbelt sandbox for OpenCode V1/V2 agent shell commands.
description: >-
  Runs OpenCode agent shell commands inside bubblewrap on Linux or Seatbelt on
  macOS. The system is read-only, the workspace writable, HOME synthetic,
  ambient secrets cleared and the network denied by default. Fail-closed: if
  the sandbox cannot be created the command is refused. V1 covers the agent's
  bash tool, not the interactive terminal shell. V1 and V2 adapters, real
  startup probe, zero runtime dependencies.
```

## OpenCode official ecosystem docs

Add one row under `## Plugins` on <https://opencode.ai/docs/ecosystem/>:

```markdown
| [opencode-sandbox](https://github.com/Hamza-Abili/opencode-sandbox) | Native bubblewrap/Seatbelt sandbox for OpenCode V1/V2 agent shell commands |
```

## Tracking

```sh
npm view @hamzaabili/opencode-sandbox version
gh repo view Hamza-Abili/opencode-sandbox --json stargazerCount
gh issue list --repo Hamza-Abili/opencode-sandbox --state open
```
