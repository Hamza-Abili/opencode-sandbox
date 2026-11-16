/**
 * opencode-sandbox — workspace paths that must not become attacker-controlled.
 *
 * A sandboxed command can write the workspace. That is the point of a
 * workspace-write sandbox, but a few workspace files are executed later by a
 * host process outside the sandbox: OpenCode loads project plugins/config at
 * startup, Git runs hooks and configured filters, and direnv evaluates
 * `.envrc`. Leaving those writable turns a prompt-injected command into host
 * code execution after the next restart or `git commit`.
 *
 * They are read-only inside the sandbox and write-denied by the tool guard.
 * Reads stay available. Paths that do not exist yet cannot be bind-mounted on
 * Linux; the tool guard still denies the file tools, and the gap is documented.
 */

import fs from "node:fs";
import path from "node:path";
import { canonicalTarget, contains } from "./path-utils.ts";

/** Relative to the workspace root. */
export const PROTECTED_WORKSPACE_PATHS = [
  ".opencode",
  "opencode.json",
  "opencode.jsonc",
  ".claude",
  ".agents",
  ".git/config",
  ".git/config.worktree",
  ".git/hooks",
  ".git/info/attributes",
  ".git/modules",
  ".git/worktrees",
  ".gitattributes",
  ".gitmodules",
  ".envrc",
];

/** Trees whose repository-controlled contents a host process loads later. */
const NESTED_PROTECTED_DIRS = [".opencode", ".claude", ".agents"];

const MAX_PROTECTED_ENTRIES = 50_000;

function realpathOrNull(target: string): string | null {
  try {
    return fs.realpathSync.native(target);
  } catch {
    return null;
  }
}

function lstatOrNull(target: string): fs.Stats | null {
  try {
    return fs.lstatSync(target);
  } catch {
    return null;
  }
}

const MAX_GIT_POINTER_BYTES = 16 * 1024;

interface GitPointer {
  target: string;
  raw: string;
  base: string;
}

/** Read a `gitdir:` pointer file, resolving it relative to its directory. */
function gitPointerTarget(file: string): GitPointer | undefined {
  const info = lstatOrNull(file);
  if (info === null || !info.isFile()) return undefined;
  if (info.size > MAX_GIT_POINTER_BYTES) {
    throw new Error(`${file} is too large to be a gitdir pointer; refusing`);
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(file));
  } catch {
    throw new Error(`${file} is not a valid UTF-8 gitdir pointer; refusing`);
  }
  const match = /^gitdir:\s*(.+?)\s*$/m.exec(text);
  if (match === null) return undefined;
  const raw = match[1];
  const base = canonicalTarget(path.dirname(file));
  const target = canonicalTarget(path.isAbsolute(raw) ? raw : `${base}${path.sep}${raw}`);
  return { target, raw, base };
}

/**
 * A pointer target can be external at setup but later resolve inside the
 * workspace if a normal workspace component is swapped for a symlink. Walk the
 * raw path with kernel symlink/`..` semantics and report any mutable workspace
 * child it traverses. Only the root `.git`, `.git/modules` and
 * `.git/worktrees` are trusted workspace components.
 */
function traversedWorkspaceChildren(
  pointer: GitPointer,
  workspace: string,
  rootGitReal: string,
  modules: string,
  worktrees: string
): string[] {
  const parts = pointer.raw.split(path.sep).filter(Boolean);
  let current = path.isAbsolute(pointer.raw) ? path.sep : pointer.base;
  const bad: string[] = [];
  for (const part of parts) {
    if (part === ".") continue;
    if (part === "..") {
      current = path.dirname(current);
      continue;
    }
    const next = path.join(current, part);
    const info = lstatOrNull(next);
    const symlink = info?.isSymbolicLink() === true;
    // System aliases such as macOS /var -> /private/var are root-owned and not
    // replaceable by the sandbox; a user-owned workspace symlink is mutable and
    // never becomes trusted merely because its current target is protected.
    const trustedAlias = symlink && info !== null && info.uid === 0 && (info.mode & 0o022) === 0;
    const resolved = canonicalTarget(next);
    if (contains(workspace, next) || contains(workspace, resolved)) {
      const pathTrusted =
        next === workspace ||
        next === rootGitReal ||
        contains(modules, next) ||
        contains(worktrees, next);
      const resolvedTrusted =
        (!symlink || trustedAlias) &&
        (resolved === workspace ||
          resolved === rootGitReal ||
          contains(modules, resolved) ||
          contains(worktrees, resolved));
      if (!pathTrusted && !resolvedTrusted) bad.push(next);
    }
    current = resolved;
  }
  return bad;
}

function assertPointerSafe(
  pointer: GitPointer,
  workspace: string,
  rootGitReal: string,
  modules: string,
  worktrees: string,
  writablePaths: readonly string[]
): void {
  const bad = traversedWorkspaceChildren(pointer, workspace, rootGitReal, modules, worktrees);
  if (bad.length > 0) {
    throw new Error(`workspace .git pointer traverses writable workspace path ${bad[0]}; refusing`);
  }
  const gitDir = pointer.target;
  if (contains(workspace, gitDir) && !contains(modules, gitDir) && !contains(worktrees, gitDir)) {
    throw new Error(`workspace .git pointer targets writable path ${gitDir}; refusing`);
  }
  if (writablePaths.some((root) => contains(root, gitDir))) {
    throw new Error(`workspace .git pointer targets a writable mount ${gitDir}; refusing`);
  }
}

/** Reject symlinks inside a nested .git dir except object stores. */
function rejectGitSymlinks(gitDir: string): void {
  const stack = [gitDir];
  let seen = 0;
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let entries: string[];
    try {
      entries = fs.readdirSync(current);
    } catch (error) {
      throw new Error(
        `cannot inspect nested .git ${current}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    for (const name of entries) {
      seen += 1;
      if (seen > MAX_PROTECTED_ENTRIES) {
        throw new Error(`nested .git ${gitDir} has too many entries; refusing to guess`);
      }
      const target = path.join(current, name);
      let info: fs.Stats;
      try {
        info = fs.lstatSync(target);
      } catch (error) {
        throw new Error(
          `cannot inspect nested .git path ${target}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      if (info.isSymbolicLink()) {
        throw new Error(
          `nested .git path ${target} is a symlink; replace it with a regular file or directory`
        );
      }
      if (info.isDirectory() && name !== "objects") stack.push(target);
    }
  }
}

/** Reject a symlinked parent that could redirect a protected path outside. */
function assertRegularParents(workspace: string, lexical: string): void {
  const relative = path.relative(workspace, lexical);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return;
  }
  const parts = relative.split(path.sep);
  let current = workspace;
  for (let index = 0; index < parts.length - 1; index++) {
    current = path.join(current, parts[index]);
    const info = lstatOrNull(current);
    if (info === null) return;
    if (info.isSymbolicLink()) {
      throw new Error(
        `protected workspace path ${lexical} has a symlinked parent ${current}; replace it with a regular directory`
      );
    }
  }
}

/** Add a path, its real target inside the workspace, and reject symlinks. */
function addProtected(result: Set<string>, workspace: string, lexical: string): void {
  assertRegularParents(workspace, lexical);
  const info = lstatOrNull(lexical);
  if (info?.isSymbolicLink()) {
    throw new Error(
      `protected workspace path ${lexical} is a symlink; replace it with a regular file or directory`
    );
  }
  result.add(lexical);
  const resolved = realpathOrNull(lexical);
  if (resolved !== null && contains(workspace, resolved)) result.add(resolved);
}

/**
 * A symlink nested inside a repository-controlled protected tree is still
 * followed by the host loader (for example
 * `.opencode/plugin/x.ts -> ../../plugins/x.ts`). The read-only bind protects
 * the link itself, not its writable target, so reject the tree at setup.
 *
 * `lstat` is used per entry rather than `Dirent` type bits: filesystems that
 * return DT_UNKNOWN make every Dirent predicate false and would hide both the
 * symlink and the subdirectory. A real `node_modules` directory is skipped
 * (package managers create symlinks inside it); a symlink *named*
 * `node_modules` is rejected.
 */
function rejectNestedSymlinks(root: string): void {
  const stack = [root];
  let seen = 0;
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let entries: string[];
    try {
      entries = fs.readdirSync(current);
    } catch (error) {
      throw new Error(
        `cannot inspect protected workspace tree ${root}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    for (const name of entries) {
      seen += 1;
      if (seen > MAX_PROTECTED_ENTRIES) {
        throw new Error(
          `protected workspace tree ${root} has more than ${MAX_PROTECTED_ENTRIES} entries; refusing to guess`
        );
      }
      const target = path.join(current, name);
      let info: fs.Stats;
      try {
        info = fs.lstatSync(target);
      } catch (error) {
        throw new Error(
          `cannot inspect protected workspace path ${target}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      if (name === "node_modules") {
        if (info.isSymbolicLink()) {
          throw new Error(
            `protected workspace path ${target} is a symlink; replace it with a regular directory`
          );
        }
        continue;
      }
      if (info.isSymbolicLink()) {
        throw new Error(
          `protected workspace path ${target} is a symlink; replace it with a regular file or directory`
        );
      }
      if (info.isDirectory()) stack.push(target);
    }
  }
}

/**
 * Find `.git` entries inside the workspace (submodules, nested repositories,
 * absorbed worktrees) and protect them. A `.git` file pointer may point outside
 * the workspace (main repository `.git/modules` for a linked worktree); that
 * target is outside the sandbox and not writable, while the pointer file is
 * protected. A pointer to another in-workspace path outside `.git/modules` or
 * `.git/worktrees` is rejected: Git would execute config/hooks from a path the
 * sandbox can write.
 */
function protectNestedGit(
  result: Set<string>,
  workspace: string,
  writablePaths: readonly string[]
): void {
  const rootGit = path.join(workspace, ".git");
  const rootGitReal = realpathOrNull(rootGit) ?? rootGit;
  const modules = path.join(rootGitReal, "modules");
  const worktrees = path.join(rootGitReal, "worktrees");
  const stack = [workspace];
  let seen = 0;
  while (stack.length > 0) {
    const current = stack.pop() as string;
    let entries: string[];
    try {
      entries = fs.readdirSync(current);
    } catch (error) {
      throw new Error(
        `cannot inspect workspace ${current}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    for (const name of entries) {
      if (name === "node_modules") continue;
      seen += 1;
      if (seen > MAX_PROTECTED_ENTRIES) {
        throw new Error(
          `workspace has more than ${MAX_PROTECTED_ENTRIES} entries; refusing to guess nested .git protection`
        );
      }
      const target = path.join(current, name);
      let info: fs.Stats;
      try {
        info = fs.lstatSync(target);
      } catch (error) {
        throw new Error(
          `cannot inspect workspace path ${target}: ${error instanceof Error ? error.message : String(error)}`
        );
      }
      const isGitName = name.toLowerCase() === ".git";
      if (isGitName && info.isSymbolicLink()) {
        throw new Error(
          `workspace .git ${target} is a symlink; replace it with a regular file or directory`
        );
      }
      if (info.isSymbolicLink()) continue;
      if (isGitName) {
        const targetReal = realpathOrNull(target) ?? target;
        if (target === rootGit || targetReal === rootGitReal) continue;
        if (info.isFile()) {
          const pointer = gitPointerTarget(target);
          if (pointer !== undefined) {
            assertPointerSafe(pointer, workspace, rootGitReal, modules, worktrees, writablePaths);
          }
        } else if (info.isDirectory()) {
          rejectGitSymlinks(target);
        }
        addProtected(result, workspace, target);
        continue;
      }
      if (info.isDirectory()) stack.push(target);
    }
  }
}

/**
 * Every protected path, absolute and deduplicated. The lexical path is always
 * present so the tool guard can reject a write even when the path does not
 * exist. Existing real targets inside the workspace are included so a symlink
 * cannot redirect a write to an unprotected alias.
 *
 * A worktree uses a `.git` *file*; protecting the `.git` directory wholesale
 * would break `git add`/`commit`, so only the pointer file is protected in
 * that layout.
 */
export function protectedPaths(workspace: string, writablePaths: readonly string[] = []): string[] {
  const result = new Set<string>();
  for (const relative of PROTECTED_WORKSPACE_PATHS) {
    addProtected(result, workspace, path.join(workspace, relative));
  }

  for (const relative of NESTED_PROTECTED_DIRS) {
    const root = path.join(workspace, relative);
    const info = lstatOrNull(root);
    if (info?.isDirectory()) rejectNestedSymlinks(root);
  }

  protectNestedGit(result, workspace, writablePaths);

  // Linked worktrees keep per-worktree config under .git/worktrees/<id>.
  // Protect the files that exist; a not-yet-created one follows the same
  // Linux missing-path rule as the other protected paths.
  const worktrees = path.join(workspace, ".git", "worktrees");
  try {
    for (const entry of fs.readdirSync(worktrees, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        addProtected(result, workspace, path.join(worktrees, entry.name, "config.worktree"));
      }
    }
  } catch {
    // No linked worktrees.
  }

  const git = path.join(workspace, ".git");
  const gitInfo = lstatOrNull(git);
  if (gitInfo?.isSymbolicLink()) {
    throw new Error(
      `protected workspace path ${git} is a symlink; replace it with a regular file or directory`
    );
  }
  if (gitInfo !== null && !gitInfo.isDirectory()) {
    const gitReal = realpathOrNull(git) ?? git;
    const pointer = gitPointerTarget(git);
    if (pointer !== undefined) {
      assertPointerSafe(
        pointer,
        workspace,
        gitReal,
        path.join(gitReal, "modules"),
        path.join(gitReal, "worktrees"),
        writablePaths
      );
    }
    addProtected(result, workspace, git);
  }
  return [...result].sort();
}
