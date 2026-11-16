import fs from "node:fs";
import path from "node:path";

/** Shared path containment helper (canonical, absolute paths). */
export function contains(root: string, target: string): boolean {
  return (
    target === root || target.startsWith(root.endsWith(path.sep) ? root : `${root}${path.sep}`)
  );
}

/**
 * Resolve a path the way the kernel does: walk components in order, expand a
 * symlink when it is encountered, then apply later `..` segments to the
 * resolved location. `path.resolve` alone is wrong because it collapses `..`
 * before following a symlink.
 */
export function resolvePathKernel(input: string): string {
  const absolute = path.isAbsolute(input) ? input : path.resolve(input);
  const parts = absolute.split(path.sep).filter(Boolean);
  const resolved: string[] = [];
  let links = 0;
  let index = 0;

  while (index < parts.length) {
    const part = parts[index++];
    if (part === ".") continue;
    if (part === "..") {
      resolved.pop();
      continue;
    }
    resolved.push(part);
    const current = path.sep + resolved.join(path.sep);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(current);
    } catch {
      continue;
    }
    if (!stat.isSymbolicLink()) continue;
    if (++links > 40) throw new Error("too many symbolic links");

    const link = fs.readlinkSync(current);
    resolved.pop();
    const linkParts = link.split(path.sep).filter((item) => item !== "");
    if (path.isAbsolute(link)) resolved.length = 0;
    parts.splice(index, 0, ...linkParts);
  }
  return path.sep + resolved.join(path.sep);
}

/** Canonical absolute target; non-existent suffixes use the nearest existing ancestor. */
export function canonicalTarget(input: string): string {
  const expanded = resolvePathKernel(input);
  try {
    return fs.realpathSync.native(expanded);
  } catch {
    // Fall through to the nearest existing ancestor.
  }

  let current = expanded;
  const suffix: string[] = [];
  while (true) {
    const parent = path.dirname(current);
    if (parent === current) return expanded;
    suffix.push(path.basename(current));
    try {
      return path.join(fs.realpathSync.native(parent), ...suffix.reverse());
    } catch {
      current = parent;
    }
  }
}
