/**
 * WSL detection. OpenCode on Windows is not supported by this plugin, but
 * OpenCode inside WSL2 is a normal Linux host and works unchanged. The
 * diagnostic distinguishes the two so the startup log and `doctor` can point
 * at the right setup.
 */

import fs from "node:fs";

function read(file: string): string {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

/** Return the WSL distro name (or "wsl2") when running inside WSL. */
export function wslName(
  env: NodeJS.ProcessEnv = process.env,
  osrelease: string = read("/proc/sys/kernel/osrelease"),
  version: string = read("/proc/version")
): string | undefined {
  if (typeof env.WSL_DISTRO_NAME === "string" && env.WSL_DISTRO_NAME !== "") {
    return env.WSL_DISTRO_NAME;
  }
  if (typeof env.WSL_INTEROP === "string" && env.WSL_INTEROP !== "") return "wsl2";
  return /microsoft|wsl/i.test(osrelease) || /microsoft|wsl/i.test(version) ? "wsl2" : undefined;
}
