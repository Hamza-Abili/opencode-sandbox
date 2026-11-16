import { describe, expect, test } from "bun:test";
import { wslName } from "../src/wsl.ts";

describe("wslName", () => {
  test("reads WSL_DISTRO_NAME first", () => {
    expect(wslName({ WSL_DISTRO_NAME: "Ubuntu-24.04" }, "", "")).toBe("Ubuntu-24.04");
  });

  test("detects WSL from the kernel release or version", () => {
    expect(wslName({}, "5.15.153.1-microsoft-standard-WSL2", "")).toBe("wsl2");
    expect(wslName({}, "", "Linux version 6.6.87.2-microsoft-standard-WSL2")).toBe("wsl2");
    expect(wslName({ WSL_INTEROP: "/run/WSL/1_interop" }, "", "")).toBe("wsl2");
  });

  test("returns undefined on a normal Linux host", () => {
    expect(wslName({}, "6.8.0-45-generic", "Linux version 6.8.0-45-generic")).toBeUndefined();
  });
});
