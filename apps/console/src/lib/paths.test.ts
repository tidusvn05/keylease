import { describe, expect, it } from "vitest";
import { apiPrefix, consoleBase, loginToken } from "@/lib/paths";

describe("console paths", () => {
  it("finds the mount point with or without a proxy prefix", () => {
    expect(consoleBase("/console/devices")).toBe("/console");
    expect(consoleBase("/api/console/")).toBe("/api/console");
    expect(apiPrefix("/api/console/passkeys")).toBe("/api");
    expect(apiPrefix("/console/")).toBe("");
    expect(consoleBase("/devices")).toBe("");
    expect(apiPrefix("/")).toBe("");
  });

  it("reads a device sign-in token only from a well-formed fragment", () => {
    expect(loginToken("#login=abcdefghijklmnop_-123")).toBe("abcdefghijklmnop_-123");
    expect(loginToken("#login=short")).toBeNull();
    expect(loginToken("#login=bad token with spaces")).toBeNull();
    expect(loginToken("")).toBeNull();
  });
});
