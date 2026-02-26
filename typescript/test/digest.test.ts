import { describe, it, expect } from "vitest";
import { contentDigest, verifyContentDigest } from "../src/index.js";

const body = new TextEncoder().encode('{"hello": "world"}');

describe("Content-Digest", () => {
  it("computes sha-256", () => {
    const result = contentDigest(body, "sha-256");
    expect(result).toMatch(/^sha-256=:.+:$/);
  });

  it("computes sha-512", () => {
    const result = contentDigest(body, "sha-512");
    expect(result).toMatch(/^sha-512=:.+:$/);
  });

  it("verifies correct digest", () => {
    const header = contentDigest(body, "sha-256");
    expect(verifyContentDigest(body, header)).toBe(true);
  });

  it("rejects incorrect digest", () => {
    const header = contentDigest(body, "sha-256");
    const wrongBody = new TextEncoder().encode("wrong");
    expect(verifyContentDigest(wrongBody, header)).toBe(false);
  });

  it("verifies the RFC test vector sha-512 digest", () => {
    const header =
      "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";
    expect(verifyContentDigest(body, header)).toBe(true);
  });
});
