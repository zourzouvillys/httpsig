import { describe, it, expect } from "vitest";
import * as crypto from "node:crypto";
import {
  buildAcceptSignature,
  parseAcceptSignature,
  toSignatureParameters,
  component,
  queryParam,
  signMessage,
  verifyMessage,
  signatureInputHeader,
  signatureHeader,
  newHMACSHA256Key,
  InvalidSignatureError,
} from "../src/index.js";
import type {
  HttpMessage,
  SignatureParameters,
  SignatureRequirements,
  VerifyingKey,
  Algorithm,
} from "../src/index.js";

describe("Accept-Signature", () => {
  describe("buildAcceptSignature", () => {
    it("builds a single entry with components and params", () => {
      const result = buildAcceptSignature({
        sig1: {
          components: [component("@method"), component("@authority"), component("content-digest")],
          keyId: "server-key-1",
          algorithm: "ecdsa-p256-sha256",
          requireCreated: true,
          requireExpires: true,
          tag: "myapp",
        },
      });
      expect(result).toBe(
        'sig1=("@method" "@authority" "content-digest");keyid="server-key-1";alg="ecdsa-p256-sha256";created;expires;tag="myapp"',
      );
    });

    it("builds empty components", () => {
      const result = buildAcceptSignature({
        sig1: { components: [] },
      });
      expect(result).toBe("sig1=()");
    });

    it("builds multiple entries", () => {
      const result = buildAcceptSignature({
        sig1: {
          components: [component("@method")],
          keyId: "key-1",
        },
        sig2: {
          components: [component("@authority")],
          algorithm: "hmac-sha256",
        },
      });
      expect(result).toBe(
        'sig1=("@method");keyid="key-1", sig2=("@authority");alg="hmac-sha256"',
      );
    });

    it("builds components with params", () => {
      const result = buildAcceptSignature({
        sig1: {
          components: [component("@authority"), queryParam("foo")],
        },
      });
      expect(result).toBe('sig1=("@authority" "@query-param";name="foo")');
    });
  });

  describe("parseAcceptSignature", () => {
    it("parses an RFC-style example", () => {
      const input =
        'sig1=("@method" "@authority" "content-digest");keyid="server-key-1";alg="ecdsa-p256-sha256";created;expires;tag="myapp"';
      const result = parseAcceptSignature(input);

      expect(Object.keys(result)).toEqual(["sig1"]);
      const sig1 = result["sig1"];
      expect(sig1.components).toHaveLength(3);
      expect(sig1.components[0].name).toBe("@method");
      expect(sig1.components[1].name).toBe("@authority");
      expect(sig1.components[2].name).toBe("content-digest");
      expect(sig1.keyId).toBe("server-key-1");
      expect(sig1.algorithm).toBe("ecdsa-p256-sha256");
      expect(sig1.requireCreated).toBe(true);
      expect(sig1.requireExpires).toBe(true);
      expect(sig1.tag).toBe("myapp");
    });

    it("parses multiple entries", () => {
      const input =
        'sig1=("@method");keyid="key-1", sig2=("@authority");alg="hmac-sha256"';
      const result = parseAcceptSignature(input);

      expect(Object.keys(result)).toEqual(["sig1", "sig2"]);
      expect(result["sig1"].components[0].name).toBe("@method");
      expect(result["sig1"].keyId).toBe("key-1");
      expect(result["sig2"].components[0].name).toBe("@authority");
      expect(result["sig2"].algorithm).toBe("hmac-sha256");
    });

    it("parses empty components", () => {
      const result = parseAcceptSignature("sig1=()");
      expect(result["sig1"].components).toEqual([]);
    });

    it("parses component with params", () => {
      const input = 'sig1=("@authority" "@query-param";name="foo")';
      const result = parseAcceptSignature(input);
      const comps = result["sig1"].components;
      expect(comps).toHaveLength(2);
      expect(comps[0].name).toBe("@authority");
      expect(comps[1].name).toBe("@query-param");
      expect(comps[1].params?.values["name"]).toBe("foo");
    });

    it("leaves optional fields undefined when absent", () => {
      const result = parseAcceptSignature('sig1=("@method")');
      const sig1 = result["sig1"];
      expect(sig1.keyId).toBeUndefined();
      expect(sig1.algorithm).toBeUndefined();
      expect(sig1.tag).toBeUndefined();
      expect(sig1.requireCreated).toBeUndefined();
      expect(sig1.requireExpires).toBeUndefined();
    });
  });

  describe("round-trip", () => {
    it("build then parse preserves requirements", () => {
      const original: Record<string, SignatureRequirements> = {
        sig1: {
          components: [component("@method"), component("@authority")],
          keyId: "my-key",
          algorithm: "ecdsa-p256-sha256",
          requireCreated: true,
          requireExpires: true,
          tag: "app1",
        },
      };

      const header = buildAcceptSignature(original);
      const parsed = parseAcceptSignature(header);

      expect(parsed["sig1"].components).toHaveLength(2);
      expect(parsed["sig1"].components[0].name).toBe("@method");
      expect(parsed["sig1"].components[1].name).toBe("@authority");
      expect(parsed["sig1"].keyId).toBe("my-key");
      expect(parsed["sig1"].algorithm).toBe("ecdsa-p256-sha256");
      expect(parsed["sig1"].requireCreated).toBe(true);
      expect(parsed["sig1"].requireExpires).toBe(true);
      expect(parsed["sig1"].tag).toBe("app1");
    });

    it("round-trips multiple entries with component params", () => {
      const original: Record<string, SignatureRequirements> = {
        sig1: {
          components: [queryParam("bar")],
          keyId: "k1",
        },
        sig2: {
          components: [],
          tag: "debug",
        },
      };

      const header = buildAcceptSignature(original);
      const parsed = parseAcceptSignature(header);

      expect(parsed["sig1"].components).toHaveLength(1);
      expect(parsed["sig1"].components[0].name).toBe("@query-param");
      expect(parsed["sig1"].components[0].params?.values["name"]).toBe("bar");
      expect(parsed["sig1"].keyId).toBe("k1");
      expect(parsed["sig2"].components).toEqual([]);
      expect(parsed["sig2"].tag).toBe("debug");
    });
  });

  describe("toSignatureParameters", () => {
    it("converts requirements to SignatureParameters", () => {
      const req: SignatureRequirements = {
        components: [component("@method"), component("@authority")],
        keyId: "my-key",
        algorithm: "hmac-sha256",
        tag: "myapp",
      };

      const params = toSignatureParameters(req, {
        created: 1700000000,
        expires: 1700003600,
        nonce: "abc123",
      });

      expect(params.components).toHaveLength(2);
      expect(params.components[0].name).toBe("@method");
      expect(params.keyId).toBe("my-key");
      expect(params.algorithm).toBe("hmac-sha256");
      expect(params.tag).toBe("myapp");
      expect(params.created).toBe(1700000000);
      expect(params.expires).toBe(1700003600);
      expect(params.nonce).toBe("abc123");
    });

    it("uses defaults when opts omitted", () => {
      const req: SignatureRequirements = {
        components: [component("@method")],
      };

      const params = toSignatureParameters(req);

      expect(params.keyId).toBe("");
      expect(params.algorithm).toBeUndefined();
      expect(params.created).toBeUndefined();
      expect(params.expires).toBeUndefined();
      expect(params.nonce).toBeUndefined();
    });
  });

  describe("verifier integration with requirements", () => {
    const secret = crypto.randomBytes(32);
    const hmacKey = newHMACSHA256Key("test-key", new Uint8Array(secret));

    const hmacProvider = async (
      keyId: string,
      _alg: Algorithm | undefined,
    ): Promise<VerifyingKey> => {
      if (keyId === "test-key") return hmacKey;
      throw new Error(`unknown key: ${keyId}`);
    };

    function makeRequest(
      headers: Record<string, string | string[]> = {},
    ): HttpMessage {
      const headerMap = new Map<string, string[]>();
      for (const [name, value] of Object.entries(headers)) {
        headerMap.set(
          name.toLowerCase(),
          Array.isArray(value) ? value : [value],
        );
      }
      return {
        isRequest: true,
        method: "GET",
        url: new URL("https://example.com/resource"),
        headerValues: (name: string) =>
          headerMap.get(name.toLowerCase()) ?? [],
      };
    }

    async function signAndBuildMessage(
      params: SignatureParameters,
    ): Promise<HttpMessage> {
      const baseMsg = makeRequest();
      const result = await signMessage(baseMsg, "sig1", params, hmacKey);

      const sigInputValue = signatureInputHeader(result);
      const sigValue = signatureHeader(result);

      const headerMap = new Map<string, string[]>();
      headerMap.set("signature-input", [sigInputValue]);
      headerMap.set("signature", [sigValue]);

      return {
        isRequest: true,
        method: "GET",
        url: new URL("https://example.com/resource"),
        headerValues: (name: string) =>
          headerMap.get(name.toLowerCase()) ?? [],
      };
    }

    it("accepts a signature that matches requirements", async () => {
      const params: SignatureParameters = {
        components: [component("@method"), component("@authority")],
        keyId: "test-key",
        tag: "myapp",
        created: Math.floor(Date.now() / 1000),
      };

      const msg = await signAndBuildMessage(params);
      const result = await verifyMessage(msg, hmacProvider, {
        requirements: {
          components: [component("@method")],
          keyId: "test-key",
          tag: "myapp",
        },
        rejectExpired: false,
      });

      expect(result.label).toBe("sig1");
      expect(result.keyId).toBe("test-key");
    });

    it("rejects signature with wrong keyId", async () => {
      const params: SignatureParameters = {
        components: [component("@method")],
        keyId: "test-key",
        created: Math.floor(Date.now() / 1000),
      };

      const msg = await signAndBuildMessage(params);
      await expect(
        verifyMessage(msg, hmacProvider, {
          requirements: {
            components: [],
            keyId: "other-key",
          },
          rejectExpired: false,
        }),
      ).rejects.toThrow(InvalidSignatureError);
    });

    it("rejects signature with wrong algorithm", async () => {
      const params: SignatureParameters = {
        components: [component("@method")],
        keyId: "test-key",
        algorithm: "hmac-sha256",
        created: Math.floor(Date.now() / 1000),
      };

      const msg = await signAndBuildMessage(params);
      await expect(
        verifyMessage(msg, hmacProvider, {
          requirements: {
            components: [],
            algorithm: "ecdsa-p256-sha256",
          },
          rejectExpired: false,
        }),
      ).rejects.toThrow(InvalidSignatureError);
    });

    it("rejects signature with wrong tag", async () => {
      const params: SignatureParameters = {
        components: [component("@method")],
        keyId: "test-key",
        tag: "myapp",
        created: Math.floor(Date.now() / 1000),
      };

      const msg = await signAndBuildMessage(params);
      await expect(
        verifyMessage(msg, hmacProvider, {
          requirements: {
            components: [],
            tag: "other-tag",
          },
          rejectExpired: false,
        }),
      ).rejects.toThrow(InvalidSignatureError);
    });

    it("rejects when required components are missing", async () => {
      const params: SignatureParameters = {
        components: [component("@method")],
        keyId: "test-key",
        created: Math.floor(Date.now() / 1000),
      };

      const msg = await signAndBuildMessage(params);
      await expect(
        verifyMessage(msg, hmacProvider, {
          requirements: {
            components: [component("@method"), component("@authority")],
          },
          rejectExpired: false,
        }),
      ).rejects.toThrow(InvalidSignatureError);
    });

    it("accepts when requirements have no filtering constraints", async () => {
      const params: SignatureParameters = {
        components: [component("@method")],
        keyId: "test-key",
        created: Math.floor(Date.now() / 1000),
      };

      const msg = await signAndBuildMessage(params);
      const result = await verifyMessage(msg, hmacProvider, {
        requirements: {
          components: [],
        },
        rejectExpired: false,
      });

      expect(result.label).toBe("sig1");
    });
  });
});
