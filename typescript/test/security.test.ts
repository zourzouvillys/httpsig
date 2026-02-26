import { describe, it, expect } from "vitest";
import * as crypto from "node:crypto";
import {
  signMessage,
  verifyMessage,
  signatureInputHeader,
  signatureHeader,
  component,
  newHMACSHA256Key,
  InvalidSignatureError,
} from "../src/index.js";
import type {
  HttpMessage,
  SignatureParameters,
  VerifyingKey,
  Algorithm,
  VerifyOptions,
} from "../src/index.js";

/**
 * Build a minimal GET request HttpMessage with optional extra headers.
 */
function makeRequest(
  headers: Record<string, string | string[]> = {},
): HttpMessage {
  const headerMap = new Map<string, string[]>();
  for (const [name, value] of Object.entries(headers)) {
    headerMap.set(name.toLowerCase(), Array.isArray(value) ? value : [value]);
  }
  return {
    isRequest: true,
    method: "GET",
    url: new URL("https://example.com/resource"),
    headerValues: (name: string) => headerMap.get(name.toLowerCase()) ?? [],
  };
}

/**
 * Sign a request with the given key and params, then return a new HttpMessage
 * that includes the Signature-Input and Signature headers (as verifyMessage expects).
 *
 * Optionally allows mutating the Signature-Input header before returning,
 * which is how we test algorithm mismatch attacks.
 */
async function signAndBuildVerifiableMessage(
  key: ReturnType<typeof newHMACSHA256Key>,
  params: SignatureParameters,
  mutateSignatureInput?: (raw: string) => string,
): Promise<HttpMessage> {
  const baseMsg = makeRequest();
  const result = await signMessage(baseMsg, "sig1", params, key);

  let sigInputValue = signatureInputHeader(result);
  const sigValue = signatureHeader(result);

  if (mutateSignatureInput) {
    sigInputValue = mutateSignatureInput(sigInputValue);
  }

  const headerMap = new Map<string, string[]>();
  headerMap.set("signature-input", [sigInputValue]);
  headerMap.set("signature", [sigValue]);

  return {
    isRequest: true,
    method: "GET",
    url: new URL("https://example.com/resource"),
    headerValues: (name: string) => headerMap.get(name.toLowerCase()) ?? [],
  };
}

// Shared HMAC key for all tests
const secret = crypto.randomBytes(32);
const hmacKey = newHMACSHA256Key("test-key", new Uint8Array(secret));

const hmacProvider = async (
  keyId: string,
  _alg: Algorithm | undefined,
): Promise<VerifyingKey> => {
  if (keyId === "test-key") return hmacKey;
  throw new Error("key not found");
};

describe("future-dated signature rejection", () => {
  const futureCreated = Math.floor(Date.now() / 1000) + 3600; // 1 hour in the future

  const params: SignatureParameters = {
    components: [component("@method")],
    keyId: "test-key",
    created: futureCreated,
  };

  it("rejects when created is beyond maxClockSkewMs", async () => {
    const msg = await signAndBuildVerifiableMessage(hmacKey, params);

    await expect(
      verifyMessage(msg, hmacProvider, { maxClockSkewMs: 30_000 }),
    ).rejects.toThrow(InvalidSignatureError);
  });

  it("accepts when created is within maxClockSkewMs", async () => {
    const msg = await signAndBuildVerifiableMessage(hmacKey, params);

    const result = await verifyMessage(msg, hmacProvider, {
      maxClockSkewMs: 7_200_000,
    });
    expect(result.keyId).toBe("test-key");
  });

  it("accepts with no maxClockSkewMs (opt-in behavior)", async () => {
    const msg = await signAndBuildVerifiableMessage(hmacKey, params);

    const result = await verifyMessage(msg, hmacProvider);
    expect(result.keyId).toBe("test-key");
  });
});

describe("algorithm mismatch rejection", () => {
  const params: SignatureParameters = {
    components: [component("@method")],
    keyId: "test-key",
    algorithm: "hmac-sha256",
    created: Math.floor(Date.now() / 1000),
  };

  it("rejects when header alg does not match key algorithm", async () => {
    // Sign normally with alg="hmac-sha256", then tamper the Signature-Input
    // to claim alg="ed25519". The key provider still returns the HMAC key,
    // so the alg in the header won't match key.algorithm.
    const msg = await signAndBuildVerifiableMessage(hmacKey, params, (raw) =>
      raw.replace('alg="hmac-sha256"', 'alg="ed25519"'),
    );

    await expect(verifyMessage(msg, hmacProvider)).rejects.toThrow(
      InvalidSignatureError,
    );
  });

  it("accepts when no alg param in signature (alg is optional)", async () => {
    const noAlgParams: SignatureParameters = {
      components: [component("@method")],
      keyId: "test-key",
      // no algorithm field
      created: Math.floor(Date.now() / 1000),
    };

    const msg = await signAndBuildVerifiableMessage(hmacKey, noAlgParams);
    const result = await verifyMessage(msg, hmacProvider);
    expect(result.keyId).toBe("test-key");
  });
});

describe("VerifyResult returns key algorithm, not untrusted header value", () => {
  it("result.algorithm comes from the key, not the header", async () => {
    const params: SignatureParameters = {
      components: [component("@method")],
      keyId: "test-key",
      algorithm: "hmac-sha256",
      created: Math.floor(Date.now() / 1000),
    };

    const msg = await signAndBuildVerifiableMessage(hmacKey, params);
    const result = await verifyMessage(msg, hmacProvider);

    // The algorithm in the result must come from the key object, not from
    // whatever an attacker might have placed in the Signature-Input header.
    expect(result.algorithm).toBe("hmac-sha256");
  });
});
