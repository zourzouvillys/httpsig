import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";
import {
  buildSignatureBase,
  signMessage,
  component,
  componentWithParams,
  newSFVParams,
  sfvParamsSet,
  uint8ToBase64,
  base64ToUint8,
  newRSAPSSSigningKey,
  newRSAPSSVerifyingKey,
  newECDSAP256SigningKey,
  newECDSAP256VerifyingKey,
  newEd25519SigningKey,
  newEd25519VerifyingKey,
  newHMACSHA256Key,
} from "../src/index.js";
import type {
  HttpMessage,
  SignatureParameters,
  SigningKey,
  VerifyingKey,
  Algorithm,
  ComponentIdentifier,
} from "../src/index.js";

// Vector file JSON structure
interface VectorFile {
  id: string;
  description: string;
  message: VectorMessage;
  requestMessage?: VectorMessage;
  signingParams: VectorSigParams;
  expectedBase: string;
  expectedSignatureInput: string;
  expectedSignature?: string;
  verifyOnlySignature?: string;
  deterministic: boolean;
  keyFile?: string;
  pubKeyFile?: string;
}

interface VectorMessage {
  type: string;
  method?: string;
  url?: string;
  statusCode?: number;
  headers: [string, string][];
  body?: string;
}

interface VectorSigParams {
  label: string;
  components: Array<string | { name: string; params?: Record<string, string> }>;
  keyId: string;
  algorithm?: string;
  created?: number;
  expires?: number;
  nonce?: string;
  tag?: string;
}

const TESTDATA_DIR = path.join(__dirname, "..", "..", "testdata");

function loadVectors(): VectorFile[] {
  const vectorDir = path.join(TESTDATA_DIR, "vectors");
  const files = fs.readdirSync(vectorDir).filter((f) => f.endsWith(".json"));
  return files.map((f) => {
    const data = fs.readFileSync(path.join(vectorDir, f), "utf8");
    return JSON.parse(data) as VectorFile;
  });
}

function buildMessage(vm: VectorMessage): HttpMessage {
  const headerMap = new Map<string, string[]>();
  for (const [name, value] of vm.headers) {
    const key = name.toLowerCase();
    const existing = headerMap.get(key) ?? [];
    existing.push(value);
    headerMap.set(key, existing);
  }

  if (vm.type === "request") {
    return {
      isRequest: true,
      method: vm.method,
      url: new URL(vm.url!),
      headerValues: (name: string) => headerMap.get(name.toLowerCase()) ?? [],
    };
  }

  return {
    isRequest: false,
    statusCode: vm.statusCode,
    headerValues: (name: string) => headerMap.get(name.toLowerCase()) ?? [],
  };
}

function parseComponents(
  raw: VectorSigParams["components"],
): ComponentIdentifier[] {
  return raw.map((item) => {
    if (typeof item === "string") {
      return component(item);
    }
    let params = newSFVParams();
    if (item.params) {
      for (const [k, v] of Object.entries(item.params)) {
        params = sfvParamsSet(params, k, v);
      }
    }
    return componentWithParams(item.name, params);
  });
}

function buildSigParams(vsp: VectorSigParams): SignatureParameters {
  const components = parseComponents(vsp.components);
  const sp: SignatureParameters = {
    components,
    keyId: vsp.keyId,
    created: vsp.created,
    expires: vsp.expires,
  };
  // Don't set algorithm in params (matches RFC test vectors, which omit "alg")
  if (vsp.nonce) sp.nonce = vsp.nonce;
  if (vsp.tag) sp.tag = vsp.tag;
  return sp;
}

function loadSigningKey(v: VectorFile): SigningKey {
  const alg = v.signingParams.algorithm as Algorithm;
  const keyId = v.signingParams.keyId;
  const keyPath = path.join(TESTDATA_DIR, v.keyFile!);
  const keyData = fs.readFileSync(keyPath);

  switch (alg) {
    case "hmac-sha256": {
      const secret = Buffer.from(keyData.toString().trim(), "base64");
      return newHMACSHA256Key(keyId, new Uint8Array(secret));
    }
    case "ed25519": {
      const key = crypto.createPrivateKey(keyData);
      return newEd25519SigningKey(keyId, key);
    }
    case "rsa-pss-sha512": {
      const key = crypto.createPrivateKey(keyData);
      return newRSAPSSSigningKey(keyId, key);
    }
    case "ecdsa-p256-sha256": {
      const key = crypto.createPrivateKey(keyData);
      return newECDSAP256SigningKey(keyId, key);
    }
    default:
      throw new Error(`unknown algorithm: ${alg}`);
  }
}

function loadVerifyingKey(v: VectorFile): VerifyingKey {
  const alg = v.signingParams.algorithm as Algorithm;
  const keyId = v.signingParams.keyId;

  if (alg === "hmac-sha256") {
    const keyPath = path.join(TESTDATA_DIR, v.keyFile!);
    const keyData = fs.readFileSync(keyPath);
    const secret = Buffer.from(keyData.toString().trim(), "base64");
    return newHMACSHA256Key(keyId, new Uint8Array(secret));
  }

  const pubKeyPath = path.join(TESTDATA_DIR, v.pubKeyFile!);
  const pubKeyData = fs.readFileSync(pubKeyPath);
  const key = crypto.createPublicKey(pubKeyData);

  switch (alg) {
    case "rsa-pss-sha512":
      return newRSAPSSVerifyingKey(keyId, key);
    case "ecdsa-p256-sha256":
      return newECDSAP256VerifyingKey(keyId, key);
    case "ed25519":
      return newEd25519VerifyingKey(keyId, key);
    default:
      throw new Error(`unknown algorithm: ${alg}`);
  }
}

describe("RFC 9421 Test Vectors", () => {
  const vectors = loadVectors();

  describe("signature base", () => {
    for (const v of vectors) {
      it(`${v.id} - ${v.description}`, () => {
        const msg = buildMessage(v.message);
        const params = buildSigParams(v.signingParams);
        const reqMsg = v.requestMessage
          ? buildMessage(v.requestMessage)
          : undefined;

        const [base, sigInput] = buildSignatureBase(msg, params, reqMsg);
        const baseStr = new TextDecoder().decode(base);

        expect(baseStr).toBe(v.expectedBase);

        // Strip label prefix from expected
        const labelPrefix = v.signingParams.label + "=";
        let expectedInput = v.expectedSignatureInput;
        if (expectedInput.startsWith(labelPrefix)) {
          expectedInput = expectedInput.slice(labelPrefix.length);
        }
        expect(sigInput).toBe(expectedInput);
      });
    }
  });

  describe("deterministic signatures", () => {
    for (const v of vectors) {
      if (!v.deterministic || !v.expectedSignature) continue;

      it(`${v.id} - ${v.description}`, async () => {
        const msg = buildMessage(v.message);
        const params = buildSigParams(v.signingParams);
        const key = loadSigningKey(v);
        const reqMsg = v.requestMessage
          ? buildMessage(v.requestMessage)
          : undefined;

        const result = await signMessage(
          msg,
          v.signingParams.label,
          params,
          key,
          reqMsg,
        );

        expect(uint8ToBase64(result.signature)).toBe(v.expectedSignature);
      });
    }
  });

  describe("verify signatures", () => {
    for (const v of vectors) {
      const sigB64 = v.expectedSignature || v.verifyOnlySignature;
      if (!sigB64) continue;

      it(`${v.id} - ${v.description}`, async () => {
        const sigBytes = base64ToUint8(sigB64);
        const verifyKey = loadVerifyingKey(v);
        const baseBytes = new TextEncoder().encode(v.expectedBase);

        const valid = await verifyKey.verify(baseBytes, sigBytes);
        expect(valid).toBe(true);
      });
    }
  });

  describe("sign and verify round-trip", () => {
    for (const v of vectors) {
      it(`${v.id} - ${v.description}`, async () => {
        const msg = buildMessage(v.message);
        const params = buildSigParams(v.signingParams);
        const sigKey = loadSigningKey(v);
        const verifyKey = loadVerifyingKey(v);
        const reqMsg = v.requestMessage
          ? buildMessage(v.requestMessage)
          : undefined;

        const result = await signMessage(
          msg,
          v.signingParams.label,
          params,
          sigKey,
          reqMsg,
        );

        const baseBytes = new TextEncoder().encode(v.expectedBase);
        const valid = await verifyKey.verify(baseBytes, result.signature);
        expect(valid).toBe(true);
      });
    }
  });
});
