import { describe, it, expect } from "vitest";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  newSigningKey,
  newVerifyingKey,
  newKeyPair,
  newHMACKeyPair,
  newWebCryptoSigningKey,
  newWebCryptoVerifyingKey,
} from "../src/keys.js";

const KEYS_DIR = path.resolve(__dirname, "..", "..", "testdata", "keys");

function loadPrivateKey(file: string): crypto.KeyObject {
  const pem = fs.readFileSync(path.join(KEYS_DIR, file), "utf-8");
  return crypto.createPrivateKey(pem);
}

function loadPublicKey(file: string): crypto.KeyObject {
  const pem = fs.readFileSync(path.join(KEYS_DIR, file), "utf-8");
  return crypto.createPublicKey(pem);
}

describe("auto-detection", () => {
  it("detects RSA-PSS from private key", () => {
    const key = loadPrivateKey("rsa-pss.priv.pem");
    const sk = newSigningKey("rsa-test", key);
    expect(sk.algorithm).toBe("rsa-pss-sha512");
    expect(sk.keyId).toBe("rsa-test");
  });

  it("detects ECDSA P-256 from private key", () => {
    const key = loadPrivateKey("ecc-p256.priv.pem");
    const sk = newSigningKey("ec-test", key);
    expect(sk.algorithm).toBe("ecdsa-p256-sha256");
  });

  it("detects Ed25519 from private key", () => {
    const key = loadPrivateKey("ed25519.priv.pem");
    const sk = newSigningKey("ed-test", key);
    expect(sk.algorithm).toBe("ed25519");
  });

  it("detects RSA-PSS from public key", () => {
    const key = loadPublicKey("rsa-pss.pub.pem");
    const vk = newVerifyingKey("rsa-test", key);
    expect(vk.algorithm).toBe("rsa-pss-sha512");
  });

  it("detects ECDSA P-256 from public key", () => {
    const key = loadPublicKey("ecc-p256.pub.pem");
    const vk = newVerifyingKey("ec-test", key);
    expect(vk.algorithm).toBe("ecdsa-p256-sha256");
  });

  it("detects Ed25519 from public key", () => {
    const key = loadPublicKey("ed25519.pub.pem");
    const vk = newVerifyingKey("ed-test", key);
    expect(vk.algorithm).toBe("ed25519");
  });
});

describe("KeyPair", () => {
  it("creates RSA-PSS key pair with sign/verify round-trip", async () => {
    const key = loadPrivateKey("rsa-pss.priv.pem");
    const kp = newKeyPair("rsa-kp", key);
    expect(kp.keyId).toBe("rsa-kp");
    expect(kp.algorithm).toBe("rsa-pss-sha512");

    const data = new TextEncoder().encode("test data");
    const sig = await kp.signingKey.sign(data);
    expect(await kp.verifyingKey.verify(data, sig)).toBe(true);
  });

  it("creates ECDSA P-256 key pair with sign/verify round-trip", async () => {
    const key = loadPrivateKey("ecc-p256.priv.pem");
    const kp = newKeyPair("ec-kp", key);
    expect(kp.algorithm).toBe("ecdsa-p256-sha256");

    const data = new TextEncoder().encode("test data");
    const sig = await kp.signingKey.sign(data);
    expect(await kp.verifyingKey.verify(data, sig)).toBe(true);
  });

  it("creates Ed25519 key pair with sign/verify round-trip", async () => {
    const key = loadPrivateKey("ed25519.priv.pem");
    const kp = newKeyPair("ed-kp", key);
    expect(kp.algorithm).toBe("ed25519");

    const data = new TextEncoder().encode("test data");
    const sig = await kp.signingKey.sign(data);
    expect(await kp.verifyingKey.verify(data, sig)).toBe(true);
  });

  it("creates HMAC key pair with sign/verify round-trip", async () => {
    const secret = new TextEncoder().encode("super-secret-key-at-least-32-bytes!!");
    const kp = newHMACKeyPair("hmac-kp", secret);
    expect(kp.algorithm).toBe("hmac-sha256");

    const data = new TextEncoder().encode("test data");
    const sig = await kp.signingKey.sign(data);
    expect(await kp.verifyingKey.verify(data, sig)).toBe(true);
  });
});

describe("Web Crypto", () => {
  it("creates Ed25519 signing key with round-trip", async () => {
    const { publicKey, privateKey } = await globalThis.crypto.subtle.generateKey(
      "Ed25519",
      true,
      ["sign", "verify"],
    ) as CryptoKeyPair;
    const sk = newWebCryptoSigningKey("wc-ed", privateKey, "ed25519");
    const vk = newWebCryptoVerifyingKey("wc-ed", publicKey, "ed25519");

    const data = new TextEncoder().encode("web crypto test");
    const sig = await sk.sign(data);
    expect(await vk.verify(data, sig)).toBe(true);
  });

  it("creates ECDSA P-256 signing key with round-trip", async () => {
    const { publicKey, privateKey } = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"],
    ) as CryptoKeyPair;
    const sk = newWebCryptoSigningKey("wc-ec", privateKey, "ecdsa-p256-sha256");
    const vk = newWebCryptoVerifyingKey("wc-ec", publicKey, "ecdsa-p256-sha256");

    const data = new TextEncoder().encode("web crypto ecdsa test");
    const sig = await sk.sign(data);
    expect(await vk.verify(data, sig)).toBe(true);
  });

  it("creates HMAC signing key with round-trip", async () => {
    const key = await globalThis.crypto.subtle.generateKey(
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"],
    ) as CryptoKey;
    const sk = newWebCryptoSigningKey("wc-hmac", key, "hmac-sha256");
    const vk = newWebCryptoVerifyingKey("wc-hmac", key, "hmac-sha256");

    const data = new TextEncoder().encode("web crypto hmac test");
    const sig = await sk.sign(data);
    expect(await vk.verify(data, sig)).toBe(true);
  });
});
