import * as crypto from "node:crypto";
import type { Algorithm } from "./types.js";
import { UnknownAlgorithmError, InvalidKeyError } from "./errors.js";

/** Sign data with the given algorithm and key material. */
export async function algorithmSign(
  alg: Algorithm,
  key: crypto.KeyObject,
  data: Uint8Array,
): Promise<Uint8Array> {
  switch (alg) {
    case "rsa-pss-sha256":
      return signRSAPSS(key, data, "sha256", 32);
    case "rsa-pss-sha384":
      return signRSAPSS(key, data, "sha384", 48);
    case "rsa-pss-sha512":
      return signRSAPSS(key, data, "sha512", 64);
    case "rsa-v1_5-sha256":
      return signRSAv15(key, data);
    case "ecdsa-p256-sha256":
      return signECDSA(key, data, "sha256", 64);
    case "ecdsa-p384-sha384":
      return signECDSA(key, data, "sha384", 96);
    case "ecdsa-p521-sha512":
      return signECDSA(key, data, "sha512", 132);
    case "ed25519":
      return signEd25519(key, data);
    default:
      throw new UnknownAlgorithmError(alg);
  }
}

/** Verify data with the given algorithm and key material. */
export async function algorithmVerify(
  alg: Algorithm,
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  switch (alg) {
    case "rsa-pss-sha256":
      return verifyRSAPSS(key, data, signature, "sha256", 32);
    case "rsa-pss-sha384":
      return verifyRSAPSS(key, data, signature, "sha384", 48);
    case "rsa-pss-sha512":
      return verifyRSAPSS(key, data, signature, "sha512", 64);
    case "rsa-v1_5-sha256":
      return verifyRSAv15(key, data, signature);
    case "ecdsa-p256-sha256":
      return verifyECDSA(key, data, signature, "sha256", 64);
    case "ecdsa-p384-sha384":
      return verifyECDSA(key, data, signature, "sha384", 96);
    case "ecdsa-p521-sha512":
      return verifyECDSA(key, data, signature, "sha512", 132);
    case "ed25519":
      return verifyEd25519(key, data, signature);
    default:
      throw new UnknownAlgorithmError(alg);
  }
}

/** Sign with HMAC using the specified hash algorithm. */
export async function signHMAC(
  secret: Uint8Array,
  data: Uint8Array,
  hash: "sha256" | "sha384" | "sha512" = "sha256",
): Promise<Uint8Array> {
  const hmac = crypto.createHmac(hash, secret);
  hmac.update(data);
  return new Uint8Array(hmac.digest());
}

/** Verify with HMAC using the specified hash algorithm. */
export async function verifyHMAC(
  secret: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
  hash: "sha256" | "sha384" | "sha512" = "sha256",
): Promise<boolean> {
  const expected = await signHMAC(secret, data, hash);
  if (expected.length !== signature.length) return false;
  return crypto.timingSafeEqual(expected, signature);
}

// --- RSA-PSS ---

function signRSAPSS(
  key: crypto.KeyObject,
  data: Uint8Array,
  hash: string,
  saltLength: number,
): Uint8Array {
  if (key.type !== "private") {
    throw new InvalidKeyError("expected private key for RSA-PSS signing");
  }
  return new Uint8Array(
    crypto.sign(hash, data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength,
    }),
  );
}

function verifyRSAPSS(
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
  hash: string,
  saltLength: number,
): boolean {
  if (key.type !== "public") {
    throw new InvalidKeyError("expected public key for RSA-PSS verification");
  }
  return crypto.verify(
    hash,
    data,
    {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength,
    },
    signature,
  );
}

// --- RSA PKCS1 v1.5 ---

function signRSAv15(key: crypto.KeyObject, data: Uint8Array): Uint8Array {
  if (key.type !== "private") {
    throw new InvalidKeyError("expected private key for RSA PKCS1v1.5 signing");
  }
  return new Uint8Array(
    crypto.sign("sha256", data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }),
  );
}

function verifyRSAv15(
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (key.type !== "public") {
    throw new InvalidKeyError("expected public key for RSA PKCS1v1.5 verification");
  }
  return crypto.verify(
    "sha256",
    data,
    {
      key,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    signature,
  );
}

// --- ECDSA ---
// RFC 9421 Section 3.3.3: r || s in raw big-endian format
// P-256: 32+32 = 64 bytes, P-384: 48+48 = 96 bytes, P-521: 66+66 = 132 bytes

function signECDSA(
  key: crypto.KeyObject,
  data: Uint8Array,
  hash: string,
  expectedLength: number,
): Uint8Array {
  if (key.type !== "private") {
    throw new InvalidKeyError("expected private key for ECDSA signing");
  }
  const sig = crypto.sign(hash, data, { key, dsaEncoding: "ieee-p1363" });
  const result = new Uint8Array(sig);
  if (result.length !== expectedLength) {
    throw new InvalidKeyError(
      `ECDSA signature length mismatch: expected ${expectedLength}, got ${result.length}`,
    );
  }
  return result;
}

function verifyECDSA(
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
  hash: string,
  expectedLength: number,
): boolean {
  if (key.type !== "public") {
    throw new InvalidKeyError("expected public key for ECDSA verification");
  }
  if (signature.length !== expectedLength) return false;
  return crypto.verify(hash, data, { key, dsaEncoding: "ieee-p1363" }, signature);
}

// --- Ed25519 ---

function signEd25519(key: crypto.KeyObject, data: Uint8Array): Uint8Array {
  if (key.type !== "private") {
    throw new InvalidKeyError("expected private key for Ed25519 signing");
  }
  return new Uint8Array(crypto.sign(null, data, key));
}

function verifyEd25519(
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (key.type !== "public") {
    throw new InvalidKeyError("expected public key for Ed25519 verification");
  }
  return crypto.verify(null, data, key, signature);
}
