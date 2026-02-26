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
    case "rsa-pss-sha512":
      return signRSAPSS(key, data);
    case "ecdsa-p256-sha256":
      return signECDSAP256(key, data);
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
    case "rsa-pss-sha512":
      return verifyRSAPSS(key, data, signature);
    case "ecdsa-p256-sha256":
      return verifyECDSAP256(key, data, signature);
    case "ed25519":
      return verifyEd25519(key, data, signature);
    default:
      throw new UnknownAlgorithmError(alg);
  }
}

/** Sign with HMAC-SHA256. */
export async function signHMAC(
  secret: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(data);
  return new Uint8Array(hmac.digest());
}

/** Verify with HMAC-SHA256. */
export async function verifyHMAC(
  secret: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const expected = await signHMAC(secret, data);
  if (expected.length !== signature.length) return false;
  return crypto.timingSafeEqual(expected, signature);
}

// --- RSA-PSS-SHA512 ---

function signRSAPSS(key: crypto.KeyObject, data: Uint8Array): Uint8Array {
  if (key.type !== "private") {
    throw new InvalidKeyError("expected private key for RSA-PSS signing");
  }
  return new Uint8Array(
    crypto.sign("sha512", data, {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 64,
    }),
  );
}

function verifyRSAPSS(
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (key.type !== "public") {
    throw new InvalidKeyError("expected public key for RSA-PSS verification");
  }
  return crypto.verify(
    "sha512",
    data,
    {
      key,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 64,
    },
    signature,
  );
}

// --- ECDSA-P256-SHA256 ---
// RFC 9421 Section 3.3.3: r || s, each 32 bytes big-endian

function signECDSAP256(key: crypto.KeyObject, data: Uint8Array): Uint8Array {
  if (key.type !== "private") {
    throw new InvalidKeyError("expected private key for ECDSA signing");
  }
  // Node.js produces DER-encoded signatures, we need to convert to r||s
  const derSig = crypto.sign("sha256", data, { key, dsaEncoding: "ieee-p1363" });
  return new Uint8Array(derSig);
}

function verifyECDSAP256(
  key: crypto.KeyObject,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (key.type !== "public") {
    throw new InvalidKeyError("expected public key for ECDSA verification");
  }
  if (signature.length !== 64) return false;
  return crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, signature);
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
