import * as crypto from "node:crypto";
import type { Algorithm, SigningKey, VerifyingKey } from "./types.js";
import { algorithmSign, algorithmVerify, signHMAC, verifyHMAC } from "./algorithm.js";

// --- Asymmetric keys ---

class AsymmetricSigningKey implements SigningKey {
  constructor(
    public readonly keyId: string,
    public readonly algorithm: Algorithm,
    private readonly key: crypto.KeyObject,
  ) {}

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return algorithmSign(this.algorithm, this.key, data);
  }
}

class AsymmetricVerifyingKey implements VerifyingKey {
  constructor(
    public readonly keyId: string,
    public readonly algorithm: Algorithm,
    private readonly key: crypto.KeyObject,
  ) {}

  async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return algorithmVerify(this.algorithm, this.key, data, signature);
  }
}

/** Create a SigningKey for rsa-pss-sha512. */
export function newRSAPSSSigningKey(
  keyId: string,
  key: crypto.KeyObject,
): SigningKey {
  return new AsymmetricSigningKey(keyId, "rsa-pss-sha512", key);
}

/** Create a VerifyingKey for rsa-pss-sha512. */
export function newRSAPSSVerifyingKey(
  keyId: string,
  key: crypto.KeyObject,
): VerifyingKey {
  return new AsymmetricVerifyingKey(keyId, "rsa-pss-sha512", key);
}

/** Create a SigningKey for ecdsa-p256-sha256. */
export function newECDSAP256SigningKey(
  keyId: string,
  key: crypto.KeyObject,
): SigningKey {
  return new AsymmetricSigningKey(keyId, "ecdsa-p256-sha256", key);
}

/** Create a VerifyingKey for ecdsa-p256-sha256. */
export function newECDSAP256VerifyingKey(
  keyId: string,
  key: crypto.KeyObject,
): VerifyingKey {
  return new AsymmetricVerifyingKey(keyId, "ecdsa-p256-sha256", key);
}

/** Create a SigningKey for ed25519. */
export function newEd25519SigningKey(
  keyId: string,
  key: crypto.KeyObject,
): SigningKey {
  return new AsymmetricSigningKey(keyId, "ed25519", key);
}

/** Create a VerifyingKey for ed25519. */
export function newEd25519VerifyingKey(
  keyId: string,
  key: crypto.KeyObject,
): VerifyingKey {
  return new AsymmetricVerifyingKey(keyId, "ed25519", key);
}

// --- HMAC ---

class HMACSHA256Key implements SigningKey, VerifyingKey {
  public readonly algorithm: Algorithm = "hmac-sha256";

  constructor(
    public readonly keyId: string,
    private readonly secret: Uint8Array,
  ) {}

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return signHMAC(this.secret, data);
  }

  async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return verifyHMAC(this.secret, data, signature);
  }
}

/** Create a key that implements both SigningKey and VerifyingKey for hmac-sha256. */
export function newHMACSHA256Key(
  keyId: string,
  secret: Uint8Array,
): SigningKey & VerifyingKey {
  return new HMACSHA256Key(keyId, new Uint8Array(secret));
}
