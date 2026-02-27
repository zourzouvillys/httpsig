import * as crypto from "node:crypto";
import type { Algorithm, KeyPair, SigningKey, VerifyingKey } from "./types.js";
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

// --- Auto-detection ---

function detectAlgorithm(key: crypto.KeyObject): Algorithm {
  if (key.type === "secret") {
    return "hmac-sha256";
  }
  switch (key.asymmetricKeyType) {
    case "rsa":
    case "rsa-pss":
      return "rsa-pss-sha512";
    case "ec": {
      const details = key.asymmetricKeyDetails;
      if (details?.namedCurve !== "prime256v1" && details?.namedCurve !== "P-256") {
        throw new Error(`unsupported EC curve: ${details?.namedCurve}`);
      }
      return "ecdsa-p256-sha256";
    }
    case "ed25519":
      return "ed25519";
    default:
      throw new Error(`unsupported key type: ${key.asymmetricKeyType}`);
  }
}

/** Create a SigningKey by auto-detecting the algorithm from the key type. */
export function newSigningKey(keyId: string, key: crypto.KeyObject): SigningKey {
  return new AsymmetricSigningKey(keyId, detectAlgorithm(key), key);
}

/** Create a VerifyingKey by auto-detecting the algorithm from the key type. */
export function newVerifyingKey(keyId: string, key: crypto.KeyObject): VerifyingKey {
  return new AsymmetricVerifyingKey(keyId, detectAlgorithm(key), key);
}

/** Create a KeyPair by auto-detecting the algorithm and deriving the public key from a private key. */
export function newKeyPair(keyId: string, privateKey: crypto.KeyObject): KeyPair {
  const algorithm = detectAlgorithm(privateKey);
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    keyId,
    algorithm,
    signingKey: new AsymmetricSigningKey(keyId, algorithm, privateKey),
    verifyingKey: new AsymmetricVerifyingKey(keyId, algorithm, publicKey),
  };
}

/** Create a KeyPair for HMAC-SHA256 where the same secret backs both sides. */
export function newHMACKeyPair(keyId: string, secret: Uint8Array): KeyPair {
  const key = new HMACSHA256Key(keyId, new Uint8Array(secret));
  return {
    keyId,
    algorithm: "hmac-sha256",
    signingKey: key,
    verifyingKey: key,
  };
}

// --- Web Crypto adapters ---

function webCryptoParams(
  algorithm: Algorithm,
): crypto.webcrypto.AlgorithmIdentifier | crypto.webcrypto.RsaPssParams | crypto.webcrypto.EcdsaParams {
  switch (algorithm) {
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", saltLength: 64 } satisfies crypto.webcrypto.RsaPssParams;
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", hash: "SHA-256" } satisfies crypto.webcrypto.EcdsaParams;
    case "ed25519":
      return { name: "Ed25519" };
    case "hmac-sha256":
      return { name: "HMAC" };
    default:
      throw new Error(`unsupported Web Crypto algorithm: ${algorithm}`);
  }
}

class WebCryptoSigningKey implements SigningKey {
  constructor(
    public readonly keyId: string,
    public readonly algorithm: Algorithm,
    private readonly cryptoKey: crypto.webcrypto.CryptoKey,
  ) {}

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const params = webCryptoParams(this.algorithm);
    const buf = data as NodeJS.BufferSource;
    const sig = await globalThis.crypto.subtle.sign(params, this.cryptoKey, buf);
    return new Uint8Array(sig);
  }
}

class WebCryptoVerifyingKey implements VerifyingKey {
  constructor(
    public readonly keyId: string,
    public readonly algorithm: Algorithm,
    private readonly cryptoKey: crypto.webcrypto.CryptoKey,
  ) {}

  async verify(data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const params = webCryptoParams(this.algorithm);
    const dataBuf = data as NodeJS.BufferSource;
    const sigBuf = signature as NodeJS.BufferSource;
    return globalThis.crypto.subtle.verify(params, this.cryptoKey, sigBuf, dataBuf);
  }
}

/** Create a SigningKey backed by Web Crypto. Algorithm must be specified because CryptoKey type mapping is ambiguous. */
export function newWebCryptoSigningKey(
  keyId: string,
  cryptoKey: crypto.webcrypto.CryptoKey,
  algorithm: Algorithm,
): SigningKey {
  return new WebCryptoSigningKey(keyId, algorithm, cryptoKey);
}

/** Create a VerifyingKey backed by Web Crypto. Algorithm must be specified because CryptoKey type mapping is ambiguous. */
export function newWebCryptoVerifyingKey(
  keyId: string,
  cryptoKey: crypto.webcrypto.CryptoKey,
  algorithm: Algorithm,
): VerifyingKey {
  return new WebCryptoVerifyingKey(keyId, algorithm, cryptoKey);
}
