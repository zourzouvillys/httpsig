import * as crypto from "node:crypto";
import type { DigestAlgorithm } from "./types.js";

/** Compute a Content-Digest header value per RFC 9530. */
export function contentDigest(
  body: Uint8Array,
  alg: DigestAlgorithm,
): string {
  let hashAlg: string;
  switch (alg) {
    case "sha-256":
      hashAlg = "sha256";
      break;
    case "sha-512":
      hashAlg = "sha512";
      break;
    default:
      throw new Error(`unsupported digest algorithm: ${alg}`);
  }
  const hash = crypto.createHash(hashAlg);
  hash.update(body);
  const digest = hash.digest("base64");
  return `${alg}=:${digest}:`;
}

/** Verify a Content-Digest header value matches the body. */
export function verifyContentDigest(
  body: Uint8Array,
  headerValue: string,
): boolean {
  const parts = headerValue.split(",");
  for (const part of parts) {
    const trimmed = part.trim();
    const eqIdx = trimmed.indexOf("=:");
    if (eqIdx < 0) continue;

    const algStr = trimmed.slice(0, eqIdx).trim();
    const rest = trimmed.slice(eqIdx + 2);
    const colonIdx = rest.lastIndexOf(":");
    if (colonIdx < 0) continue;

    const b64 = rest.slice(0, colonIdx);
    let expected: Buffer;
    try {
      expected = Buffer.from(b64, "base64");
    } catch {
      continue;
    }

    let hashAlg: string;
    switch (algStr as DigestAlgorithm) {
      case "sha-256":
        hashAlg = "sha256";
        break;
      case "sha-512":
        hashAlg = "sha512";
        break;
      default:
        continue;
    }

    const hash = crypto.createHash(hashAlg);
    hash.update(body);
    const actual = hash.digest();

    if (actual.length === expected.length && crypto.timingSafeEqual(actual, expected)) {
      return true;
    }
  }
  return false;
}
