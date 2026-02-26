/** Signature algorithm identifiers per RFC 9421 Section 3.3. */
export type Algorithm =
  | "rsa-pss-sha512"
  | "ecdsa-p256-sha256"
  | "ed25519"
  | "hmac-sha256";

/** Digest algorithm identifiers per RFC 9530. */
export type DigestAlgorithm = "sha-256" | "sha-512";

/** Ordered key-value parameter map for SFV. */
export interface SFVParams {
  readonly keys: string[];
  readonly values: Record<string, SFVBareItem>;
}

export type SFVBareItem = string | number | boolean | Uint8Array | SFVToken;

/** Wrapper to distinguish tokens from strings in SFV serialization. */
export class SFVToken {
  constructor(public readonly value: string) {}
}

export interface SFVItem {
  value: SFVBareItem;
  params?: SFVParams;
}

export interface SFVInnerList {
  items: SFVItem[];
  params?: SFVParams;
}

export interface SFVDictMember {
  key: string;
  item?: SFVItem;
  innerList?: SFVInnerList;
}

/** Component identifier for signature base construction. */
export interface ComponentIdentifier {
  name: string;
  params?: SFVParams;
}

/** Parameters that control signature generation. */
export interface SignatureParameters {
  components: ComponentIdentifier[];
  algorithm?: Algorithm;
  keyId: string;
  created?: number;
  expires?: number;
  nonce?: string;
  tag?: string;
}

/** Minimal view of an HTTP message for signature operations. */
export interface HttpMessage {
  isRequest: boolean;
  method?: string;
  url?: URL;
  statusCode?: number;
  headerValues(name: string): string[];
}

/** A key that can produce signatures. */
export interface SigningKey {
  keyId: string;
  algorithm: Algorithm;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** A key that can verify signatures. */
export interface VerifyingKey {
  keyId: string;
  algorithm: Algorithm;
  verify(data: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

/** Resolves a key ID to a VerifyingKey. */
export type KeyProvider = (
  keyId: string,
  algorithm: Algorithm | undefined,
) => Promise<VerifyingKey>;

/** Result of a signing operation. */
export interface SignResult {
  label: string;
  signatureInput: string;
  signature: Uint8Array;
}

/** Result of a verification operation. */
export interface VerifyResult {
  label: string;
  keyId: string;
  algorithm?: Algorithm;
  components: ComponentIdentifier[];
  created?: number;
  expires?: number;
}

/** Options for signature verification. */
export interface VerifyOptions {
  requiredComponents?: ComponentIdentifier[];
  maxAgeMs?: number;
  /** Maximum allowed forward clock skew in milliseconds. Rejects signatures with created > now + maxClockSkewMs. */
  maxClockSkewMs?: number;
  rejectExpired?: boolean;
  requiredLabel?: string;
  now?: () => number;
}
