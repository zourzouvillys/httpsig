// Types
export type {
  Algorithm,
  DigestAlgorithm,
  SFVParams,
  SFVBareItem,
  SFVItem,
  SFVInnerList,
  SFVDictMember,
  ComponentIdentifier,
  SignatureParameters,
  HttpMessage,
  SigningKey,
  VerifyingKey,
  KeyPair,
  KeyProvider,
  SignResult,
  VerifyResult,
  VerifyOptions,
} from "./types.js";
export { SFVToken } from "./types.js";

// Errors
export {
  HttpSigError,
  UnknownAlgorithmError,
  InvalidKeyError,
  InvalidSignatureError,
  MissingComponentError,
  MissingSignatureError,
  SignatureExpiredError,
  KeyNotFoundError,
  MalformedInputError,
  DuplicateComponentError,
} from "./errors.js";

// SFV
export {
  newSFVParams,
  sfvParamsSet,
  sfvParamsGet,
  parseDictionary,
  serializeBareItem,
  serializeParams,
  serializeComponentId,
  serializeSignatureParams,
  serializeDictionary,
  serializeInnerList,
  uint8ToBase64,
  base64ToUint8,
} from "./sfv.js";

// Components
export {
  component,
  componentWithParams,
  componentWithKey,
  queryParam,
  componentReq,
  extractComponent,
} from "./components.js";

// Signature base
export { buildSignatureBase } from "./base.js";

// Signer
export { signMessage, signatureInputHeader, signatureHeader } from "./signer.js";

// Verifier
export { verifyMessage } from "./verifier.js";

// Keys
export {
  newRSAPSSSigningKey,
  newRSAPSSVerifyingKey,
  newECDSAP256SigningKey,
  newECDSAP256VerifyingKey,
  newEd25519SigningKey,
  newEd25519VerifyingKey,
  newHMACSHA256Key,
  newSigningKey,
  newVerifyingKey,
  newKeyPair,
  newHMACKeyPair,
  newWebCryptoSigningKey,
  newWebCryptoVerifyingKey,
} from "./keys.js";

// Content-Digest
export { contentDigest, verifyContentDigest } from "./digest.js";

// Message helpers
export { RawMessage, buildRequestMessage, buildResponseMessage } from "./message.js";
