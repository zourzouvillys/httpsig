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
  SignatureRequirements,
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
  componentReqWithKey,
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
  newRSAPSSSHA256SigningKey,
  newRSAPSSSHA256VerifyingKey,
  newRSAPSSSHA384SigningKey,
  newRSAPSSSHA384VerifyingKey,
  newRSAv15SigningKey,
  newRSAv15VerifyingKey,
  newECDSAP256SigningKey,
  newECDSAP256VerifyingKey,
  newECDSAP384SigningKey,
  newECDSAP384VerifyingKey,
  newECDSAP521SigningKey,
  newECDSAP521VerifyingKey,
  newEd25519SigningKey,
  newEd25519VerifyingKey,
  newHMACSHA256Key,
  newHMACSHA384Key,
  newHMACSHA512Key,
  newSigningKey,
  newVerifyingKey,
  newKeyPair,
  newHMACKeyPair,
  newHMACSHA384KeyPair,
  newHMACSHA512KeyPair,
  newWebCryptoSigningKey,
  newWebCryptoVerifyingKey,
} from "./keys.js";

// Content-Digest
export { contentDigest, verifyContentDigest } from "./digest.js";

// Accept-Signature (RFC 9421 Section 5)
export {
  buildAcceptSignature,
  parseAcceptSignature,
  toSignatureParameters,
} from "./acceptSignature.js";

// Message helpers
export { RawMessage, buildRequestMessage, buildResponseMessage } from "./message.js";
