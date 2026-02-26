import type {
  ComponentIdentifier,
  HttpMessage,
  SignatureParameters,
  SFVParams,
} from "./types.js";
import { DuplicateComponentError } from "./errors.js";
import {
  newSFVParams,
  sfvParamsSet,
  serializeComponentId,
  serializeSignatureParams,
} from "./sfv.js";
import { extractComponent } from "./components.js";

/**
 * Build the signature base string per RFC 9421 Section 2.5.
 * Returns [signatureBase, signatureParamsValue].
 */
export function buildSignatureBase(
  msg: HttpMessage,
  params: SignatureParameters,
  reqMsg?: HttpMessage,
): [Uint8Array, string] {
  validateComponents(params.components);

  let base = "";
  for (const c of params.components) {
    const value = extractComponent(c, msg, reqMsg);
    base += serializeComponentId(c) + ": " + value + "\n";
  }

  const sfvParams = buildSFVParams(params);
  const sigParamsValue = serializeSignatureParams(params.components, sfvParams);
  base += '"@signature-params": ' + sigParamsValue;

  return [new TextEncoder().encode(base), sigParamsValue];
}

function buildSFVParams(params: SignatureParameters): SFVParams {
  let p = newSFVParams();
  if (params.created !== undefined) {
    p = sfvParamsSet(p, "created", params.created);
  }
  if (params.expires !== undefined) {
    p = sfvParamsSet(p, "expires", params.expires);
  }
  if (params.keyId) {
    p = sfvParamsSet(p, "keyid", params.keyId);
  }
  if (params.algorithm) {
    p = sfvParamsSet(p, "alg", params.algorithm);
  }
  if (params.nonce !== undefined) {
    p = sfvParamsSet(p, "nonce", params.nonce);
  }
  if (params.tag !== undefined) {
    p = sfvParamsSet(p, "tag", params.tag);
  }
  return p;
}

function validateComponents(components: ComponentIdentifier[]): void {
  const seen = new Set<string>();
  for (const c of components) {
    const key = serializeComponentId(c);
    if (seen.has(key)) {
      throw new DuplicateComponentError(key);
    }
    seen.add(key);
  }
}
