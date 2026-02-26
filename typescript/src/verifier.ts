import type {
  Algorithm,
  ComponentIdentifier,
  HttpMessage,
  KeyProvider,
  SignatureParameters,
  VerifyOptions,
  VerifyResult,
} from "./types.js";
import {
  InvalidSignatureError,
  MissingSignatureError,
  MalformedInputError,
} from "./errors.js";
import { parseDictionary, serializeComponentId, sfvParamsGet } from "./sfv.js";
import { buildSignatureBase } from "./base.js";

/**
 * Verify a signature on a message.
 * Parses the Signature-Input and Signature headers, reconstructs the signature base,
 * and verifies using a key from the provider.
 */
export async function verifyMessage(
  msg: HttpMessage,
  provider: KeyProvider,
  opts?: VerifyOptions,
  reqMsg?: HttpMessage,
): Promise<VerifyResult> {
  const sigInputValues = msg.headerValues("signature-input");
  if (sigInputValues.length === 0) {
    throw new MissingSignatureError();
  }
  const sigInputStr = sigInputValues.join(", ");

  let sigInputDict;
  try {
    sigInputDict = parseDictionary(sigInputStr);
  } catch {
    throw new MalformedInputError("malformed Signature-Input header");
  }

  const sigValues = msg.headerValues("signature");
  if (sigValues.length === 0) {
    throw new MissingSignatureError();
  }
  const sigStr = sigValues.join(", ");

  let sigDict;
  try {
    sigDict = parseDictionary(sigStr);
  } catch {
    throw new MalformedInputError("malformed Signature header");
  }

  // Build lookup for signatures
  const sigMap = new Map<string, Uint8Array>();
  for (const m of sigDict) {
    if (m.item && m.item.value instanceof Uint8Array) {
      sigMap.set(m.key, m.item.value);
    }
  }

  // Try each signature input entry
  for (const member of sigInputDict) {
    const label = member.key;

    if (opts?.requiredLabel && label !== opts.requiredLabel) continue;
    if (!member.innerList) continue;

    let components: ComponentIdentifier[];
    try {
      components = parseComponentsFromInnerList(member.innerList);
    } catch {
      continue;
    }

    let sigParams: SignatureParameters;
    try {
      sigParams = parseSignatureParams(
        member.innerList.params,
        components,
      );
    } catch {
      continue;
    }

    if (
      opts?.requiredComponents &&
      !hasRequiredComponents(sigParams.components, opts.requiredComponents)
    ) {
      continue;
    }

    if (!checkTimeConstraints(sigParams, opts)) continue;

    const sigBytes = sigMap.get(label);
    if (!sigBytes) continue;

    let key;
    try {
      key = await provider(sigParams.keyId, sigParams.algorithm);
    } catch {
      continue;
    }

    // If algorithm was specified in the input, it must match the key
    if (sigParams.algorithm && key.algorithm !== sigParams.algorithm) {
      continue;
    }

    let base: Uint8Array;
    try {
      [base] = buildSignatureBase(msg, sigParams, reqMsg);
    } catch {
      continue;
    }

    let valid: boolean;
    try {
      valid = await key.verify(base, sigBytes);
    } catch {
      continue;
    }
    if (!valid) continue;

    return {
      label,
      keyId: key.keyId,
      algorithm: key.algorithm,
      components: sigParams.components,
      created: sigParams.created,
      expires: sigParams.expires,
    };
  }

  throw new InvalidSignatureError();
}

function parseComponentsFromInnerList(
  il: { items: Array<{ value: unknown; params?: import("./types.js").SFVParams }> },
): ComponentIdentifier[] {
  return il.items.map((item) => {
    const name = typeof item.value === "string" ? item.value : String(item.value);
    return { name, params: item.params };
  });
}

function parseSignatureParams(
  params: import("./types.js").SFVParams | undefined,
  components: ComponentIdentifier[],
): SignatureParameters {
  const sp: SignatureParameters = {
    components,
    keyId: "",
  };
  if (!params) return sp;

  const created = sfvParamsGet(params, "created");
  if (typeof created === "number") sp.created = created;

  const expires = sfvParamsGet(params, "expires");
  if (typeof expires === "number") sp.expires = expires;

  const nonce = sfvParamsGet(params, "nonce");
  if (typeof nonce === "string") sp.nonce = nonce;

  const alg = sfvParamsGet(params, "alg");
  if (typeof alg === "string") sp.algorithm = alg as Algorithm;

  const keyid = sfvParamsGet(params, "keyid");
  if (typeof keyid === "string") sp.keyId = keyid;

  const tag = sfvParamsGet(params, "tag");
  if (typeof tag === "string") sp.tag = tag;

  return sp;
}

function hasRequiredComponents(
  have: ComponentIdentifier[],
  required: ComponentIdentifier[],
): boolean {
  const haveSet = new Set(have.map(serializeComponentId));
  return required.every((c) => haveSet.has(serializeComponentId(c)));
}

function checkTimeConstraints(
  params: SignatureParameters,
  opts?: VerifyOptions,
): boolean {
  if (!opts) return true;

  const now = opts.now ? opts.now() : Date.now();

  if (params.created !== undefined && opts.maxAgeMs) {
    const createdMs = params.created * 1000;
    if (now - createdMs > opts.maxAgeMs) return false;
  }

  if (params.created !== undefined && opts.maxClockSkewMs) {
    const createdMs = params.created * 1000;
    if (createdMs - now > opts.maxClockSkewMs) return false;
  }

  const rejectExpired = opts.rejectExpired !== false;
  if (params.expires !== undefined && rejectExpired) {
    const expiresMs = params.expires * 1000;
    if (now > expiresMs) return false;
  }

  return true;
}
