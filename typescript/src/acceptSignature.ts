import type {
  Algorithm,
  ComponentIdentifier,
  SignatureParameters,
  SignatureRequirements,
  SFVDictMember,
  SFVInnerList,
  SFVItem,
  SFVParams,
} from "./types.js";
import {
  parseDictionary,
  serializeDictionary,
  newSFVParams,
  sfvParamsSet,
  sfvParamsGet,
} from "./sfv.js";

/**
 * Build an Accept-Signature header value from a set of labeled requirements.
 *
 * Each entry maps a label (e.g. "sig1") to the requirements that the
 * corresponding signature must satisfy.
 */
export function buildAcceptSignature(
  entries: Record<string, SignatureRequirements>,
): string {
  const members: SFVDictMember[] = [];

  for (const [label, req] of Object.entries(entries)) {
    const items: SFVItem[] = req.components.map((c) => ({
      value: c.name,
      params: c.params,
    }));

    let params: SFVParams | undefined;

    if (req.keyId !== undefined) {
      if (!params) params = newSFVParams();
      params = sfvParamsSet(params, "keyid", req.keyId);
    }
    if (req.algorithm !== undefined) {
      if (!params) params = newSFVParams();
      params = sfvParamsSet(params, "alg", req.algorithm);
    }
    if (req.requireCreated) {
      if (!params) params = newSFVParams();
      params = sfvParamsSet(params, "created", true);
    }
    if (req.requireExpires) {
      if (!params) params = newSFVParams();
      params = sfvParamsSet(params, "expires", true);
    }
    if (req.tag !== undefined) {
      if (!params) params = newSFVParams();
      params = sfvParamsSet(params, "tag", req.tag);
    }

    const innerList: SFVInnerList = { items, params };
    members.push({ key: label, innerList });
  }

  return serializeDictionary(members);
}

/**
 * Parse an Accept-Signature header value into labeled requirements.
 */
export function parseAcceptSignature(
  headerValue: string,
): Record<string, SignatureRequirements> {
  const dict = parseDictionary(headerValue);
  const result: Record<string, SignatureRequirements> = {};

  for (const member of dict) {
    if (!member.innerList) continue;

    const components: ComponentIdentifier[] = member.innerList.items.map(
      (item) => {
        const name =
          typeof item.value === "string" ? item.value : String(item.value);
        return { name, params: item.params };
      },
    );

    const req: SignatureRequirements = { components };
    const params = member.innerList.params;

    if (params) {
      const keyId = sfvParamsGet(params, "keyid");
      if (typeof keyId === "string") req.keyId = keyId;

      const alg = sfvParamsGet(params, "alg");
      if (typeof alg === "string") req.algorithm = alg as Algorithm;

      const tag = sfvParamsGet(params, "tag");
      if (typeof tag === "string") req.tag = tag;

      const created = sfvParamsGet(params, "created");
      if (created === true) req.requireCreated = true;

      const expires = sfvParamsGet(params, "expires");
      if (expires === true) req.requireExpires = true;
    }

    result[member.key] = req;
  }

  return result;
}

/**
 * Convert signature requirements to SignatureParameters suitable for signing.
 *
 * The caller supplies the dynamic values (created, expires, nonce) that
 * cannot be inferred from the requirements alone.
 */
export function toSignatureParameters(
  req: SignatureRequirements,
  opts?: { created?: number; expires?: number; nonce?: string },
): SignatureParameters {
  const params: SignatureParameters = {
    components: req.components,
    keyId: req.keyId ?? "",
    algorithm: req.algorithm,
    tag: req.tag,
    created: opts?.created,
    expires: opts?.expires,
    nonce: opts?.nonce,
  };
  return params;
}
