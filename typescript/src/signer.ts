import type {
  HttpMessage,
  SignatureParameters,
  SigningKey,
  SignResult,
  SFVDictMember,
} from "./types.js";
import { SFVToken } from "./types.js";
import { buildSignatureBase } from "./base.js";
import { serializeDictionary } from "./sfv.js";

/**
 * Sign a message and return the Signature-Input and Signature values.
 * The reqMsg parameter is only needed for response signatures with ;req components.
 */
export async function signMessage(
  msg: HttpMessage,
  label: string,
  params: SignatureParameters,
  key: SigningKey,
  reqMsg?: HttpMessage,
): Promise<SignResult> {
  const [base, sigInput] = buildSignatureBase(msg, params, reqMsg);
  const signature = await key.sign(base);

  return {
    label,
    signatureInput: sigInput,
    signature,
  };
}

/** Format one or more SignResults as a Signature-Input header value. */
export function signatureInputHeader(...results: SignResult[]): string {
  const members: SFVDictMember[] = results.map((r) => ({
    key: r.label,
    item: { value: new SFVToken(r.signatureInput) },
  }));
  return serializeDictionary(members);
}

/** Format one or more SignResults as a Signature header value. */
export function signatureHeader(...results: SignResult[]): string {
  const members: SFVDictMember[] = results.map((r) => ({
    key: r.label,
    item: { value: r.signature },
  }));
  return serializeDictionary(members);
}
