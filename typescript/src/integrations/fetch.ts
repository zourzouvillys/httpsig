import type { SigningKey, SignatureParameters, HttpMessage } from "../types.js";
import { component } from "../components.js";
import { signMessage, signatureInputHeader, signatureHeader } from "../signer.js";

export interface SigningFetchOptions {
  /** The signing key for outgoing requests. */
  key: SigningKey;
  /** Signature label. Defaults to "sig1". */
  label?: string;
  /** Build SignatureParameters for each request. If not provided, signs @method, @path, @authority. */
  params?: (request: Request) => SignatureParameters;
  /** Base fetch function. Defaults to globalThis.fetch. */
  fetch?: typeof globalThis.fetch;
}

/**
 * Create a fetch function that signs outgoing requests.
 *
 * ```ts
 * const signedFetch = createSigningFetch({ key: myKey });
 * const response = await signedFetch("https://example.com/api", { method: "POST" });
 * ```
 */
export function createSigningFetch(
  options: SigningFetchOptions,
): typeof globalThis.fetch {
  const baseFetch = options.fetch ?? globalThis.fetch;
  const label = options.label ?? "sig1";

  return async (input, init) => {
    const req = new Request(input, init);
    const url = new URL(req.url);

    const msg: HttpMessage = {
      isRequest: true,
      method: req.method,
      url,
      headerValues(name: string): string[] {
        const v = req.headers.get(name);
        return v !== null ? [v] : [];
      },
    };

    const params = options.params
      ? options.params(req)
      : defaultParams(options.key);

    const result = await signMessage(msg, label, params, options.key);

    const headers = new Headers(req.headers);
    headers.set("Signature-Input", signatureInputHeader(result));
    headers.set("Signature", signatureHeader(result));

    return baseFetch(new Request(req, { headers }));
  };
}

function defaultParams(key: SigningKey): SignatureParameters {
  return {
    components: [
      component("@method"),
      component("@path"),
      component("@authority"),
    ],
    keyId: key.keyId,
    created: Math.floor(Date.now() / 1000),
  };
}
