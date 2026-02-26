import type { SigningKey, SignatureParameters, HttpMessage } from "../types.js";
import { component } from "../components.js";
import { signMessage, signatureInputHeader, signatureHeader } from "../signer.js";

/**
 * Minimal undici types so we don't require undici as a compile-time dependency.
 * Users who import this module will already have undici available (built into Node 20+).
 */
interface UndiciRequestOptions {
  method?: string;
  headers?: Record<string, string> | string[][];
  body?: unknown;
  [key: string]: unknown;
}

interface UndiciResponseData {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body: unknown;
  [key: string]: unknown;
}

type UndiciRequestFn = (
  url: string | URL,
  options?: UndiciRequestOptions,
) => Promise<UndiciResponseData>;

export interface UndiciSigningOptions {
  /** The signing key for outgoing requests. */
  key: SigningKey;
  /** Signature label. Defaults to "sig1". */
  label?: string;
  /** Build SignatureParameters from the request. If not provided, signs @method, @path, @authority. */
  params?: (url: URL, method: string) => SignatureParameters;
}

/**
 * Create an undici request function that signs outgoing requests.
 *
 * ```ts
 * import { request } from 'undici';
 * import { createSigningRequest } from '@zourzouvillys/httpsig/undici';
 *
 * const signedRequest = createSigningRequest(request, { key: myKey });
 * const { statusCode, body } = await signedRequest('https://example.com/api');
 * ```
 */
export function createSigningRequest(
  baseRequest: UndiciRequestFn,
  options: UndiciSigningOptions,
): UndiciRequestFn {
  const label = options.label ?? "sig1";

  return async (url, opts) => {
    const parsedUrl = url instanceof URL ? url : new URL(url);
    const method = (opts?.method ?? "GET").toUpperCase();

    const existingHeaders = normalizeHeaders(opts?.headers);

    const msg: HttpMessage = {
      isRequest: true,
      method,
      url: parsedUrl,
      headerValues(name: string): string[] {
        const key = name.toLowerCase();
        const v = existingHeaders[key];
        return v !== undefined ? [v] : [];
      },
    };

    const params = options.params
      ? options.params(parsedUrl, method)
      : defaultParams(options.key);

    const result = await signMessage(msg, label, params, options.key);

    const signedHeaders = {
      ...existingHeaders,
      "signature-input": signatureInputHeader(result),
      signature: signatureHeader(result),
    };

    return baseRequest(url, { ...opts, headers: signedHeaders });
  };
}

function normalizeHeaders(
  headers?: Record<string, string> | string[][],
): Record<string, string> {
  if (!headers) return {};
  if (Array.isArray(headers)) {
    const result: Record<string, string> = {};
    for (const [k, v] of headers) {
      result[k.toLowerCase()] = v;
    }
    return result;
  }
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    result[k.toLowerCase()] = v;
  }
  return result;
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
