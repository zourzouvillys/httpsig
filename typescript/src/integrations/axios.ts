import type { SigningKey, SignatureParameters, HttpMessage } from "../types.js";
import { component } from "../components.js";
import { signMessage, signatureInputHeader, signatureHeader } from "../signer.js";

/**
 * Minimal axios types so we don't require axios as a compile-time dependency.
 * Users who import this module will already have axios installed.
 */
interface AxiosRequestConfig {
  url?: string;
  baseURL?: string;
  method?: string;
  headers?: Record<string, string>;
}

interface AxiosInterceptorManager {
  use(
    onFulfilled: (config: AxiosRequestConfig) => Promise<AxiosRequestConfig>,
  ): number;
}

interface AxiosInstance {
  interceptors: {
    request: AxiosInterceptorManager;
  };
  defaults: {
    baseURL?: string;
  };
}

export interface AxiosSigningOptions {
  /** The signing key for outgoing requests. */
  key: SigningKey;
  /** Signature label. Defaults to "sig1". */
  label?: string;
  /** Build SignatureParameters from the request config. If not provided, signs @method, @path, @authority. */
  params?: (config: AxiosRequestConfig) => SignatureParameters;
}

/**
 * Add a request interceptor to an axios instance that signs outgoing requests.
 * Returns the interceptor ID (can be used with `axios.interceptors.request.eject()`).
 *
 * ```ts
 * import axios from 'axios';
 * import { addSigningInterceptor } from '@zourzouvillys/httpsig/axios';
 *
 * const client = axios.create({ baseURL: 'https://api.example.com' });
 * addSigningInterceptor(client, { key: myKey });
 * ```
 */
export function addSigningInterceptor(
  instance: AxiosInstance,
  options: AxiosSigningOptions,
): number {
  const label = options.label ?? "sig1";

  return instance.interceptors.request.use(async (config) => {
    const fullUrl = buildUrl(config, instance.defaults.baseURL);
    const url = new URL(fullUrl);
    const method = (config.method ?? "GET").toUpperCase();
    const headers = config.headers ?? {};

    const msg: HttpMessage = {
      isRequest: true,
      method,
      url,
      headerValues(name: string): string[] {
        const key = name.toLowerCase();
        for (const [k, v] of Object.entries(headers)) {
          if (k.toLowerCase() === key) return [v];
        }
        return [];
      },
    };

    const params = options.params
      ? options.params(config)
      : defaultParams(options.key);

    const result = await signMessage(msg, label, params, options.key);

    config.headers = {
      ...config.headers,
      "Signature-Input": signatureInputHeader(result),
      Signature: signatureHeader(result),
    };

    return config;
  });
}

function buildUrl(config: AxiosRequestConfig, baseURL?: string): string {
  const url = config.url ?? "/";
  if (/^https?:\/\//i.test(url)) return url;
  const base = (config.baseURL ?? baseURL ?? "").replace(/\/+$/, "");
  return base + (url.startsWith("/") ? url : "/" + url);
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
