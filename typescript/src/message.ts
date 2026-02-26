import type { HttpMessage } from "./types.js";

/** A hand-constructed HttpMessage for testing and custom use. */
export class RawMessage implements HttpMessage {
  constructor(
    public readonly isRequest: boolean,
    public readonly method: string | undefined,
    public readonly url: URL | undefined,
    public readonly statusCode: number | undefined,
    private readonly headers: Map<string, string[]>,
  ) {}

  headerValues(name: string): string[] {
    return this.headers.get(name.toLowerCase()) ?? [];
  }
}

/** Build a RawMessage from test vector data. */
export function buildRequestMessage(
  method: string,
  urlStr: string,
  headers: Array<[string, string]>,
): RawMessage {
  const headerMap = new Map<string, string[]>();
  for (const [name, value] of headers) {
    const key = name.toLowerCase();
    const existing = headerMap.get(key) ?? [];
    existing.push(value);
    headerMap.set(key, existing);
  }
  return new RawMessage(true, method, new URL(urlStr), undefined, headerMap);
}

/** Build a RawMessage for a response. */
export function buildResponseMessage(
  statusCode: number,
  headers: Array<[string, string]>,
): RawMessage {
  const headerMap = new Map<string, string[]>();
  for (const [name, value] of headers) {
    const key = name.toLowerCase();
    const existing = headerMap.get(key) ?? [];
    existing.push(value);
    headerMap.set(key, existing);
  }
  return new RawMessage(false, undefined, undefined, statusCode, headerMap);
}
