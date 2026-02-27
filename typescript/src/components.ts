import type { ComponentIdentifier, HttpMessage, SFVParams } from "./types.js";
import { MissingComponentError } from "./errors.js";
import {
  newSFVParams,
  sfvParamsSet,
  sfvParamsGet,
  parseDictionary,
  serializeBareItem,
  serializeInnerList,
  serializeParams,
  uint8ToBase64,
} from "./sfv.js";

/** Create a simple component identifier. */
export function component(name: string): ComponentIdentifier {
  return { name: name.toLowerCase() };
}

/** Create a component identifier with custom parameters. */
export function componentWithParams(
  name: string,
  params: SFVParams,
): ComponentIdentifier {
  return { name: name.toLowerCase(), params };
}

/** Create a @query-param component identifier. */
export function queryParam(name: string): ComponentIdentifier {
  return { name: "@query-param", params: sfvParamsSet(newSFVParams(), "name", name) };
}

/** Create a component identifier with the ;key parameter for extracting a single member from a Dictionary Structured Field header. */
export function componentWithKey(name: string, key: string): ComponentIdentifier {
  return { name: name.toLowerCase(), params: sfvParamsSet(newSFVParams(), "key", key) };
}

/** Create a component identifier with the ;req flag for response signatures. */
export function componentReq(name: string): ComponentIdentifier {
  return { name: name.toLowerCase(), params: sfvParamsSet(newSFVParams(), "req", true) };
}

/** Create a component identifier with both ;req and ;key parameters for response signatures that bind to a specific dictionary member from the request. */
export function componentReqWithKey(name: string, key: string): ComponentIdentifier {
  return { name: name.toLowerCase(), params: sfvParamsSet(sfvParamsSet(newSFVParams(), "req", true), "key", key) };
}

function hasParam(c: ComponentIdentifier, key: string): boolean {
  return c.params !== undefined && c.params.keys.includes(key);
}

function paramString(c: ComponentIdentifier, key: string): string {
  if (!c.params) return "";
  const v = sfvParamsGet(c.params, key);
  return typeof v === "string" ? v : "";
}

/** Extract a component value from a message. */
export function extractComponent(
  c: ComponentIdentifier,
  msg: HttpMessage,
  reqMsg?: HttpMessage,
): string {
  // ;req: extract from the associated request
  if (hasParam(c, "req")) {
    if (!reqMsg) {
      throw new MissingComponentError(
        `;req specified but no request message available`,
      );
    }
    const stripped: ComponentIdentifier = { name: c.name };
    if (c.params) {
      const sp = c.params.keys
        .filter((k) => k !== "req")
        .reduce(
          (p, k) => sfvParamsSet(p, k, c.params!.values[k]),
          newSFVParams(),
        );
      if (sp.keys.length > 0) stripped.params = sp;
    }
    return extractComponent(stripped, reqMsg);
  }

  if (c.name.startsWith("@")) {
    return extractDerived(c, msg);
  }
  return extractHeader(c, msg);
}

function extractDerived(c: ComponentIdentifier, msg: HttpMessage): string {
  switch (c.name) {
    case "@method":
      if (!msg.isRequest) throw new MissingComponentError("@method on response");
      return (msg.method ?? "").toUpperCase();

    case "@target-uri":
      if (!msg.isRequest) throw new MissingComponentError("@target-uri on response");
      return msg.url!.href;

    case "@authority":
      if (!msg.isRequest) throw new MissingComponentError("@authority on response");
      return extractAuthority(msg.url!);

    case "@scheme":
      if (!msg.isRequest) throw new MissingComponentError("@scheme on response");
      return msg.url!.protocol.replace(":", "").toLowerCase();

    case "@request-target":
      if (!msg.isRequest) throw new MissingComponentError("@request-target on response");
      return extractRequestTarget(msg.url!);

    case "@path":
      if (!msg.isRequest) throw new MissingComponentError("@path on response");
      return msg.url!.pathname || "/";

    case "@query":
      if (!msg.isRequest) throw new MissingComponentError("@query on response");
      return extractQuery(msg.url!);

    case "@query-param": {
      if (!msg.isRequest) throw new MissingComponentError("@query-param on response");
      const name = paramString(c, "name");
      if (!name) throw new MissingComponentError("@query-param requires ;name parameter");
      return extractQueryParam(msg.url!, name);
    }

    case "@status":
      if (msg.isRequest) throw new MissingComponentError("@status on request");
      return String(msg.statusCode ?? 0);

    default:
      throw new MissingComponentError(`unknown derived component ${c.name}`);
  }
}

function extractHeader(c: ComponentIdentifier, msg: HttpMessage): string {
  if (hasParam(c, "sf")) {
    return extractHeaderSF(c, msg);
  }
  if (hasParam(c, "bs")) {
    return extractHeaderBS(c, msg);
  }
  if (hasParam(c, "key")) {
    return extractHeaderKey(c, msg);
  }

  const values = msg.headerValues(c.name);
  if (values.length === 0) {
    throw new MissingComponentError(`header "${c.name}" not present`);
  }
  return values.map((v) => v.trim()).join(", ");
}

function extractHeaderSF(c: ComponentIdentifier, msg: HttpMessage): string {
  const values = msg.headerValues(c.name);
  if (values.length === 0) {
    throw new MissingComponentError(`header "${c.name}" not present`);
  }
  return values.map((v) => v.trim()).join(", ");
}

function extractHeaderBS(c: ComponentIdentifier, msg: HttpMessage): string {
  const values = msg.headerValues(c.name);
  if (values.length === 0) {
    throw new MissingComponentError(`header "${c.name}" not present`);
  }
  return values
    .map((v) => ":" + uint8ToBase64(new TextEncoder().encode(v.trim())) + ":")
    .join(", ");
}

function extractHeaderKey(c: ComponentIdentifier, msg: HttpMessage): string {
  const key = paramString(c, "key");
  if (!key) throw new MissingComponentError(";key parameter is empty");

  const values = msg.headerValues(c.name);
  if (values.length === 0) {
    throw new MissingComponentError(`header "${c.name}" not present`);
  }

  const combined = values.join(", ");
  const members = parseDictionary(combined);
  for (const m of members) {
    if (m.key === key) {
      if (m.innerList) return serializeInnerList(m.innerList);
      if (m.item) {
        let result = serializeBareItem(m.item.value);
        if (m.item.params && m.item.params.keys.length > 0) {
          result += serializeParams(m.item.params);
        }
        return result;
      }
    }
  }
  throw new MissingComponentError(
    `key "${key}" not found in dictionary header "${c.name}"`,
  );
}

function extractAuthority(url: URL): string {
  const host = url.hostname.toLowerCase();
  const port = url.port;
  if (!port) return host;
  // Omit default ports
  if (
    (url.protocol === "http:" && port === "80") ||
    (url.protocol === "https:" && port === "443")
  ) {
    return host;
  }
  return host + ":" + port;
}

function extractRequestTarget(url: URL): string {
  const path = url.pathname || "/";
  const search = url.search;
  return path + search;
}

function extractQuery(url: URL): string {
  // Always include the leading ?
  if (!url.search) return "?";
  return url.search;
}

function extractQueryParam(url: URL, name: string): string {
  const params = url.searchParams;
  if (!params.has(name)) {
    throw new MissingComponentError(`query parameter "${name}" not present`);
  }
  return params.get(name)!;
}
