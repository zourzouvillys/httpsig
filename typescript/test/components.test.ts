import { describe, it, expect } from "vitest";
import {
  component,
  queryParam,
  componentReq,
  extractComponent,
} from "../src/index.js";
import type { HttpMessage } from "../src/index.js";

function makeRequest(
  method: string,
  url: string,
  headers: Record<string, string | string[]> = {},
): HttpMessage {
  const headerMap = new Map<string, string[]>();
  for (const [name, value] of Object.entries(headers)) {
    const key = name.toLowerCase();
    headerMap.set(key, Array.isArray(value) ? value : [value]);
  }
  return {
    isRequest: true,
    method,
    url: new URL(url),
    headerValues: (name: string) => headerMap.get(name.toLowerCase()) ?? [],
  };
}

describe("derived components", () => {
  const msg = makeRequest(
    "POST",
    "https://example.com/foo?param=Value&Pet=dog",
    { "content-type": "application/json" },
  );

  it("@method", () => {
    expect(extractComponent(component("@method"), msg)).toBe("POST");
  });

  it("@path", () => {
    expect(extractComponent(component("@path"), msg)).toBe("/foo");
  });

  it("@authority", () => {
    expect(extractComponent(component("@authority"), msg)).toBe("example.com");
  });

  it("@scheme", () => {
    expect(extractComponent(component("@scheme"), msg)).toBe("https");
  });

  it("@target-uri", () => {
    expect(extractComponent(component("@target-uri"), msg)).toBe(
      "https://example.com/foo?param=Value&Pet=dog",
    );
  });

  it("@request-target", () => {
    expect(extractComponent(component("@request-target"), msg)).toBe(
      "/foo?param=Value&Pet=dog",
    );
  });

  it("@query", () => {
    expect(extractComponent(component("@query"), msg)).toBe(
      "?param=Value&Pet=dog",
    );
  });

  it("@query-param", () => {
    expect(extractComponent(queryParam("Pet"), msg)).toBe("dog");
  });
});

describe("header components", () => {
  it("extracts single header", () => {
    const msg = makeRequest("GET", "https://example.com", {
      "content-type": "application/json",
    });
    expect(extractComponent(component("content-type"), msg)).toBe(
      "application/json",
    );
  });

  it("combines multi-value headers", () => {
    const msg = makeRequest("GET", "https://example.com", {
      accept: ["application/json", "*/*"],
    });
    expect(extractComponent(component("accept"), msg)).toBe(
      "application/json, */*",
    );
  });

  it("throws for missing header", () => {
    const msg = makeRequest("GET", "https://example.com");
    expect(() => extractComponent(component("x-missing"), msg)).toThrow(
      "missing component",
    );
  });
});

describe("response components", () => {
  it("@status", () => {
    const msg: HttpMessage = {
      isRequest: false,
      statusCode: 200,
      headerValues: () => [],
    };
    expect(extractComponent(component("@status"), msg)).toBe("200");
  });

  it("@method on response throws", () => {
    const msg: HttpMessage = {
      isRequest: false,
      statusCode: 200,
      headerValues: () => [],
    };
    expect(() => extractComponent(component("@method"), msg)).toThrow(
      "@method on response",
    );
  });
});
