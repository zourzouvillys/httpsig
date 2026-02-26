import { describe, it, expect } from "vitest";
import {
  newSFVParams,
  sfvParamsSet,
  serializeSignatureParams,
  serializeBareItem,
  parseDictionary,
  component,
  queryParam,
  componentWithParams,
  SFVToken,
} from "../src/index.js";

describe("SFV serialization", () => {
  it("serializes empty signature params", () => {
    const result = serializeSignatureParams([], newSFVParams());
    expect(result).toBe("()");
  });

  it("serializes signature params with components and metadata", () => {
    let params = newSFVParams();
    params = sfvParamsSet(params, "created", 1618884473);
    params = sfvParamsSet(params, "keyid", "test-key");

    const result = serializeSignatureParams(
      [component("@method"), component("@path")],
      params,
    );
    expect(result).toBe(
      '("@method" "@path");created=1618884473;keyid="test-key"',
    );
  });

  it("serializes parameterized components", () => {
    let params = newSFVParams();
    params = sfvParamsSet(params, "created", 1618884473);
    params = sfvParamsSet(params, "keyid", "test-key");

    const result = serializeSignatureParams(
      [component("@authority"), queryParam("Pet")],
      params,
    );
    expect(result).toBe(
      '("@authority" "@query-param";name="Pet");created=1618884473;keyid="test-key"',
    );
  });

  it("serializes bare items", () => {
    expect(serializeBareItem(42)).toBe("42");
    expect(serializeBareItem("hello")).toBe('"hello"');
    expect(serializeBareItem(true)).toBe("?1");
    expect(serializeBareItem(false)).toBe("?0");
    expect(serializeBareItem(new SFVToken("tok"))).toBe("tok");
    expect(serializeBareItem(new Uint8Array([1, 2, 3]))).toBe(":AQID:");
  });
});

describe("SFV parsing", () => {
  it("parses a simple dictionary", () => {
    const result = parseDictionary('a=1, b="hello"');
    expect(result).toHaveLength(2);
    expect(result[0].key).toBe("a");
    expect(result[0].item?.value).toBe(1);
    expect(result[1].key).toBe("b");
    expect(result[1].item?.value).toBe("hello");
  });

  it("parses dictionary with inner list", () => {
    const result = parseDictionary(
      'sig1=("@method" "@path");created=1618884473',
    );
    expect(result).toHaveLength(1);
    expect(result[0].key).toBe("sig1");
    expect(result[0].innerList).toBeDefined();
    expect(result[0].innerList!.items).toHaveLength(2);
    expect(result[0].innerList!.items[0].value).toBe("@method");
    expect(result[0].innerList!.params?.values["created"]).toBe(1618884473);
  });

  it("parses binary values", () => {
    const result = parseDictionary("sig1=:AQID:");
    expect(result[0].item?.value).toBeInstanceOf(Uint8Array);
    const bytes = result[0].item?.value as Uint8Array;
    expect(bytes).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("parses boolean true member", () => {
    const result = parseDictionary("a, b=?0");
    expect(result[0].item?.value).toBe(true);
    expect(result[1].item?.value).toBe(false);
  });
});
