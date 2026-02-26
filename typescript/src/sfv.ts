import type {
  SFVBareItem,
  SFVDictMember,
  SFVInnerList,
  SFVItem,
  SFVParams,
  ComponentIdentifier,
} from "./types.js";
import { SFVToken } from "./types.js";
import { MalformedInputError } from "./errors.js";

// --- SFVParams helpers ---

export function newSFVParams(): SFVParams {
  return { keys: [], values: {} };
}

export function sfvParamsSet(
  p: SFVParams,
  key: string,
  value: SFVBareItem,
): SFVParams {
  const keys = p.keys.includes(key) ? [...p.keys] : [...p.keys, key];
  return { keys, values: { ...p.values, [key]: value } };
}

export function sfvParamsGet(
  p: SFVParams,
  key: string,
): SFVBareItem | undefined {
  return p.keys.includes(key) ? p.values[key] : undefined;
}

// --- Serialization ---

export function serializeBareItem(value: SFVBareItem): string {
  if (value instanceof SFVToken) {
    return value.value;
  }
  if (value instanceof Uint8Array) {
    return ":" + uint8ToBase64(value) + ":";
  }
  if (typeof value === "string") {
    return '"' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : String(value);
  }
  if (typeof value === "boolean") {
    return value ? "?1" : "?0";
  }
  return String(value);
}

export function serializeParams(params: SFVParams | undefined): string {
  if (!params || params.keys.length === 0) return "";
  let result = "";
  for (const key of params.keys) {
    const value = params.values[key];
    result += ";" + key;
    if (value === true) continue;
    result += "=" + serializeBareItem(value);
  }
  return result;
}

export function serializeComponentId(c: ComponentIdentifier): string {
  return '"' + c.name + '"' + serializeParams(c.params);
}

export function serializeSignatureParams(
  components: ComponentIdentifier[],
  params: SFVParams,
): string {
  const items = components.map((c) => serializeComponentId(c)).join(" ");
  return "(" + items + ")" + serializeParams(params);
}

export function serializeInnerList(il: SFVInnerList): string {
  const items = il.items
    .map((item) => serializeBareItem(item.value) + serializeParams(item.params))
    .join(" ");
  return "(" + items + ")" + serializeParams(il.params);
}

export function serializeDictionary(members: SFVDictMember[]): string {
  return members
    .map((m) => {
      if (m.innerList) {
        return m.key + "=" + serializeInnerList(m.innerList);
      }
      if (m.item) {
        const val = serializeBareItem(m.item.value);
        const params = serializeParams(m.item.params);
        if (m.item.value === true) {
          return m.key + params;
        }
        return m.key + "=" + val + params;
      }
      return m.key;
    })
    .join(", ");
}

// --- Parsing ---

class SFVParser {
  private pos = 0;

  constructor(private readonly input: string) {}

  parseDictionary(): SFVDictMember[] {
    const members: SFVDictMember[] = [];
    this.skipSpaces();
    if (this.pos >= this.input.length) return members;

    members.push(this.parseDictMember());
    while (this.pos < this.input.length) {
      this.skipOWS();
      if (this.pos >= this.input.length || this.peek() !== ",") break;
      this.advance(); // skip ','
      this.skipOWS();
      if (this.pos >= this.input.length) {
        throw new MalformedInputError("trailing comma in dictionary");
      }
      members.push(this.parseDictMember());
    }
    return members;
  }

  private parseDictMember(): SFVDictMember {
    const key = this.parseKey();
    if (this.pos < this.input.length && this.peek() === "=") {
      this.advance();
      if (this.pos < this.input.length && this.peek() === "(") {
        const innerList = this.parseInnerList();
        return { key, innerList };
      }
      const item = this.parseItem();
      return { key, item };
    }
    // Boolean true member
    const params = this.parseParams();
    return { key, item: { value: true, params } };
  }

  private parseKey(): string {
    const start = this.pos;
    if (this.pos >= this.input.length || !/[a-z*]/.test(this.peek())) {
      throw new MalformedInputError(`expected key at position ${this.pos}`);
    }
    while (
      this.pos < this.input.length &&
      /[a-z0-9_\-.*]/.test(this.peek())
    ) {
      this.advance();
    }
    return this.input.slice(start, this.pos);
  }

  parseInnerList(): SFVInnerList {
    if (this.peek() !== "(") {
      throw new MalformedInputError("expected '(' for inner list");
    }
    this.advance();

    const items: SFVItem[] = [];
    while (this.pos < this.input.length) {
      this.skipSpaces();
      if (this.peek() === ")") {
        this.advance();
        const params = this.parseParams();
        return { items, params };
      }
      items.push(this.parseItem());
    }
    throw new MalformedInputError("unterminated inner list");
  }

  private parseItem(): SFVItem {
    const value = this.parseBareItem();
    const params = this.parseParams();
    return { value, params };
  }

  private parseBareItem(): SFVBareItem {
    const c = this.peek();
    if (c === '"') return this.parseString();
    if (c === ":") return this.parseBinary();
    if (c === "?") return this.parseBoolean();
    if (c === "-" || (c >= "0" && c <= "9")) return this.parseNumber();
    if (/[a-zA-Z*]/.test(c)) return this.parseToken();
    throw new MalformedInputError(`unexpected character '${c}' at ${this.pos}`);
  }

  private parseString(): string {
    this.advance(); // skip opening "
    let result = "";
    while (this.pos < this.input.length) {
      const c = this.input[this.pos];
      if (c === "\\") {
        this.advance();
        if (this.pos >= this.input.length) {
          throw new MalformedInputError("unterminated escape in string");
        }
        result += this.input[this.pos];
        this.advance();
      } else if (c === '"') {
        this.advance();
        return result;
      } else {
        result += c;
        this.advance();
      }
    }
    throw new MalformedInputError("unterminated string");
  }

  private parseBinary(): Uint8Array {
    this.advance(); // skip ':'
    const end = this.input.indexOf(":", this.pos);
    if (end < 0) {
      throw new MalformedInputError("unterminated binary");
    }
    const b64 = this.input.slice(this.pos, end);
    this.pos = end + 1;
    return base64ToUint8(b64);
  }

  private parseBoolean(): boolean {
    this.advance(); // skip '?'
    if (this.pos >= this.input.length) {
      throw new MalformedInputError("unterminated boolean");
    }
    const c = this.peek();
    this.advance();
    if (c === "1") return true;
    if (c === "0") return false;
    throw new MalformedInputError(`invalid boolean value '${c}'`);
  }

  private parseNumber(): number {
    const start = this.pos;
    if (this.peek() === "-") this.advance();
    let isFloat = false;
    while (this.pos < this.input.length && this.peek() >= "0" && this.peek() <= "9") {
      this.advance();
    }
    if (this.pos < this.input.length && this.peek() === ".") {
      isFloat = true;
      this.advance();
      while (this.pos < this.input.length && this.peek() >= "0" && this.peek() <= "9") {
        this.advance();
      }
    }
    const str = this.input.slice(start, this.pos);
    return isFloat ? parseFloat(str) : parseInt(str, 10);
  }

  private parseToken(): SFVToken {
    const start = this.pos;
    while (
      this.pos < this.input.length &&
      /[a-zA-Z0-9!#$%&'*+\-.^_`|~:/]/.test(this.peek())
    ) {
      this.advance();
    }
    return new SFVToken(this.input.slice(start, this.pos));
  }

  private parseParams(): SFVParams | undefined {
    let params: SFVParams | undefined;
    while (this.pos < this.input.length && this.peek() === ";") {
      this.advance(); // skip ';'
      this.skipSpaces();
      const key = this.parseKey();
      let value: SFVBareItem = true;
      if (this.pos < this.input.length && this.peek() === "=") {
        this.advance();
        value = this.parseBareItem();
      }
      if (!params) params = newSFVParams();
      params = sfvParamsSet(params, key, value);
    }
    return params;
  }

  private peek(): string {
    return this.input[this.pos];
  }

  private advance(): void {
    this.pos++;
  }

  private skipSpaces(): void {
    while (this.pos < this.input.length && this.input[this.pos] === " ") {
      this.pos++;
    }
  }

  private skipOWS(): void {
    while (
      this.pos < this.input.length &&
      (this.input[this.pos] === " " || this.input[this.pos] === "\t")
    ) {
      this.pos++;
    }
  }
}

export function parseDictionary(input: string): SFVDictMember[] {
  return new SFVParser(input).parseDictionary();
}

// --- Base64 helpers ---

export function uint8ToBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

export function base64ToUint8(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
