// Minimal `Buffer` shim injected into the playground bundle. The httpsig library
// uses `Buffer.from(...).toString("base64")` and `Buffer.from(b64, "base64")` for
// its SFV base64 helpers; the browser has no Buffer, so esbuild's `inject` option
// rewrites the unbound global `Buffer` reference to this implementation (backed by
// the browser's btoa/atob).

function bytesToBase64(u8) {
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(String(b64).replace(/\s+/g, ''));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

export const Buffer = {
  from(input, encoding) {
    if (typeof input === 'string') {
      if (encoding === 'base64') return base64ToBytes(input);
      return new TextEncoder().encode(input);
    }
    const u8 = input instanceof Uint8Array ? input : new Uint8Array(input);
    // Return a byte array that also answers `.toString("base64")`.
    u8.toString = (enc) => (enc === 'base64' ? bytesToBase64(u8) : Array.prototype.toString.call(u8));
    return u8;
  },
};
