// Browser shim for `node:crypto`, used only when bundling the httpsig library
// for the playground. The library imports `node:crypto` at module top-level for
// its Node KeyObject code paths (RSA/ECDSA/Ed25519/HMAC sign+verify, createHash,
// timingSafeEqual). The playground never exercises those paths — it uses the
// WebCrypto adapters (newWebCryptoSigningKey / newWebCryptoVerifyingKey), which
// call globalThis.crypto.subtle directly. So we only need:
//   - `webcrypto`, referenced (as a type) by the WebCrypto adapters, and
//   - throwing stubs for the Node-only functions, so an accidental call is loud
//     rather than silently wrong.

export const webcrypto = globalThis.crypto;

function nodeOnly(name) {
  return () => {
    throw new Error(
      `httpsig: node:crypto.${name}() is not available in the browser. ` +
        `Use the Web Crypto key adapters (this is a playground limitation, not the library).`,
    );
  };
}

export const createHash = nodeOnly('createHash');
export const createHmac = nodeOnly('createHmac');
export const sign = nodeOnly('sign');
export const verify = nodeOnly('verify');
export const createPublicKey = nodeOnly('createPublicKey');
export const createPrivateKey = nodeOnly('createPrivateKey');
export const timingSafeEqual = nodeOnly('timingSafeEqual');
export const constants = {};

export default {
  webcrypto,
  createHash,
  createHmac,
  sign,
  verify,
  createPublicKey,
  createPrivateKey,
  timingSafeEqual,
  constants,
};
