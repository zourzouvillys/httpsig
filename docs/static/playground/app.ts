// Interactive RFC 9421 playground — sign, verify, and inspect HTTP Message
// Signatures entirely in the browser, using the project's own TypeScript library
// over the Web Crypto API. No network, no key exfiltration.

import {
  signMessage,
  signatureInputHeader,
  signatureHeader,
  buildSignatureBase,
  verifyMessage,
  buildRequestMessage,
  component,
  newWebCryptoSigningKey,
  newWebCryptoVerifyingKey,
  parseDictionary,
  serializeComponentId,
  sfvParamsGet,
  uint8ToBase64,
  type Algorithm,
  type ComponentIdentifier,
  type VerifyingKey,
  type VerifyOptions,
} from "../../../typescript/src/index.js";

// ---------------------------------------------------------------------------
// Algorithm parameter tables for Web Crypto generate / import / sign-verify.
// ---------------------------------------------------------------------------
type AlgoInfo = {
  kind: "asym" | "hmac";
  generate: any;
  import: any; // params for importKey of public/private
  hash?: string;
};
const ALGOS: Record<string, AlgoInfo> = {
  ed25519: { kind: "asym", generate: { name: "Ed25519" }, import: { name: "Ed25519" } },
  "ecdsa-p256-sha256": {
    kind: "asym",
    generate: { name: "ECDSA", namedCurve: "P-256" },
    import: { name: "ECDSA", namedCurve: "P-256" },
  },
  "rsa-pss-sha512": {
    kind: "asym",
    generate: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-512" },
    import: { name: "RSA-PSS", hash: "SHA-512" },
  },
  "hmac-sha256": { kind: "hmac", generate: { name: "HMAC", hash: "SHA-256" }, import: { name: "HMAC", hash: "SHA-256" } },
};

const subtle = globalThis.crypto.subtle;
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function parseHeaders(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    const i = t.indexOf(":");
    if (i < 0) continue;
    out.push([t.slice(0, i).trim(), t.slice(i + 1).trim()]);
  }
  return out;
}

function getHeader(headers: Array<[string, string]>, name: string): string | undefined {
  const lc = name.toLowerCase();
  for (const [n, v] of headers) if (n.toLowerCase() === lc) return v;
  return undefined;
}

function pemToDer(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
  if (!b64) throw new Error("no PEM body found");
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function derToPem(der: ArrayBuffer, label: string): string {
  const b64 = uint8ToBase64(new Uint8Array(der));
  const lines = b64.match(/.{1,64}/g)?.join("\n") ?? b64;
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function secretToBytes(secret: string, encoding: string): Uint8Array {
  if (encoding === "base64") {
    const bin = atob(secret.trim());
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }
  return enc.encode(secret);
}

async function contentDigestHeader(body: string): Promise<string> {
  const hash = await subtle.digest("SHA-256", enc.encode(body));
  return `sha-256=:${uint8ToBase64(new Uint8Array(hash))}:`;
}

// RFC 9530: recompute Content-Digest over the body and compare to the header.
// Returns null when there is no Content-Digest header (check not applicable).
async function digestMatchesBody(
  headers: Array<[string, string]>,
  body: string,
): Promise<boolean | null> {
  const cd = getHeader(headers, "content-digest");
  if (!cd) return null;
  const ALG: Record<string, string> = { "sha-256": "SHA-256", "sha-512": "SHA-512" };
  let checked = false;
  for (const entry of cd.split(",")) {
    const m = entry.trim().match(/^(sha-256|sha-512)=:(.*):$/);
    if (!m || !ALG[m[1]]) continue;
    checked = true;
    const h = await subtle.digest(ALG[m[1]], enc.encode(body));
    if (uint8ToBase64(new Uint8Array(h)) !== m[2]) return false;
  }
  return checked ? true : null;
}

function importHmac(secret: Uint8Array, info: AlgoInfo): Promise<CryptoKey> {
  return subtle.importKey("raw", secret, info.import, false, ["sign", "verify"]);
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
document.querySelectorAll<HTMLButtonElement>(".pg-tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    const name = tab.dataset.tab!;
    document.querySelectorAll(".pg-tab").forEach((t) => t.classList.toggle("active", t === tab));
    document.querySelectorAll(".pg-panel").forEach((p) =>
      p.classList.toggle("active", p.id === `panel-${name}`),
    );
  });
});

// Show/hide key-source blocks driven by a radio group.
function wireKeySource(radioName: string, map: Record<string, string>) {
  const radios = document.querySelectorAll<HTMLInputElement>(`input[name="${radioName}"]`);
  const update = () => {
    let selected = "";
    radios.forEach((r) => {
      if (r.checked) selected = r.value;
    });
    for (const [val, id] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el) el.hidden = val !== selected;
    }
  };
  radios.forEach((r) => r.addEventListener("change", update));
  update();
}
wireKeySource("s-keysrc", { generate: "s-key-generate", pem: "s-key-pem", hmac: "s-key-hmac" });
wireKeySource("v-keysrc", { pem: "v-key-pem", hmac: "v-key-hmac" });

function radioValue(name: string): string {
  const r = document.querySelector<HTMLInputElement>(`input[name="${name}"]:checked`);
  return r ? r.value : "";
}

// ===========================================================================
// SIGN
// ===========================================================================
const DERIVED = ["@method", "@target-uri", "@authority", "@scheme", "@path", "@query"];
const DEFAULT_COMPONENTS = new Set(["@method", "@authority", "@path", "content-digest"]);

// Carry generated material to the Verify tab.
let signedTransfer:
  | { method: string; url: string; body: string; headersText: string; algo: string; keyKind: "pem" | "hmac" | "none"; publicPem?: string; secret?: string; secretEnc?: string }
  | null = null;

// Cache of a generated keypair for the current algorithm.
let generated: { algo: string; privateKey: CryptoKey; publicPem?: string; secret?: string; secretEnc?: string } | null = null;

function rebuildComponentChecks() {
  const container = $("s-components");
  const headers = parseHeaders(($("s-headers") as HTMLTextAreaElement).value);
  const headerNames = [...new Set(headers.map((h) => h[0].toLowerCase()))];
  const items = [...DERIVED, ...headerNames];
  const prev = new Map(
    [...container.querySelectorAll<HTMLInputElement>("input")].map((i) => [i.value, i.checked]),
  );
  container.innerHTML = items
    .map((name) => {
      const checked = prev.has(name) ? prev.get(name)! : DEFAULT_COMPONENTS.has(name);
      return `<label><input type="checkbox" value="${escapeHtml(name)}" ${checked ? "checked" : ""}/> ${escapeHtml(name)}</label>`;
    })
    .join("");
}

function selectedComponents(): ComponentIdentifier[] {
  return [...$("s-components").querySelectorAll<HTMLInputElement>("input:checked")].map((i) =>
    component(i.value),
  );
}

async function buildSigningKey(algo: string, keyId: string): Promise<CryptoKey> {
  const info = ALGOS[algo];
  const src = radioValue("s-keysrc");
  if (src === "generate") {
    if (!generated || generated.algo !== algo) {
      throw new Error("Generate a key first (the algorithm changed).");
    }
    return generated.privateKey;
  }
  if (src === "hmac") {
    if (info.kind !== "hmac") throw new Error(`${algo} needs a PEM key, not an HMAC secret.`);
    const secret = secretToBytes(($("s-hmac") as HTMLInputElement).value, ($("s-hmac-enc") as HTMLSelectElement).value);
    if (!secret.length) throw new Error("Enter an HMAC secret.");
    return importHmac(secret, info);
  }
  // pem
  if (info.kind === "hmac") throw new Error("HMAC uses a shared secret, not a PEM key.");
  const pem = ($("s-pem") as HTMLTextAreaElement).value.trim();
  if (!pem) throw new Error("Paste a PKCS#8 private key PEM.");
  return subtle.importKey("pkcs8", pemToDer(pem), info.import, false, ["sign"]);
}

async function doGenerate() {
  const algo = ($("s-algo") as HTMLSelectElement).value;
  const info = ALGOS[algo];
  const out = $("s-genout");
  try {
    if (info.kind === "hmac") {
      const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
      const secretB64 = uint8ToBase64(raw);
      generated = { algo, privateKey: await importHmac(raw, info), secret: secretB64, secretEnc: "base64" };
      out.innerHTML = block("Shared secret (base64)", secretB64);
    } else {
      const pair = (await subtle.generateKey(info.generate, true, ["sign", "verify"])) as CryptoKeyPair;
      const priv = derToPem(await subtle.exportKey("pkcs8", pair.privateKey), "PRIVATE KEY");
      const pub = derToPem(await subtle.exportKey("spki", pair.publicKey), "PUBLIC KEY");
      generated = { algo, privateKey: pair.privateKey, publicPem: pub };
      out.innerHTML = block("Public key (SPKI PEM) — use this to verify", pub) + block("Private key (PKCS#8 PEM)", priv);
    }
  } catch (e: any) {
    out.innerHTML = `<p class="err-text">Could not generate ${algo}: ${escapeHtml(e.message || String(e))}. Your browser may not support this algorithm.</p>`;
  }
}

function block(label: string, value: string): string {
  return `<div class="out"><div class="out-label">${escapeHtml(label)}<button class="copy" data-copy>copy</button></div><pre>${escapeHtml(value)}</pre></div>`;
}

async function doSign() {
  const outEl = $("s-output");
  try {
    const method = ($("s-method") as HTMLSelectElement).value;
    const urlStr = ($("s-url") as HTMLInputElement).value.trim();
    const url = new URL(urlStr);
    const body = ($("s-body") as HTMLTextAreaElement).value;
    const headers = parseHeaders(($("s-headers") as HTMLTextAreaElement).value);
    const algo = ($("s-algo") as HTMLSelectElement).value as Algorithm;
    const keyId = ($("s-keyid") as HTMLInputElement).value.trim() || "test-key";
    const label = ($("s-label") as HTMLInputElement).value.trim() || "sig1";

    const components = selectedComponents();
    if (!components.length) throw new Error("Select at least one component to cover.");

    const params: any = { components, keyId };
    const nowS = Math.floor(Date.now() / 1000);
    if (($("s-created-on") as HTMLInputElement).checked) params.created = nowS;
    const expiresIn = parseInt(($("s-expires") as HTMLInputElement).value, 10);
    if (!Number.isNaN(expiresIn)) params.expires = (params.created ?? nowS) + expiresIn;
    const nonce = ($("s-nonce") as HTMLInputElement).value.trim();
    if (nonce) params.nonce = nonce;
    const tag = ($("s-tag") as HTMLInputElement).value.trim();
    if (tag) params.tag = tag;
    if (($("s-alg-on") as HTMLInputElement).checked) params.algorithm = algo;

    const cryptoKey = await buildSigningKey(algo, keyId);
    const signingKey = newWebCryptoSigningKey(keyId, cryptoKey, algo);

    const msg = buildRequestMessage(method, urlStr, headers);
    const result = await signMessage(msg, label, params, signingKey);
    const [baseBytes] = buildSignatureBase(msg, params);
    const baseStr = dec.decode(baseBytes);
    const sigInput = signatureInputHeader(result);
    const sigHeader = signatureHeader(result);

    const reqLine = `${method} ${url.pathname}${url.search} HTTP/1.1`;
    const fullReq =
      [reqLine, ...headers.map(([n, v]) => `${n}: ${v}`), `Signature-Input: ${sigInput}`, `Signature: ${sigHeader}`].join("\n") +
      "\n\n" +
      body;

    // Stash transfer data for the Verify tab.
    const src = radioValue("s-keysrc");
    const headersWithSig = `${($("s-headers") as HTMLTextAreaElement).value.trim()}\nSignature-Input: ${sigInput}\nSignature: ${sigHeader}`;
    if (src === "hmac") {
      signedTransfer = { method, url: urlStr, body, headersText: headersWithSig, algo, keyKind: "hmac", secret: ($("s-hmac") as HTMLInputElement).value, secretEnc: ($("s-hmac-enc") as HTMLSelectElement).value };
    } else if (src === "generate" && generated) {
      signedTransfer = generated.secret
        ? { method, url: urlStr, body, headersText: headersWithSig, algo, keyKind: "hmac", secret: generated.secret, secretEnc: "base64" }
        : { method, url: urlStr, body, headersText: headersWithSig, algo, keyKind: "pem", publicPem: generated.publicPem };
    } else {
      signedTransfer = { method, url: urlStr, body, headersText: headersWithSig, algo, keyKind: "none" };
    }

    outEl.innerHTML =
      block("Signature base (the signed bytes)", baseStr) +
      block("Signature-Input header", sigInput) +
      block("Signature header", sigHeader) +
      block("Full signed request", fullReq) +
      `<div class="btn-row"><button class="btn" id="s-tov">Send to Verify →</button></div>`;
    $("s-tov").addEventListener("click", sendToVerify);
    wireCopyButtons(outEl);
  } catch (e: any) {
    outEl.innerHTML = `<div class="banner fail"><span class="big">✗</span> ${escapeHtml(e.message || String(e))}</div>`;
  }
}

function sendToVerify() {
  if (!signedTransfer) return;
  const t = signedTransfer;
  ($("v-method") as HTMLSelectElement).value = t.method;
  ($("v-url") as HTMLInputElement).value = t.url;
  ($("v-body") as HTMLTextAreaElement).value = t.body;
  ($("v-headers") as HTMLTextAreaElement).value = t.headersText;
  ($("v-algo") as HTMLSelectElement).value = t.algo;
  if (t.keyKind === "hmac") {
    (document.querySelector('input[name="v-keysrc"][value="hmac"]') as HTMLInputElement).checked = true;
    ($("v-hmac") as HTMLInputElement).value = t.secret || "";
    ($("v-hmac-enc") as HTMLSelectElement).value = t.secretEnc || "base64";
  } else {
    (document.querySelector('input[name="v-keysrc"][value="pem"]') as HTMLInputElement).checked = true;
    if (t.publicPem) ($("v-pem") as HTMLTextAreaElement).value = t.publicPem;
  }
  document.querySelectorAll('input[name="v-keysrc"]').forEach((r) => r.dispatchEvent(new Event("change")));
  (document.querySelector('.pg-tab[data-tab="verify"]') as HTMLButtonElement).click();
}

// ===========================================================================
// VERIFY
// ===========================================================================
async function buildVerifyingKey(algo: string, keyId: string): Promise<VerifyingKey> {
  const info = ALGOS[algo];
  const src = radioValue("v-keysrc");
  let cryptoKey: CryptoKey;
  if (src === "hmac") {
    if (info.kind !== "hmac") throw new Error(`${algo} needs a public key PEM, not an HMAC secret.`);
    const secret = secretToBytes(($("v-hmac") as HTMLInputElement).value, ($("v-hmac-enc") as HTMLSelectElement).value);
    if (!secret.length) throw new Error("Enter the HMAC secret.");
    cryptoKey = await importHmac(secret, info);
  } else {
    if (info.kind === "hmac") throw new Error("HMAC uses a shared secret, not a PEM key.");
    const pem = ($("v-pem") as HTMLTextAreaElement).value.trim();
    if (!pem) throw new Error("Paste the signer's public key (SPKI PEM).");
    cryptoKey = await subtle.importKey("spki", pemToDer(pem), info.import, false, ["verify"]);
  }
  return newWebCryptoVerifyingKey(keyId, cryptoKey, algo as Algorithm);
}

type Row = { ok: boolean | null; label: string; detail?: string };

async function doVerify() {
  const outEl = $("v-output");
  try {
    const method = ($("v-method") as HTMLSelectElement).value;
    const urlStr = ($("v-url") as HTMLInputElement).value.trim();
    const body = ($("v-body") as HTMLTextAreaElement).value;
    const headers = parseHeaders(($("v-headers") as HTMLTextAreaElement).value);
    const algo = ($("v-algo") as HTMLSelectElement).value;

    const sigInputRaw = getHeader(headers, "signature-input");
    const sigRaw = getHeader(headers, "signature");

    const rows: Row[] = [];
    rows.push({ ok: !!sigInputRaw, label: "Signature-Input header present" });
    rows.push({ ok: !!sigRaw, label: "Signature header present" });
    if (!sigInputRaw || !sigRaw) {
      renderVerify(outEl, false, rows, null, "Missing Signature-Input or Signature header.");
      return;
    }

    // Parse the first signature label to drive the per-check breakdown.
    const inputDict = parseDictionary(sigInputRaw);
    const member = inputDict[0];
    const label = member?.key;
    const comps: ComponentIdentifier[] = (member?.innerList?.items ?? []).map((it: any) => ({
      name: String(it.value),
      params: it.params,
    }));
    const p = member?.innerList?.params;
    const created = numParam(p, "created");
    const expires = numParam(p, "expires");
    const keyid = strParam(p, "keyid") || "key";
    const algParam = strParam(p, "alg");
    const nonce = strParam(p, "nonce");
    const tag = strParam(p, "tag");

    const verifyingKey = await buildVerifyingKey(algo, keyid);

    if (algParam) {
      rows.push({
        ok: algParam === algo,
        label: "alg matches key",
        detail: `${algParam} vs ${algo}`,
      });
    }

    // Crypto check: rebuild the base from the parsed params and verify the bytes.
    const sigDict = parseDictionary(sigRaw);
    const sigBytes = sigDict.find((m: any) => m.key === label)?.item?.value as Uint8Array | undefined;
    let cryptoOk = false;
    try {
      const msg = buildRequestMessage(method, urlStr, headers);
      const sigParams: any = { components: comps, keyId: keyid };
      if (created !== undefined) sigParams.created = created;
      if (expires !== undefined) sigParams.expires = expires;
      if (nonce) sigParams.nonce = nonce;
      if (tag) sigParams.tag = tag;
      if (algParam) sigParams.algorithm = algParam;
      const [base] = buildSignatureBase(msg, sigParams);
      cryptoOk = sigBytes ? await verifyingKey.verify(base, sigBytes) : false;
    } catch (e: any) {
      rows.push({ ok: false, label: "rebuild signature base", detail: e.message });
    }
    rows.push({ ok: cryptoOk, label: "signature cryptographically valid" });

    // RFC 9530 body integrity: if Content-Digest is present, it must match the body.
    const digestOk = await digestMatchesBody(headers, body);
    if (digestOk !== null) {
      rows.push({ ok: digestOk, label: "Content-Digest matches body (RFC 9530)" });
    }

    // Time-based checks (advisory display; verifyMessage enforces them too).
    const nowS = Math.floor(Date.now() / 1000);
    const maxAge = intField("v-maxage");
    const skew = intField("v-skew");
    const rejectExpired = ($("v-rejexp") as HTMLInputElement).checked;
    if (expires !== undefined) {
      rows.push({ ok: !rejectExpired || nowS <= expires, label: "not expired", detail: `expires ${fmtTime(expires)}` });
    }
    if (created !== undefined && maxAge !== undefined) {
      rows.push({ ok: nowS - created <= maxAge, label: `within max age (${maxAge}s)`, detail: `created ${fmtTime(created)}` });
    }
    if (created !== undefined && skew !== undefined) {
      rows.push({ ok: created - nowS <= skew, label: `created not in future (skew ${skew}s)` });
    }

    // Authoritative verdict via the library.
    const opts: VerifyOptions = { rejectExpired };
    if (maxAge !== undefined) opts.maxAgeMs = maxAge * 1000;
    if (skew !== undefined) opts.maxClockSkewMs = skew * 1000;
    const provider = async () => verifyingKey;
    const msg2 = buildRequestMessage(method, urlStr, headers);

    let pass = false;
    let result: any = null;
    let errMsg: string | null = null;
    try {
      result = await verifyMessage(msg2, provider, opts);
      pass = true;
    } catch (e: any) {
      pass = false;
      errMsg = e?.name ? `${e.name}: ${e.message}` : String(e);
    }

    // A cryptographically valid signature over a Content-Digest that no longer
    // matches the body still means the message was tampered with.
    if (pass && digestOk === false) {
      pass = false;
      errMsg = "signature is valid but the body does not match the signed Content-Digest";
    }

    renderVerify(outEl, pass, rows, result || { label, keyId: keyid, algorithm: algParam, components: comps, created, expires, nonce }, errMsg);
  } catch (e: any) {
    outEl.innerHTML = `<div class="banner fail"><span class="big">✗</span> ${escapeHtml(e.message || String(e))}</div>`;
  }
}

function renderVerify(outEl: HTMLElement, pass: boolean, rows: Row[], result: any, errMsg: string | null) {
  const banner = pass
    ? `<div class="banner pass"><span class="big">✓</span> Signature verified</div>`
    : `<div class="banner fail"><span class="big">✗</span> Verification failed${errMsg ? ` — <span style="font-weight:400">${escapeHtml(errMsg)}</span>` : ""}</div>`;
  const rowsHtml = rows
    .map((r) => {
      const cls = r.ok === null ? "skip" : r.ok ? "pass" : "fail";
      const mark = r.ok === null ? "–" : r.ok ? "✓" : "✗";
      return `<li class="${cls}"><span class="mark">${mark}</span><span>${escapeHtml(r.label)}</span>${r.detail ? `<span class="det">${escapeHtml(r.detail)}</span>` : ""}</li>`;
    })
    .join("");
  let decoded = "";
  if (result) {
    decoded =
      `<div class="out"><div class="out-label">Decoded signature</div><div class="kv">` +
      kv("label", escapeHtml(String(result.label ?? "—"))) +
      kv("keyid", escapeHtml(String(result.keyId ?? "—"))) +
      kv("algorithm", escapeHtml(String(result.algorithm || "(not stated)"))) +
      kv("created", result.created ? `${Number(result.created)} · ${escapeHtml(fmtTime(Number(result.created)))}` : "—") +
      kv("expires", result.expires ? `${Number(result.expires)} · ${escapeHtml(fmtTime(Number(result.expires)))}` : "—") +
      kv("nonce", escapeHtml(String(result.nonce || "—"))) +
      kv("components", (result.components || []).map((c: any) => `<span class="cid">${escapeHtml(serializeComponentId(c))}</span>`).join("  ")) +
      `</div></div>`;
  }
  outEl.innerHTML = banner + `<ul class="checkrows">${rowsHtml}</ul>` + decoded;
}

// ===========================================================================
// INSPECT
// ===========================================================================
function doInspect() {
  const outEl = $("i-output");
  try {
    const inputRaw = ($("i-input") as HTMLTextAreaElement).value.trim();
    const sigRaw = ($("i-sig") as HTMLTextAreaElement).value.trim();
    if (!inputRaw) throw new Error("Paste a Signature-Input header value.");
    const inputDict = parseDictionary(inputRaw);
    const sigDict = sigRaw ? parseDictionary(sigRaw) : [];
    const sigMap = new Map<string, Uint8Array>();
    for (const m of sigDict as any[]) if (m.item && m.item.value instanceof Uint8Array) sigMap.set(m.key, m.item.value);

    if (!inputDict.length) throw new Error("No signatures found in Signature-Input.");

    const parts = (inputDict as any[]).map((m) => {
      const comps = (m.innerList?.items ?? []).map((it: any) =>
        serializeComponentId({ name: String(it.value), params: it.params }),
      );
      const p = m.innerList?.params;
      const sig = sigMap.get(m.key);
      const meta = [
        ["created", numParam(p, "created")],
        ["expires", numParam(p, "expires")],
        ["keyid", strParam(p, "keyid")],
        ["alg", strParam(p, "alg")],
        ["nonce", strParam(p, "nonce")],
        ["tag", strParam(p, "tag")],
      ].filter(([, v]) => v !== undefined && v !== "");

      return (
        `<div class="out"><div class="out-label">signature “${escapeHtml(m.key)}”</div><div class="kv">` +
        kv("covered components", comps.map((c: string) => `<span class="cid">${escapeHtml(c)}</span>`).join("  ") || "(none)") +
        meta.map(([k, v]) => kv(escapeHtml(String(k)), k === "created" || k === "expires" ? `${Number(v)} · ${escapeHtml(fmtTime(Number(v)))}` : escapeHtml(String(v)))).join("") +
        (sig ? kv("signature", `${sig.length} bytes · base64 ${escapeHtml(uint8ToBase64(sig))}`) : kv("signature", "(no Signature header pasted)")) +
        `</div></div>`
      );
    });
    outEl.innerHTML = parts.join("");
  } catch (e: any) {
    outEl.innerHTML = `<div class="banner fail"><span class="big">✗</span> ${escapeHtml(e.message || String(e))}</div>`;
  }
}

// ---------------------------------------------------------------------------
// Param + format utilities
// ---------------------------------------------------------------------------
function numParam(p: any, key: string): number | undefined {
  if (!p) return undefined;
  const v = sfvParamsGet(p, key);
  return typeof v === "number" ? v : undefined;
}
function strParam(p: any, key: string): string | undefined {
  if (!p) return undefined;
  const v = sfvParamsGet(p, key);
  return typeof v === "string" ? v : undefined;
}
function intField(id: string): number | undefined {
  const v = parseInt(($(id) as HTMLInputElement).value, 10);
  return Number.isNaN(v) ? undefined : v;
}
function fmtTime(unix: number): string {
  try {
    return new Date(unix * 1000).toISOString().replace(".000", "");
  } catch {
    return String(unix);
  }
}
function kv(k: string, v: string): string {
  return `<div><span class="k">${escapeHtml(k)}</span><span class="v">${v}</span></div>`;
}

function wireCopyButtons(root: HTMLElement) {
  root.querySelectorAll<HTMLButtonElement>("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const pre = btn.closest(".out")?.querySelector("pre");
      if (pre) {
        navigator.clipboard?.writeText(pre.textContent || "");
        const old = btn.textContent;
        btn.textContent = "copied!";
        setTimeout(() => (btn.textContent = old), 1200);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
$("s-headers").addEventListener("input", rebuildComponentChecks);
$("s-adddigest").addEventListener("click", async () => {
  const ta = $("s-headers") as HTMLTextAreaElement;
  const body = ($("s-body") as HTMLTextAreaElement).value;
  const digest = await contentDigestHeader(body);
  const lines = ta.value.split("\n").filter((l) => !/^content-digest:/i.test(l.trim()));
  lines.push(`Content-Digest: ${digest}`);
  ta.value = lines.join("\n").replace(/^\n+/, "");
  rebuildComponentChecks();
});
$("s-example").addEventListener("click", async () => {
  ($("s-method") as HTMLSelectElement).value = "POST";
  ($("s-url") as HTMLInputElement).value = "https://example.com/foo?param=value&pet=dog";
  ($("s-headers") as HTMLTextAreaElement).value = "Host: example.com\nContent-Type: application/json";
  ($("s-body") as HTMLTextAreaElement).value = '{"hello": "world"}';
  ($("s-adddigest") as HTMLButtonElement).click();
});
$("s-nonce-gen").addEventListener("click", () => {
  ($("s-nonce") as HTMLInputElement).value = uint8ToBase64(globalThis.crypto.getRandomValues(new Uint8Array(12)));
});
$("s-gen").addEventListener("click", doGenerate);
$("s-sign").addEventListener("click", doSign);
$("v-verify").addEventListener("click", doVerify);
$("i-go").addEventListener("click", doInspect);
$("i-example").addEventListener("click", () => {
  ($("i-input") as HTMLTextAreaElement).value =
    'sig1=("@method" "@authority" "@path" "content-digest");created=1618884473;keyid="test-key";alg="ed25519"';
  ($("i-sig") as HTMLTextAreaElement).value = "sig1=:wqJa3dHpY2Z1b3RhdGlvbnNhbXBsZXNpZ25hdHVyZWJ5dGVzZXhhbXBsZQ==:";
  doInspect();
});

// Reset the generated-key cache when the algorithm changes.
$("s-algo").addEventListener("change", () => {
  generated = null;
  $("s-genout").innerHTML = "";
});

rebuildComponentChecks();
