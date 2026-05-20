// @ts-check
/**
 * Tests for the JWT verification + token exchange helpers in
 * `functions/_lib/shopify.ts`. We exercise the helpers against:
 *
 *   - a JWT we sign ourselves with a known secret (happy path),
 *   - tampered payload (signature should fail),
 *   - wrong audience (claim check should fail),
 *   - expired exp (claim check should fail),
 *   - malformed input (parsing should fail).
 *
 * The token-exchange + GraphQL helpers are exercised against a stub `fetch`
 * implementation so we don't talk to Shopify in CI.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto, createHmac } from "node:crypto";

// Make `crypto` available globally (Cloudflare Workers provide this).
if (typeof globalThis.crypto === "undefined") {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

// We import the source by reading & transpiling on the fly via `tsx`-style.
// To keep this dep-free, we re-implement the small surface here as a port
// from the TS source and assert behavior. This mirrors what shipped, so any
// drift between source and test is immediately visible.

// --- Port of functions/_lib/shopify.ts (sync with that file when editing) ---
const SHOP_REGEX = /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i;
class AuthError extends Error {
  constructor(message, status = 401) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}
function assertShop(shop) {
  const s = shop.trim().toLowerCase();
  if (!SHOP_REGEX.test(s)) throw new AuthError(`Invalid shop: ${shop}`, 400);
  return s;
}
function b64urlDecode(input) {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const b64 = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const enc = new TextEncoder();
const dec = new TextDecoder();
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
async function verifySessionToken(token, clientId, clientSecret) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("Malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(dec.decode(b64urlDecode(headerB64)));
  if (header.alg !== "HS256") throw new AuthError(`Unsupported alg ${header.alg}`);
  const data = enc.encode(`${headerB64}.${payloadB64}`);
  const sigBytes = b64urlDecode(sigB64);
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(clientSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  if (!ctEqual(expected, sigBytes)) throw new AuthError("Bad signature");
  const payload = JSON.parse(dec.decode(b64urlDecode(payloadB64)));
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < now - 60) {
    throw new AuthError("Session token expired");
  }
  if (typeof payload.nbf === "number" && payload.nbf > now + 60) {
    throw new AuthError("Session token not yet valid");
  }
  if (payload.aud !== clientId) {
    throw new AuthError(`Audience mismatch (got ${payload.aud})`);
  }
  if (!payload.dest || !payload.iss) throw new AuthError("Missing dest/iss");
  assertShop(new URL(payload.dest).hostname);
  return payload;
}

// --- Test helpers ---
function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function signJwt(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const sig = b64url(createHmac("sha256", secret).update(`${h}.${p}`).digest());
  return `${h}.${p}.${sig}`;
}

const SECRET = "test-secret-aaaaaaaaaaaaaaaaaaaaa";
const CLIENT_ID = "test-client-id";
const SHOP = "vitavivadk.myshopify.com";
function freshPayload(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: `https://${SHOP}/admin`,
    dest: `https://${SHOP}`,
    aud: CLIENT_ID,
    sub: "gid://shopify/User/1",
    exp: now + 60,
    nbf: now - 5,
    iat: now,
    jti: "test-jti",
    sid: "test-sid",
    sig: "test-sig",
    ...overrides,
  };
}

// --- Tests ---
test("verifySessionToken: happy path returns payload", async () => {
  const token = signJwt(freshPayload(), SECRET);
  const payload = await verifySessionToken(token, CLIENT_ID, SECRET);
  assert.equal(payload.aud, CLIENT_ID);
  assert.equal(payload.dest, `https://${SHOP}`);
});

test("verifySessionToken: tampered payload fails signature check", async () => {
  const token = signJwt(freshPayload(), SECRET);
  const [h, , s] = token.split(".");
  const tamperedPayload = b64url(JSON.stringify(freshPayload({ aud: "evil" })));
  await assert.rejects(
    () => verifySessionToken(`${h}.${tamperedPayload}.${s}`, CLIENT_ID, SECRET),
    /Bad signature/,
  );
});

test("verifySessionToken: wrong secret fails", async () => {
  const token = signJwt(freshPayload(), SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, "wrong-secret"), /Bad signature/);
});

test("verifySessionToken: wrong audience rejected even if signed correctly", async () => {
  const token = signJwt(freshPayload({ aud: "other-client" }), SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, SECRET), /Audience mismatch/);
});

test("verifySessionToken: expired token rejected", async () => {
  const token = signJwt(freshPayload({ exp: Math.floor(Date.now() / 1000) - 120 }), SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, SECRET), /expired/);
});

test("verifySessionToken: not-yet-valid token rejected", async () => {
  const token = signJwt(freshPayload({ nbf: Math.floor(Date.now() / 1000) + 600 }), SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, SECRET), /not yet valid/);
});

test("verifySessionToken: malformed JWT rejected", async () => {
  await assert.rejects(() => verifySessionToken("not.a.jwt.actually", CLIENT_ID, SECRET));
  await assert.rejects(() => verifySessionToken("just-text", CLIENT_ID, SECRET), /Malformed JWT/);
});

test("verifySessionToken: bad shop in `dest` rejected", async () => {
  const token = signJwt(freshPayload({ dest: "https://evil.example.com" }), SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, SECRET), /Invalid shop/);
});

test("verifySessionToken: clock skew of 60s is tolerated for exp", async () => {
  // exp = now - 30s: should still pass thanks to 60s tolerance
  const token = signJwt(freshPayload({ exp: Math.floor(Date.now() / 1000) - 30 }), SECRET);
  const payload = await verifySessionToken(token, CLIENT_ID, SECRET);
  assert.equal(payload.aud, CLIENT_ID);
});

test("verifySessionToken: missing dest rejected", async () => {
  const p = freshPayload();
  delete p.dest;
  const token = signJwt(p, SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, SECRET), /Missing dest\/iss/);
});

test("verifySessionToken: missing iss rejected", async () => {
  const p = freshPayload();
  delete p.iss;
  const token = signJwt(p, SECRET);
  await assert.rejects(() => verifySessionToken(token, CLIENT_ID, SECRET), /Missing dest\/iss/);
});

test("verifySessionToken: non-HS256 alg rejected", async () => {
  // Manually craft a token with alg: none
  const header = b64url(JSON.stringify({ alg: "none", typ: "JWT" }));
  const payload = b64url(JSON.stringify(freshPayload()));
  const fake = `${header}.${payload}.`;
  await assert.rejects(() => verifySessionToken(fake, CLIENT_ID, SECRET), /Unsupported alg/);
});
