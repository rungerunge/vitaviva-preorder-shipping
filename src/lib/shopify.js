// @ts-check
/**
 * Shopify auth helpers — JWT verification, token exchange, and a thin
 * Admin GraphQL client. Pure Web-Platform APIs (`crypto.subtle`, `fetch`,
 * `TextEncoder`, `Request`/`Response`), so this module works unchanged on
 * Node 20+, Cloudflare Workers, Deno, or Bun.
 *
 * Token-exchange flow:
 *   1. App Bridge in the iframe issues a session token (HS256 JWT signed
 *      with the app's `SHOPIFY_API_SECRET`). It arrives here as
 *      `Authorization: Bearer ...`.
 *   2. We HMAC-verify the JWT, extract the `dest` shop from claims.
 *   3. We POST that same session token to
 *      `https://{shop}/admin/oauth/access_token` with
 *      `grant_type = urn:ietf:params:oauth:grant-type:token-exchange`
 *      to receive a real Admin API access token.
 *   4. Use that token to call any Admin GraphQL endpoint — including
 *      `deliveryCustomizationCreate`, which requires the calling app to
 *      own the function being attached.
 *
 * Docs:
 *   https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens/token-exchange
 */

const SHOP_REGEX = /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i;
const SHOPIFY_API_VERSION = "2024-10";

export class AuthError extends Error {
  /**
   * @param {string} message
   * @param {number} status
   */
  constructor(message, status = 401) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

/**
 * @param {string} shop
 * @returns {string}
 */
function assertShop(shop) {
  const s = String(shop || "")
    .trim()
    .toLowerCase();
  if (!SHOP_REGEX.test(s)) throw new AuthError(`Invalid shop domain: ${shop}`, 400);
  return s;
}

/**
 * @param {string} input
 * @returns {Uint8Array}
 */
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

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Convert a Uint8Array into a fresh ArrayBuffer-backed view. The DOM types
 * for crypto.subtle.* refuse Uint8Array<ArrayBufferLike> in strict mode.
 *
 * @param {Uint8Array} bytes
 * @returns {ArrayBuffer}
 */
function toBufferSource(bytes) {
  return /** @type {ArrayBuffer} */ (bytes.slice().buffer);
}

/**
 * @typedef {object} SessionPayload
 * @property {string} iss
 * @property {string} dest
 * @property {string} aud
 * @property {string} sub
 * @property {number} exp
 * @property {number} [nbf]
 * @property {number} iat
 * @property {string} jti
 * @property {string} sid
 * @property {string} [sig]
 */

/**
 * Verify a Shopify session-token (HS256 JWT). Throws AuthError on any
 * failure. Validates expiry, audience, and shop shape.
 *
 * @param {string} token
 * @param {string} clientId
 * @param {string} clientSecret
 * @returns {Promise<SessionPayload>}
 */
export async function verifySessionToken(token, clientId, clientSecret) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("Malformed JWT");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(dec.decode(b64urlDecode(headerB64)));
  if (header.alg !== "HS256") throw new AuthError(`Unsupported alg ${header.alg}`);

  const data = toBufferSource(enc.encode(`${headerB64}.${payloadB64}`));
  const sigBytes = b64urlDecode(sigB64);
  const key = await crypto.subtle.importKey(
    "raw",
    toBufferSource(enc.encode(clientSecret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  if (!ctEqual(expected, sigBytes)) throw new AuthError("Bad signature");

  const payload = /** @type {SessionPayload} */ (
    JSON.parse(dec.decode(b64urlDecode(payloadB64)))
  );
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
  if (!payload.dest || !payload.iss) throw new AuthError("Missing dest/iss in payload");
  assertShop(new URL(payload.dest).hostname);
  return payload;
}

/**
 * @param {SessionPayload} payload
 * @returns {string}
 */
export function shopFromPayload(payload) {
  return assertShop(new URL(payload.dest).hostname);
}

/**
 * Exchange a session token for an offline Admin API access token.
 *
 * @param {string} shop
 * @param {string} sessionToken
 * @param {string} clientId
 * @param {string} clientSecret
 * @param {"offline" | "online"} [type]
 * @returns {Promise<{ access_token: string; scope: string }>}
 */
export async function exchangeToken(
  shop,
  sessionToken,
  clientId,
  clientSecret,
  type = "offline",
) {
  const url = `https://${shop}/admin/oauth/access_token`;
  const body = {
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: sessionToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    requested_token_type:
      type === "offline"
        ? "urn:shopify:params:oauth:token-type:offline-access-token"
        : "urn:shopify:params:oauth:token-type:online-access-token",
  };
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new AuthError(`Token exchange failed (${res.status}): ${text}`, 502);
  }
  return /** @type {Promise<{ access_token: string; scope: string }>} */ (res.json());
}

/**
 * @typedef {object} Env
 * @property {string} SHOPIFY_API_KEY
 * @property {string} SHOPIFY_API_SECRET
 */

/**
 * High-level helper: extract bearer token from a Request, verify it,
 * exchange it for an access token, and return both the shop and token.
 *
 * @param {Request | { headers: Headers | { get(name: string): string | null } }} request
 * @param {Env} env
 * @returns {Promise<{ shop: string; accessToken: string; payload: SessionPayload }>}
 */
export async function authenticateAndExchange(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(auth);
  if (!match) throw new AuthError("Missing Bearer token");
  const sessionToken = match[1];

  const payload = await verifySessionToken(
    sessionToken,
    env.SHOPIFY_API_KEY,
    env.SHOPIFY_API_SECRET,
  );
  const shop = shopFromPayload(payload);
  const { access_token } = await exchangeToken(
    shop,
    sessionToken,
    env.SHOPIFY_API_KEY,
    env.SHOPIFY_API_SECRET,
  );
  return { shop, accessToken: access_token, payload };
}

/**
 * Thin Admin GraphQL client. Throws on HTTP errors and on GraphQL `errors`.
 *
 * @template T
 * @param {string} shop
 * @param {string} accessToken
 * @param {string} query
 * @param {Record<string, unknown>} [variables]
 * @returns {Promise<T>}
 */
export async function adminGraphQL(shop, accessToken, query, variables) {
  const url = `https://${shop}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new AuthError(`Admin GraphQL failed (${res.status}): ${text}`, 502);
  }
  const json = /** @type {{ data?: T; errors?: unknown }} */ (await res.json());
  if (json.errors) {
    throw new AuthError(`Admin GraphQL errors: ${JSON.stringify(json.errors)}`, 502);
  }
  return /** @type {T} */ (json.data);
}
