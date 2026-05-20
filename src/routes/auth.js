// @ts-check
/**
 * /auth and /auth/callback — minimum OAuth install flow.
 *
 * Why is this here?
 *   Custom Shopify apps installed via the Partner dashboard normally use
 *   Token Exchange (no OAuth callback). But that only works once an
 *   install already exists. After an uninstall, the FIRST re-install
 *   still needs a one-time OAuth dance to mint a new access grant on the
 *   merchant's store.
 *
 *   We keep this surface minimal — it does not persist tokens or sessions
 *   on disk; the install simply registers the app on the shop and lets
 *   future Token Exchange calls succeed. After OAuth completes we
 *   redirect the merchant straight into the admin's app page so they can
 *   activate the customization in one click.
 */
import { createHmac, randomBytes } from "node:crypto";

const SHOPIFY_SCOPES = "write_delivery_customizations,read_delivery_customizations";
const SHOP_REGEX = /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i;

/**
 * @param {string} shop
 * @returns {string}
 */
function assertShop(shop) {
  const s = String(shop || "")
    .trim()
    .toLowerCase();
  if (!SHOP_REGEX.test(s)) throw new Error(`Invalid shop domain: ${shop}`);
  return s;
}

/**
 * Verify the `hmac` query param from Shopify's OAuth callback. The HMAC
 * is computed over the rest of the query string, sorted alphabetically
 * by key, signed with the app's client_secret.
 *
 * @param {URLSearchParams} params
 * @param {string} secret
 * @returns {boolean}
 */
function verifyHmac(params, secret) {
  const provided = params.get("hmac");
  if (!provided) return false;
  const filtered = [];
  for (const [k, v] of params.entries()) {
    if (k === "hmac" || k === "signature") continue;
    filtered.push([k, v]);
  }
  filtered.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const message = filtered.map(([k, v]) => `${k}=${v}`).join("&");
  const computed = createHmac("sha256", secret).update(message).digest("hex");
  return timingSafeEqualHex(provided, computed);
}

/**
 * Constant-time string comparison for hex digests.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * GET /auth?shop={shop}
 *
 * Kicks off Shopify OAuth. Generates a CSRF state, builds the authorize
 * URL, and redirects the browser there. Shopify shows the merchant the
 * scopes consent screen, then calls /auth/callback.
 *
 * @param {import("hono").Context} c
 * @param {import("../lib/shopify.js").Env} env
 */
export function authStart(c, env) {
  const shop = c.req.query("shop");
  if (!shop) return c.text("Missing ?shop= query param", 400);
  let cleanShop;
  try {
    cleanShop = assertShop(shop);
  } catch (e) {
    return c.text(`Invalid shop: ${e instanceof Error ? e.message : String(e)}`, 400);
  }

  const state = randomBytes(16).toString("hex");
  const redirectUri = `${selfBaseUrl(c)}/auth/callback`;
  const params = new URLSearchParams({
    client_id: env.SHOPIFY_API_KEY,
    scope: SHOPIFY_SCOPES,
    redirect_uri: redirectUri,
    state,
  });
  // Set a short-lived cookie so we can validate `state` in the callback.
  c.header("Set-Cookie", `shopify_oauth_state=${state}; Max-Age=600; Path=/; HttpOnly; SameSite=Lax; Secure`);
  return c.redirect(`https://${cleanShop}/admin/oauth/authorize?${params.toString()}`);
}

/**
 * GET /auth/callback?code=…&shop=…&state=…&hmac=…
 *
 * 1. Verify HMAC + state.
 * 2. Exchange code for an access token (token will be stored by Shopify
 *    automatically for future Token Exchange calls).
 * 3. Redirect the merchant to the admin's app page so they can activate
 *    the customization.
 *
 * @param {import("hono").Context} c
 * @param {import("../lib/shopify.js").Env} env
 */
export async function authCallback(c, env) {
  const url = new URL(c.req.url);
  const params = url.searchParams;
  const code = params.get("code");
  const shop = params.get("shop");
  const state = params.get("state");
  if (!code || !shop || !state) {
    return c.text("Missing code/shop/state", 400);
  }
  let cleanShop;
  try {
    cleanShop = assertShop(shop);
  } catch (e) {
    return c.text(`Invalid shop: ${e instanceof Error ? e.message : String(e)}`, 400);
  }

  // CSRF: state cookie must match `state` query param.
  const cookieHeader = c.req.header("Cookie") || "";
  const cookieMatch = /(?:^|;\s*)shopify_oauth_state=([a-z0-9]+)/i.exec(cookieHeader);
  const expectedState = cookieMatch?.[1];
  if (!expectedState || expectedState !== state) {
    return c.text("State mismatch (possible CSRF)", 403);
  }

  if (!verifyHmac(params, env.SHOPIFY_API_SECRET)) {
    return c.text("HMAC verification failed", 401);
  }

  // Exchange code for access token. We don't need to keep the token —
  // Shopify stores it on its side for the app, and we use Token Exchange
  // on subsequent /api/* calls.
  const tokenRes = await fetch(`https://${cleanShop}/admin/oauth/access_token`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: env.SHOPIFY_API_KEY,
      client_secret: env.SHOPIFY_API_SECRET,
      code,
    }),
  });
  if (!tokenRes.ok) {
    const errText = await tokenRes.text();
    return c.text(`Token exchange failed (${tokenRes.status}): ${errText}`, 502);
  }

  // Clear the state cookie.
  c.header("Set-Cookie", "shopify_oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure");

  // Redirect into the admin app page so the merchant can immediately
  // activate the customization. The query string includes shop so App
  // Bridge can bootstrap.
  const adminUrl = `https://admin.shopify.com/store/${cleanShop.replace(".myshopify.com", "")}/apps/${env.SHOPIFY_API_KEY}`;
  return c.redirect(adminUrl);
}

/**
 * Compute the public base URL of this server using the incoming Host header
 * and X-Forwarded-Proto when present. Railway's edge terminates TLS, so
 * `c.req.url` reports the INTERNAL http:// scheme — using that directly
 * leaks an `http://...` redirect_uri to Shopify and OAuth rejects it as
 * not-whitelisted. We trust X-Forwarded-Proto (set by Railway's edge),
 * falling back to https when running behind a known cloud host.
 *
 * @param {import("hono").Context} c
 * @returns {string}
 */
function selfBaseUrl(c) {
  const url = new URL(c.req.url);
  const xfProto = c.req.header("x-forwarded-proto");
  const host = c.req.header("x-forwarded-host") || url.host;
  // Default to https unless we explicitly see http on the forwarded proto.
  let proto = "https";
  if (xfProto) {
    proto = xfProto.split(",")[0].trim() || "https";
  } else if (url.protocol === "http:" && /^(localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(host)) {
    proto = "http";
  }
  return `${proto}://${host}`;
}
