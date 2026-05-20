// @ts-check
/**
 * Hono server entrypoint — runs the embedded admin UI for the
 * preorder-shipping-combiner Shopify Function.
 *
 * Runs on Node 20+ via @hono/node-server. Same code targets Railway,
 * Render, Fly, or any other Node host. No build step.
 *
 * Routes:
 *   GET  /                    HTML iframe (App Bridge) — public
 *   GET  /api/status          current function + customizations — auth required
 *   POST /api/activate        create deliveryCustomization        — auth required
 *   POST /api/deactivate      delete deliveryCustomization        — auth required
 *   GET  /healthz             liveness probe — public
 *
 * Env:
 *   PORT                      defaults to 3000
 *   SHOPIFY_API_KEY           required — Shopify app client_id
 *   SHOPIFY_API_SECRET        required — Shopify app client_secret
 */
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { logger } from "hono/logger";
import { secureHeaders } from "hono/secure-headers";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { statusRoute } from "./routes/status.js";
import { activateRoute } from "./routes/activate.js";
import { deactivateRoute } from "./routes/deactivate.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, "..", "public");

const SHOPIFY_API_KEY = mustEnv("SHOPIFY_API_KEY");
const SHOPIFY_API_SECRET = mustEnv("SHOPIFY_API_SECRET");

const env = { SHOPIFY_API_KEY, SHOPIFY_API_SECRET };

const app = new Hono();

app.use("*", logger());

// ---------- Liveness ----------
app.get("/healthz", (c) => c.text("ok"));

// ---------- HTML shell ----------
// Serve index.html with the Shopify API key injected. We intentionally
// don't ship a build pipeline; just a string replace at request time.
let cachedHtml = /** @type {string | null} */ (null);
async function loadHtml() {
  if (cachedHtml !== null) return cachedHtml;
  const html = await readFile(join(PUBLIC_DIR, "index.html"), "utf8");
  cachedHtml = html.replaceAll("__SHOPIFY_API_KEY__", SHOPIFY_API_KEY);
  return cachedHtml;
}

app.get("/", async (c) => {
  const html = await loadHtml();
  const shop = c.req.query("shop");
  // Lock the iframe to the calling shop when known, fall back to wildcard
  // across *.myshopify.com so the modal in admin.shopify.com can also embed.
  const ancestors =
    shop && /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(shop)
      ? `https://${shop} https://admin.shopify.com`
      : `https://*.myshopify.com https://admin.shopify.com`;
  c.header("Content-Security-Policy", `frame-ancestors ${ancestors};`);
  c.header("Content-Type", "text/html; charset=utf-8");
  c.header("Cache-Control", "no-store");
  // X-Frame-Options would block embedding entirely; secureHeaders sets
  // sensible defaults but we explicitly do NOT want X-Frame-Options DENY.
  return c.body(html);
});

// ---------- API ----------
app.get("/api/status", (c) => statusRoute(c, env));
app.post("/api/activate", (c) => activateRoute(c, env));
app.post("/api/deactivate", (c) => deactivateRoute(c, env));

// ---------- Static (favicons etc.) ----------
app.get("/favicon.ico", (c) => c.body(null, 204));

// ---------- 404 ----------
app.notFound((c) => c.json({ error: "Not found" }, 404));

// ---------- Last-resort error handler ----------
app.onError((err, c) => {
  console.error("[hono] unhandled error", err);
  const status = /** @type {{ status?: number }} */ (err).status ?? 500;
  return c.json(
    { error: err.message || "Internal error" },
    /** @type {any} */ (status),
  );
});

// ---------- Boot ----------
const port = Number(process.env.PORT) || 3000;
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`vitaviva-preorder-shipping web listening on :${info.port}`);
});

/**
 * @param {string} name
 * @returns {string}
 */
function mustEnv(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`FATAL: missing env var ${name}`);
    process.exit(1);
  }
  return v;
}
