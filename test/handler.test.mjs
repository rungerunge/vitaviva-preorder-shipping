// @ts-check
/**
 * Integration-style tests for the Pages Function HTTP handlers. We stub
 * `fetch` so the handlers think they're talking to Shopify, then assert that:
 *
 *   - the handler authenticates via session token & token exchange,
 *   - dispatches the right GraphQL queries/mutations,
 *   - returns the expected JSON shape to the browser.
 *
 * Because the handlers are TypeScript and the Cloudflare-specific globals
 * don't exist in Node, this test file does a tiny "fake handler" that mirrors
 * the production logic. The production handlers are not directly imported —
 * see test/shopify.test.mjs for documentation of the same pattern.
 *
 * This means we test the BEHAVIOR (auth gate + GraphQL choreography), not
 * the literal code. The README explains how to also smoke-test the live
 * worker via `wrangler pages dev`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto, createHmac } from "node:crypto";

if (typeof globalThis.crypto === "undefined") {
  // @ts-ignore
  globalThis.crypto = webcrypto;
}

const SECRET = "test-secret-aaaaaaaaaaaaaaaaaaaaa";
const CLIENT_ID = "test-client-id";
const SHOP = "vitavivadk.myshopify.com";

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function signJwt(payload, secret) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const p = b64url(JSON.stringify(payload));
  const sig = b64url(createHmac("sha256", secret).update(`${header}.${p}`).digest());
  return `${header}.${p}.${sig}`;
}
function freshSessionToken() {
  const now = Math.floor(Date.now() / 1000);
  return signJwt(
    {
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
    },
    SECRET,
  );
}

/**
 * Build a stub `fetch` that responds to the URLs the handlers will call.
 * Each entry: { match: (req) => bool, respond: (req) => Response | Promise<Response> }
 */
function stubFetch(routes) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const req = { url, method: init.method || "GET", body: init.body, headers: init.headers || {} };
    calls.push(req);
    for (const r of routes) if (r.match(req)) return r.respond(req);
    throw new Error(`stub fetch: no route matched ${req.method} ${url}`);
  };
  return { fetch: fn, calls };
}

const RESP_OK = (json) =>
  new Response(JSON.stringify(json), { status: 200, headers: { "Content-Type": "application/json" } });

// Simulate the handler choreography:
//   1. Verify session token (same code as shopify.test.mjs covers).
//   2. Token-exchange the session token for an access token.
//   3. Call Admin GraphQL.
async function simulateActivate({ fetchImpl, request }) {
  // Auth check (simplified — full version in shopify.test.mjs).
  const auth = request.headers.get("Authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return new Response(JSON.stringify({ error: "Missing Bearer" }), { status: 401 });
  const token = m[1];
  const parts = token.split(".");
  if (parts.length !== 3) {
    return new Response(JSON.stringify({ error: "Malformed JWT" }), { status: 401 });
  }

  // Token exchange.
  const exch = await fetchImpl(`https://${SHOP}/admin/oauth/access_token`, {
    method: "POST",
    body: JSON.stringify({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: token,
    }),
    headers: { "Content-Type": "application/json" },
  });
  if (!exch.ok) {
    return new Response(JSON.stringify({ error: "Token exchange failed" }), { status: 502 });
  }
  const { access_token } = await exch.json();

  // Lookup function.
  const lookup = await fetchImpl(`https://${SHOP}/admin/api/2024-10/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": access_token,
    },
    body: JSON.stringify({ query: "{ shopifyFunctions { nodes { id apiType } } deliveryCustomizations { nodes { id functionId } } }" }),
  });
  const lookupJson = await lookup.json();
  const fn = lookupJson.data.shopifyFunctions.nodes.find((f) => f.apiType === "delivery_customization");
  if (!fn) return new Response(JSON.stringify({ error: "No function found" }), { status: 404 });

  const existing = lookupJson.data.deliveryCustomizations.nodes.find((c) => c.functionId === fn.id);
  if (existing) {
    return new Response(JSON.stringify({ deliveryCustomization: existing, idempotent: true }), {
      status: 200,
    });
  }

  // Create.
  const create = await fetchImpl(`https://${SHOP}/admin/api/2024-10/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": access_token,
    },
    body: JSON.stringify({
      query: "mutation { deliveryCustomizationCreate(...) { ... } }",
      variables: { input: { title: "Pre-order shipping visibility", enabled: true, functionId: fn.id } },
    }),
  });
  const createJson = await create.json();
  return new Response(JSON.stringify(createJson.data.deliveryCustomizationCreate), { status: 200 });
}

test("activate: rejects request without bearer token", async () => {
  const stub = stubFetch([]);
  const req = new Request("https://app/api/activate", { method: "POST" });
  const resp = await simulateActivate({ fetchImpl: stub.fetch, request: req });
  assert.equal(resp.status, 401);
  const body = await resp.json();
  assert.match(body.error, /Bearer/);
});

test("activate: rejects malformed bearer", async () => {
  const stub = stubFetch([]);
  const req = new Request("https://app/api/activate", {
    method: "POST",
    headers: { Authorization: "Bearer not-a-jwt" },
  });
  const resp = await simulateActivate({ fetchImpl: stub.fetch, request: req });
  assert.equal(resp.status, 401);
});

test("activate: token exchange failure surfaces as 502", async () => {
  const stub = stubFetch([
    {
      match: (r) => r.url.endsWith("/admin/oauth/access_token"),
      respond: () => new Response("invalid_grant", { status: 400 }),
    },
  ]);
  const req = new Request("https://app/api/activate", {
    method: "POST",
    headers: { Authorization: `Bearer ${freshSessionToken()}` },
  });
  const resp = await simulateActivate({ fetchImpl: stub.fetch, request: req });
  assert.equal(resp.status, 502);
});

test("activate: idempotent when customization already exists", async () => {
  const fnId = "gid://shopify/ShopifyFunction/abc";
  const existing = { id: "gid://shopify/DeliveryCustomization/1", functionId: fnId };
  const stub = stubFetch([
    {
      match: (r) => r.url.endsWith("/admin/oauth/access_token"),
      respond: () => RESP_OK({ access_token: "shpat_test", scope: "write_delivery_customizations" }),
    },
    {
      match: (r) =>
        r.url.endsWith("/admin/api/2024-10/graphql.json") && r.body?.includes("shopifyFunctions"),
      respond: () =>
        RESP_OK({
          data: {
            shopifyFunctions: { nodes: [{ id: fnId, apiType: "delivery_customization" }] },
            deliveryCustomizations: { nodes: [existing] },
          },
        }),
    },
  ]);
  const req = new Request("https://app/api/activate", {
    method: "POST",
    headers: { Authorization: `Bearer ${freshSessionToken()}` },
  });
  const resp = await simulateActivate({ fetchImpl: stub.fetch, request: req });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.idempotent, true);
  assert.equal(body.deliveryCustomization.id, existing.id);
  // Critically: we should NOT have called the create mutation.
  const createCalls = stub.calls.filter((c) => c.body?.includes("deliveryCustomizationCreate"));
  assert.equal(createCalls.length, 0);
});

test("activate: creates a customization when none exists", async () => {
  const fnId = "gid://shopify/ShopifyFunction/abc";
  const created = { id: "gid://shopify/DeliveryCustomization/new", functionId: fnId };
  const stub = stubFetch([
    {
      match: (r) => r.url.endsWith("/admin/oauth/access_token"),
      respond: () => RESP_OK({ access_token: "shpat_test", scope: "write_delivery_customizations" }),
    },
    {
      match: (r) =>
        r.url.endsWith("/admin/api/2024-10/graphql.json") &&
        r.body?.includes("shopifyFunctions"),
      respond: () =>
        RESP_OK({
          data: {
            shopifyFunctions: { nodes: [{ id: fnId, apiType: "delivery_customization" }] },
            deliveryCustomizations: { nodes: [] },
          },
        }),
    },
    {
      match: (r) =>
        r.url.endsWith("/admin/api/2024-10/graphql.json") &&
        r.body?.includes("deliveryCustomizationCreate"),
      respond: () =>
        RESP_OK({
          data: {
            deliveryCustomizationCreate: {
              deliveryCustomization: created,
              userErrors: [],
            },
          },
        }),
    },
  ]);
  const req = new Request("https://app/api/activate", {
    method: "POST",
    headers: { Authorization: `Bearer ${freshSessionToken()}` },
  });
  const resp = await simulateActivate({ fetchImpl: stub.fetch, request: req });
  assert.equal(resp.status, 200);
  const body = await resp.json();
  assert.equal(body.deliveryCustomization.id, created.id);
  const createCalls = stub.calls.filter((c) => c.body?.includes("deliveryCustomizationCreate"));
  assert.equal(createCalls.length, 1);
});

test("activate: returns 404 when no function is deployed", async () => {
  const stub = stubFetch([
    {
      match: (r) => r.url.endsWith("/admin/oauth/access_token"),
      respond: () => RESP_OK({ access_token: "shpat_test", scope: "write_delivery_customizations" }),
    },
    {
      match: (r) => r.url.endsWith("/admin/api/2024-10/graphql.json"),
      respond: () =>
        RESP_OK({
          data: {
            shopifyFunctions: { nodes: [{ id: "x", apiType: "discount" }] },
            deliveryCustomizations: { nodes: [] },
          },
        }),
    },
  ]);
  const req = new Request("https://app/api/activate", {
    method: "POST",
    headers: { Authorization: `Bearer ${freshSessionToken()}` },
  });
  const resp = await simulateActivate({ fetchImpl: stub.fetch, request: req });
  assert.equal(resp.status, 404);
});
