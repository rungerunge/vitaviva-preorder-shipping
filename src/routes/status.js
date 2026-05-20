// @ts-check
/**
 * GET /api/status
 *
 * Returns the current state needed by the iframe UI:
 *   • the preorder-shipping Function on this shop (or null if missing)
 *   • the delivery customizations that reference that function
 *   • any other delivery customizations (for visibility/debugging)
 *
 * Authenticated via Shopify session token (Authorization: Bearer …).
 */
import { adminGraphQL, authenticateAndExchange, AuthError } from "../lib/shopify.js";

const STATUS_QUERY = /* GraphQL */ `
  query Status {
    shopifyFunctions(first: 50) {
      nodes {
        id
        title
        apiType
        apiVersion
        app {
          title
        }
      }
    }
    deliveryCustomizations(first: 50) {
      nodes {
        id
        title
        enabled
        functionId
      }
    }
  }
`;

/**
 * @param {import("hono").Context} c
 * @param {import("../lib/shopify.js").Env} env
 */
export async function statusRoute(c, env) {
  try {
    const { shop, accessToken } = await authenticateAndExchange(c.req.raw, env);
    /** @type {{ shopifyFunctions: { nodes: any[] }, deliveryCustomizations: { nodes: any[] } }} */
    const data = await adminGraphQL(shop, accessToken, STATUS_QUERY);

    // The preorder-shipping function is the one targeting "delivery_customization".
    // We don't filter by app — the merchant might have multiple matching apps,
    // but for THIS account there's only ever the one we deployed.
    const fn =
      (data.shopifyFunctions?.nodes ?? []).find(
        (n) => n.apiType === "delivery_customization",
      ) ?? null;

    const all = data.deliveryCustomizations?.nodes ?? [];
    const ours = fn ? all.filter((d) => d.functionId === fn.id) : [];
    const other = all.filter((d) => !fn || d.functionId !== fn.id);

    return c.json(
      { shop, function: fn, customizations: ours, otherCustomizations: other },
      200,
      { "Cache-Control": "no-store" },
    );
  } catch (err) {
    return errorJson(c, err);
  }
}

/**
 * @param {import("hono").Context} c
 * @param {unknown} err
 */
function errorJson(c, err) {
  const status = err instanceof AuthError ? err.status : 500;
  const message = err instanceof Error ? err.message : String(err);
  console.error("[status] error", err);
  return c.json({ error: message }, /** @type {any} */ (status));
}
