// @ts-check
/**
 * POST /api/deactivate
 *
 * Body: { id: string }
 * Hard-deletes a delivery customization. The customization is cheap to
 * recreate (one mutation away), so we don't keep disabled stragglers in
 * the merchant's admin.
 */
import { adminGraphQL, authenticateAndExchange, AuthError } from "../lib/shopify.js";

const DELETE_MUTATION = /* GraphQL */ `
  mutation DeleteCustomization($id: ID!) {
    deliveryCustomizationDelete(id: $id) {
      deletedId
      userErrors {
        field
        message
        code
      }
    }
  }
`;

/**
 * @param {import("hono").Context} c
 * @param {import("../lib/shopify.js").Env} env
 */
export async function deactivateRoute(c, env) {
  try {
    const { shop, accessToken } = await authenticateAndExchange(c.req.raw, env);
    const body = /** @type {{ id?: string }} */ (await c.req.json().catch(() => ({})));
    if (!body.id) return c.json({ error: "Missing `id` in body" }, 400);

    /** @type {{ deliveryCustomizationDelete: { deletedId: string | null, userErrors: any[] } }} */
    const data = await adminGraphQL(shop, accessToken, DELETE_MUTATION, { id: body.id });
    const result = data.deliveryCustomizationDelete;
    if (result.userErrors?.length) {
      return c.json(
        { ...result, error: result.userErrors.map((e) => e.message).join("; ") },
        400,
      );
    }
    return c.json(result);
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
  console.error("[deactivate] error", err);
  return c.json({ error: message }, /** @type {any} */ (status));
}
