// @ts-check
/**
 * POST /api/activate
 *
 * Body: { title?: string }
 * Creates a delivery customization that activates the preorder-shipping
 * Function. Idempotent: if a customization already references the function,
 * the existing record is returned.
 */
import { adminGraphQL, authenticateAndExchange, AuthError } from "../lib/shopify.js";

const LOOKUP_QUERY = /* GraphQL */ `
  query Lookup {
    shopifyFunctions(first: 50) {
      nodes {
        id
        apiType
        title
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

const CREATE_MUTATION = /* GraphQL */ `
  mutation CreateCustomization($input: DeliveryCustomizationInput!) {
    deliveryCustomizationCreate(deliveryCustomization: $input) {
      deliveryCustomization {
        id
        title
        enabled
        functionId
      }
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
export async function activateRoute(c, env) {
  try {
    const { shop, accessToken } = await authenticateAndExchange(c.req.raw, env);
    const body = /** @type {{ title?: string }} */ (await c.req.json().catch(() => ({})));
    const title = (body.title || "Pre-order shipping visibility").slice(0, 100);

    /** @type {{ shopifyFunctions: { nodes: any[] }, deliveryCustomizations: { nodes: any[] } }} */
    const lookup = await adminGraphQL(shop, accessToken, LOOKUP_QUERY);
    const fn = (lookup.shopifyFunctions?.nodes ?? []).find(
      (n) => n.apiType === "delivery_customization",
    );
    if (!fn) {
      return c.json(
        {
          error:
            "No delivery_customization function found for this app. Run `shopify app deploy` first.",
        },
        404,
      );
    }

    const existing = (lookup.deliveryCustomizations?.nodes ?? []).find(
      (d) => d.functionId === fn.id,
    );
    if (existing) {
      return c.json({ deliveryCustomization: existing, userErrors: [], idempotent: true });
    }

    /** @type {{ deliveryCustomizationCreate: { deliveryCustomization: any, userErrors: any[] } }} */
    const data = await adminGraphQL(shop, accessToken, CREATE_MUTATION, {
      input: { title, enabled: true, functionId: fn.id },
    });
    const result = data.deliveryCustomizationCreate;
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
  console.error("[activate] error", err);
  return c.json({ error: message }, /** @type {any} */ (status));
}
