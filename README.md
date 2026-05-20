# Vitaviva Pre-order Shipping — Admin UI

Static HTML + Cloudflare Pages Functions that serve the embedded admin
configuration page for the `preorder-shipping-combiner` Shopify Function.

```
┌──────────────────────────────────────────────────┐
│ Shopify admin (vitavivadk.myshopify.com)         │
│                                                  │
│   Settings → Shipping → Customizations           │
│   └─ click "Pre-order ship-together combiner"    │
│      │                                           │
│      ▼  iframes embed of                         │
│         https://vitaviva-preorder-shipping.      │
│         pages.dev/?host=...&shop=...&id_token=.. │
│                                                  │
│   ┌──────────────────────────────────┐           │
│   │ App Bridge (frontend, this app)  │           │
│   │   sb.idToken() → JWT             │           │
│   │   fetch /api/{status,activate}   │           │
│   │     Authorization: Bearer <jwt>  │           │
│   └──────────────────────────────────┘           │
│            │                                     │
│            ▼ HTTPS                               │
│   ┌──────────────────────────────────┐           │
│   │ Cloudflare Pages Function        │           │
│   │  1. verify JWT (HMAC-SHA256)     │           │
│   │  2. token exchange → access tok  │           │
│   │  3. Admin GraphQL mutation       │           │
│   └──────────────────────────────────┘           │
│            │                                     │
│            ▼ HTTPS                               │
│   Shopify Admin API                              │
└──────────────────────────────────────────────────┘
```

## Why does this exist?

Shopify's modal-driven flow for activating a Function as a delivery
customization opens the app's embedded URL in an iframe. The merchant
configures the customization in that iframe. Functions-only apps (no
Remix/Node backend) lack such an iframe page, so Shopify silently
redirects to the app's installation page — making activation impossible.

This sub-project is the minimum embedded app that satisfies Shopify's
iframe contract:

* **`public/index.html`** — the iframe page (App Bridge + Polaris-style UI)
* **`functions/api/*.ts`** — Cloudflare Pages Functions handling
  GraphQL on the merchant's behalf via session-token exchange
* **`functions/_lib/shopify.ts`** — JWT verification + token exchange

It does NOT touch the function's WASM code — that still lives in
`../extensions/preorder-shipping-combiner/`.

## Local development

```bash
cd shopify-functions/web
npm install

# Run unit tests (JWT verification, handler choreography).
npm test

# Optional: type-check.
npm run typecheck

# Start the local dev server (requires Wrangler 4.x).
# Will print http://localhost:8788. Note that App Bridge only works
# when the page is loaded inside Shopify admin, so local dev is mostly
# useful for API route testing via curl.
npm run dev
```

## Deploy

```bash
cd shopify-functions/web

# One-time: get a Cloudflare API token at
# https://dash.cloudflare.com/profile/api-tokens
# (template: "Edit Cloudflare Workers")
export CLOUDFLARE_API_TOKEN=<token>

# Already known — fetched from `shopify app env show`:
export SHOPIFY_API_KEY=9cac985e37a8b8218e29b4438ed7eeca
export SHOPIFY_API_SECRET=<see-shopify-app-env-show>

# Deploy + set secrets in one shot:
./full-deploy.sh

# Subsequent code-only deploys:
npm run deploy
```

After the first deploy, Cloudflare gives you a stable URL:

    https://vitaviva-preorder-shipping.pages.dev

Plug that into the parent `shopify.app.toml`:

```toml
application_url = "https://vitaviva-preorder-shipping.pages.dev"

[auth]
redirect_urls = [
  "https://vitaviva-preorder-shipping.pages.dev/auth/callback",
]
```

Then redeploy the Shopify app config:

```bash
cd ..
npx shopify app deploy --force
```

## File layout

```
web/
├── README.md
├── deploy.sh                 # Minimal wrapper around `wrangler pages deploy`
├── full-deploy.sh            # Deploy + secret-puts in one command
├── package.json
├── tsconfig.json
├── wrangler.jsonc
├── public/
│   └── index.html            # Embedded iframe app
├── functions/
│   ├── _middleware.ts        # CSP frame-ancestors + meta key injection
│   ├── _lib/
│   │   └── shopify.ts        # JWT verification + token exchange + GraphQL
│   └── api/
│       ├── status.ts         # GET — current function + customizations
│       ├── activate.ts       # POST — create deliveryCustomization
│       └── deactivate.ts     # POST — delete deliveryCustomization
└── test/
    ├── shopify.test.mjs      # JWT verification tests (12 cases)
    └── handler.test.mjs      # End-to-end handler tests (6 cases)
```

## Security

* Session tokens are **verified** server-side using the app's
  `SHOPIFY_API_SECRET` (HMAC-SHA256), not just decoded. Tampered tokens
  return 401.
* The HTML page never sees the access token — it's exchanged server-side
  and used only within the Pages Function.
* CSP `frame-ancestors` is set to lock the iframe to the embedding shop.
* `Cache-Control: no-store` on all API responses.
* No PII or secrets are logged.

## Testing

The full Node test suite runs without network:

```
$ npm test
✔ 18 / 18 tests passing  (JWT + handler choreography)
```

For an end-to-end check, log into Shopify admin →
Settings → Shipping → Customizations → "Add delivery customization" →
pick the function. The iframe will load this app, App Bridge bootstraps,
and the UI shows current state.
