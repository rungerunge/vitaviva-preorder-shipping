# Production container for the Vitaviva pre-order shipping admin UI.
# Two stages: install only prod deps in stage A, then run them in stage B
# so the final image stays small and dev-only modules never ship.
#
# Railway picks Dockerfile over Nixpacks automatically when one is present
# at the repo root. We use this in preference to Nixpacks because the
# Nixpacks node_modules cache mount has been flaky on this account
# ("EBUSY: resource busy or locked, rmdir '/app/node_modules/.cache'").

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY src ./src
COPY public ./public

# Railway injects $PORT — bind to whatever it provides.
EXPOSE 3000
CMD ["npm", "start"]
