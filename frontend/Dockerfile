# syntax=docker/dockerfile:1
# Security-Ops SPA — React 18 + Vite 5 + Tailwind 3 (mirrors the Brigade frontend stack).
# Build context is ./frontend (see docker-compose.yml -> secops-frontend: build ./frontend).
# Multi-stage: node build -> static bundle served by nginx on :8131, with /api
# reverse-proxied to secops-api:8130 (see frontend/nginx.conf).

# --- build stage ---
FROM node:20-alpine AS build
WORKDIR /app

# Install deps first for layer caching. `npm ci` when a lockfile is present,
# otherwise fall back to `npm install`.
COPY package*.json ./
RUN npm ci || npm install

# App source (vite.config.js, tailwind/postcss configs, index.html, src/, ...).
COPY . .
RUN npm run build

# --- serve stage ---
FROM nginx:1.27-alpine

# Static production bundle.
COPY --from=build /app/dist /usr/share/nginx/html

# SPA history fallback + `/api` -> secops-api:8130 reverse proxy. This server
# block MUST `listen 8131;` (the blueprint's frontend container port). Provided
# by the frontend module.
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8131
CMD ["nginx", "-g", "daemon off;"]
