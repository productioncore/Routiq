# syntax=docker/dockerfile:1
# UAM backend — User Access Management (auth, tokens, credentials).
# Production boundary: issues access JWTs; gateway validates them locally (ADR-0050).

FROM node:20-alpine AS build
WORKDIR /app
# ci --include=dev: reproducible build; typescript-7 aliases typescript@rc
# which FLOATS — plain `npm install` re-resolves it and can break the layout.
COPY package.json package-lock.json* ./
RUN npm ci --include=dev
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY ca.crt /app/ca.crt
RUN rm -f /app/.env

RUN apk add --no-cache wget \
    && chown -R node:node /app
USER node

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

CMD ["node", "dist/index.js"]
