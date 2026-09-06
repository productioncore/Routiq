# syntax=docker/dockerfile:1
# UAM frontend — React SPA, calls gateway directly (no nginx proxy).

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* .npmrc ./
RUN npm install
COPY . .
RUN npm run build

FROM node:20-alpine
RUN npm install -g serve@14
COPY --from=build /app/dist /app/dist
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/ >/dev/null 2>&1 || exit 1
CMD ["serve", "-s", "/app/dist", "-l", "8080"]
