# ============================================================
# Gateway Dockerfile — OpenResty + Rust FFI + bundled config-sidecar
#
# Render / single-node: one container runs sidecar (polls control-plane)
# and OpenResty (data plane). K8s can still split sidecar into a sidecar pod.
# ============================================================

# ── Stage 1: Gateway Rust extension ─────────────────────────
FROM rust:slim-bullseye AS gateway-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY rust-ext/Cargo.toml rust-ext/Cargo.lock* ./
RUN mkdir src && echo "" > src/lib.rs && cargo build --release || true
COPY rust-ext/src ./src
RUN ls -la src/ && touch src/lib.rs && cargo build --release && \
    cp target/release/librust_ext.so /librust_ext.so

# ── Stage 2: Config sidecar ─────────────────────────────────
FROM rust:slim-bullseye AS sidecar-builder

WORKDIR /build
COPY config-sidecar/Cargo.toml config-sidecar/Cargo.lock* ./
COPY config-sidecar/src ./src
RUN cargo build --release && strip target/release/config-sidecar

# ── Stage 3: OpenResty runtime ──────────────────────────────
FROM openresty/openresty:1.21.4.1-bullseye

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gateway-builder /librust_ext.so /usr/local/lib/librust_ext.so
COPY --from=sidecar-builder /build/target/release/config-sidecar /usr/local/bin/config-sidecar
RUN ldconfig

COPY lua/gateway.lua        /usr/local/openresty/nginx/lua/gateway.lua
COPY nginx.conf             /usr/local/openresty/nginx/conf/nginx.conf
COPY gateway-locations.conf /usr/local/openresty/nginx/conf/gateway-locations.conf
COPY cloudflare/            /usr/local/openresty/nginx/conf/cloudflare/
COPY docker-start.sh        /docker-start.sh

RUN mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/certs/server.key \
        -out    /etc/nginx/certs/server.crt \
        -subj   "/C=US/ST=State/L=City/O=Gateway/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    && chmod 600 /etc/nginx/certs/server.key

RUN mkdir -p /var/log/nginx /etc/gateway && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log && \
    sed -i 's/\r$//' /docker-start.sh && \
    chmod +x /docker-start.sh

ENV GATEWAY_CONFIG_PATH=/etc/gateway/config.json

EXPOSE 8080 8443

ENTRYPOINT ["/docker-start.sh"]
