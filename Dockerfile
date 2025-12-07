# Fula Gateway - S3-Compatible Storage Gateway
# Multi-stage build for minimal image size

# ============================================
# Stage 1: Build
# ============================================
FROM rust:1.83-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build release binary
RUN cargo build --release --package fula-cli

# ============================================
# Stage 2: Runtime
# ============================================
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/fula-gateway /usr/local/bin/fula-gateway

# Create non-root user
RUN useradd -r -s /bin/false fula
USER fula

# Expose port
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9000/ || exit 1

# Set environment defaults
ENV FULA_HOST=0.0.0.0
ENV FULA_PORT=9000
ENV IPFS_API_URL=http://ipfs:5001
ENV CLUSTER_API_URL=http://cluster:9094
ENV RUST_LOG=info

# Run the gateway
ENTRYPOINT ["fula-gateway"]
CMD []
