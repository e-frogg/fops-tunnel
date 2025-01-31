# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Install xcaddy
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

# Create directory for caddy build
RUN mkdir -p /build/cmd/caddy
WORKDIR /build/cmd/caddy

# Copy source code
COPY . /build/

# Build caddy with plugin
WORKDIR /build
RUN xcaddy build v2.7.6 \
    --with github.com/e-frogg/fops-tunnel/server=.

# Final stage
FROM alpine:latest

WORKDIR /app

# Install required packages
RUN apk add --no-cache ca-certificates tzdata

# Create necessary directories and set permissions
RUN mkdir -p /data /config /etc/caddy/ssh && \
    chmod 755 /etc/caddy && \
    chmod 700 /etc/caddy/ssh

# Copy binary from builder
COPY --from=builder /build/caddy /usr/bin/caddy

ENV CADDY_DATA_DIR=/data

# Expose ports
EXPOSE 80 443 2222

# Set entrypoint
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile"]
