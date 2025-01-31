# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /tunnel-client cmd/main.go

# Final stage
FROM alpine:latest

WORKDIR /app

# Install required packages
RUN apk add --no-cache ca-certificates openssh-client

# Copy the binary from builder
COPY --from=builder /tunnel-client .

# Create SSH directory
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh

# Environment variables with defaults
ENV TUNNEL_SERVER_HOST=localhost \
    TUNNEL_SERVER_PORT=2222 \
    TUNNEL_USER=tunnel \
    TUNNEL_KEY_PATH="" \
    SSH_AUTH_SOCK=/ssh-agent \
    LOCAL_PORT=8080 \
    REMOTE_HOST=localhost \
    SUBDOMAIN=""

# Copy entrypoint script
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
