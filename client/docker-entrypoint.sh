#!/bin/sh
set -e

# Check authentication methods
have_key=0
have_agent=0


# Check if private key is provided
if [ -n "$TUNNEL_KEY_PATH" ] && [ -f "$TUNNEL_KEY_PATH" ]; then
    have_key=1
fi

# Check if SSH agent socket is available
if [ -S "$SSH_AUTH_SOCK" ]; then
    # Test SSH agent connection
    if ssh-add -l > /dev/null 2>&1; then
        have_agent=1
    else
        echo "Warning: SSH agent socket exists but no keys are loaded"
    fi
fi


# Verify we have at least one authentication method
if [ $have_key -eq 0 ] && [ $have_agent -eq 0 ]; then
    echo "Error: No authentication methods available"
    echo "Please either:"
    echo "  - Provide a private key via TUNNEL_KEY_PATH"
    echo "  - Mount SSH agent socket and ensure keys are loaded"
    exit 1
fi

# Start tunnel client with environment variables
if [ $have_key -eq 1 ]; then
    exec ./tunnel-client \
        --host "$TUNNEL_SERVER_HOST" \
        --port "$TUNNEL_SERVER_PORT" \
        --user "$TUNNEL_USER" \
        --key "$TUNNEL_KEY_PATH" \
        --local-port "$SOURCE_PORT" \
        --remote-host "$SOURCE_HOST" \
        ${SUBDOMAIN:+--subdomain "$SUBDOMAIN"}
else
    exec ./tunnel-client \
        --host "$TUNNEL_SERVER_HOST" \
        --port "$TUNNEL_SERVER_PORT" \
        --user "$TUNNEL_USER" \
        --local-port "$SOURCE_PORT" \
        --remote-host "$SOURCE_HOST" \
        ${SUBDOMAIN:+--subdomain "$SUBDOMAIN"} 
fi