# Variables
BINARY_NAME=caddy
XCADDY=xcaddy
# Colors for terminal output
GREEN=\033[0;32m
NC=\033[0m # No Color

server-build:
	@echo "${GREEN}Building Caddy with fops tunnel server plugin...${NC}"
	@mkdir -p build
	@$(XCADDY) build \
		--with github.com/e-frogg/fops-tunnel/server=./server \
		--output build/caddy
	@echo "${GREEN}Build complete! Binary located at build/caddy${NC}"

server-run: server-build
	@echo "${GREEN}Running Caddy with debug mode...${NC}"
	@sudo DEBUG=1 \
	FOPS_TUNNEL_SERVER_HOST=localhost \
	FOPS_TUNNEL_SERVER_HTTP_PORT=30000 \
	FOPS_TUNNEL_SERVER_HTTPS_PORT=30001 \
	FOPS_TUNNEL_SERVER_PORT=30002 \
	FOPS_TUNNEL_SERVER_ADMIN_API_TOKEN=this-is-not-a-secure-token \
	FOPS_TUNNEL_SERVER_AUTH_KEYS_PATH=./_fixtures/server/ssh/authorized_keys \
	FOPS_TUNNEL_SERVER_TIMEOUT=15m \
	./build/$(BINARY_NAME) run --config ./server/Caddyfile


server-test:
	@echo "${GREEN}Running tests...${NC}"
	@cd server && go test -v ./... -cover 


client-build:
	@echo "Building client..."
	@mkdir -p build/
	@cd client && go build -o ../build/client ./cmd/main.go
	@echo "Build complete: build/client"

client-run: client-build
	@echo "Running client..."
	@build/client \
		-host localhost \
		-port 30002 \
		-user tunnel \
		-key ./_fixtures/client/id_rsa \
		-local-port 7000 \
		-remote-host 192.168.5.251 \
		-subdomain test

# Run tests
client-test:
	@echo "Running tests..."
	@cd client && go test -v ./...

clean:
	@echo "${GREEN}Cleaning build...${NC}"
	@rm -rf build