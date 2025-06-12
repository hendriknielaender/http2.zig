# HTTP/2 TLS Example Makefile
# Generates self-signed certificates for localhost testing

.PHONY: all clean run test cert

# Default target
all: cert build

# Generate self-signed certificate for localhost
cert: server.crt server.key

server.crt server.key:
	@echo "Generating self-signed certificate for localhost..."
	@openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
		-days 365 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Certificate generated: server.crt, server.key"

# Build the example
build:
	@echo "Building HTTP/2 TLS example..."
	@zig build

# Run the server
run: cert build
	@echo "Starting HTTP/2 TLS server on https://localhost:9001"
	@./zig-out/bin/hello-world

# Test with h2spec
test: cert build
	@echo "Running h2spec tests against TLS server..."
	@./zig-out/bin/hello-world &
	@SERVER_PID=$$!; \
	sleep 2; \
	h2spec -h localhost -p 9001 -t -k || true; \
	kill $$SERVER_PID 2>/dev/null || true

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -f server.crt server.key
	@rm -rf zig-out/
	@echo "Clean complete"