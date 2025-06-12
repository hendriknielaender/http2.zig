ZIG ?= zig

# Define variables
SERVER_CERT_FILE=cert.pem
SERVER_KEY_FILE=key.pem
CLIENT_CERT_FILE=client_cert.pem
CLIENT_KEY_FILE=client_key.pem
DH_PARAMS_FILE=dhparam.pem
PORT=9001
LOG_FILE=server.log

# Default target
all: build

# Generate self-signed certificate for localhost
cert: $(SERVER_CERT_FILE) $(SERVER_KEY_FILE)

$(SERVER_CERT_FILE) $(SERVER_KEY_FILE):
	@echo "Generating self-signed certificate for localhost..."
	@openssl req -x509 -newkey rsa:4096 -keyout $(SERVER_KEY_FILE) -out $(SERVER_CERT_FILE) \
		-days 365 -nodes -subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	@echo "Certificate generated: $(SERVER_CERT_FILE), $(SERVER_KEY_FILE)"

# Generate client certificate
$(CLIENT_CERT_FILE) $(CLIENT_KEY_FILE):
	openssl req -x509 -newkey rsa:4096 -keyout $(CLIENT_KEY_FILE) -out $(CLIENT_CERT_FILE) -days 365 -nodes \
	-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=client.example.com"

# Generate DH parameters
$(DH_PARAMS_FILE):
	openssl dhparam -out $(DH_PARAMS_FILE) 2048

# Build the HTTP/2 library and examples
build:
	@echo "Building HTTP/2 library and examples..."
	@$(ZIG) build

# Run the TLS HTTP/2 server
run: cert build
	@echo "Starting HTTP/2 TLS server on https://localhost:$(PORT)"
	@./zig-out/bin/hello_world_server

# Test with h2spec
test-h2spec: cert build
	@echo "Running h2spec tests against TLS server..."
	@./zig-out/bin/hello_world_server &
	@SERVER_PID=$$!; \
	sleep 2; \
	h2spec -h localhost -p $(PORT) -t -k || true; \
	kill $$SERVER_PID 2>/dev/null || true

# Run unit tests
test: build
	@echo "Running unit tests..."
	@$(ZIG) build test

# Test TLS module specifically
test-tls: build-boringssl
	@echo "Testing TLS module..."
	@$(ZIG) test src/tls.zig -I./boringssl/include -L./boringssl/build/ssl -L./boringssl/build/crypto -lssl -lcrypto -lc++

# Format code
fmt:
	@echo "Formatting code..."
	@$(ZIG) fmt src/ examples/

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	@rm -f $(SERVER_CERT_FILE) $(SERVER_KEY_FILE) $(CLIENT_CERT_FILE) $(CLIENT_KEY_FILE) $(DH_PARAMS_FILE) $(LOG_FILE)
	@rm -rf zig-out/
	@echo "Clean complete"

# Initialize git submodules
update:
	git submodule update --init --recursive

# Build BoringSSL library
build-boringssl:
	@echo "Building BoringSSL..."
	@cd boringssl && cmake -DCMAKE_BUILD_TYPE=Release -B build && make -C build

# Build BoringSSL unoptimized
build-boringssl-unoptimized:
	@echo "Building BoringSSL (unoptimized)..."
	@cd boringssl && cmake -B build && make -C build

# Create BoringSSL bindings
create-bindings: build-boringssl
	@echo "Creating BoringSSL bindings..."
	@mkdir -p boringssl
	@$(ZIG) translate-c -I boringssl/include boringssl/include/openssl/ssl.h > src/bindings/boringssl-bindings.zig

.PHONY: all build run test test-h2spec test-tls fmt clean cert update build-boringssl build-boringssl-unoptimized create-bindings
