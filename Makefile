ZIG ?= zig

# Define variables
SERVER_CERT_FILE=cert.pem
SERVER_KEY_FILE=key.pem
CLIENT_CERT_FILE=client_cert.pem
CLIENT_KEY_FILE=client_key.pem
DH_PARAMS_FILE=dhparam.pem
PORT=4433
LOG_FILE=server.log

# Default target
all: test

# Target to generate a self-signed certificate
$(SERVER_CERT_FILE) $(SERVER_KEY_FILE):
	openssl req -x509 -newkey rsa:4096 -keyout $(SERVER_KEY_FILE) -out $(SERVER_CERT_FILE) -days 365 -nodes \
	-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"

# Target to generate a client certificate
$(CLIENT_CERT_FILE) $(CLIENT_KEY_FILE):
	openssl req -x509 -newkey rsa:4096 -keyout $(CLIENT_KEY_FILE) -out $(CLIENT_CERT_FILE) -days 365 -nodes \
	-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=client.example.com"

# Target to generate DH parameters
$(DH_PARAMS_FILE):
	openssl dhparam -out $(DH_PARAMS_FILE) 2048

# Target to start the OpenSSL server in the background
start_server: $(SERVER_CERT_FILE) $(SERVER_KEY_FILE) $(DH_PARAMS_FILE)
	@echo "Starting OpenSSL server..."
	@openssl s_server -accept $(PORT) -cert $(SERVER_CERT_FILE) -key $(SERVER_KEY_FILE) -CAfile $(SERVER_CERT_FILE) -dhparam $(DH_PARAMS_FILE) -cipher "AES128-GCM-SHA256" -Verify 1 -www -debug > $(LOG_FILE) 2>&1 &
	@sleep 2 # Wait a moment for the server to start

# Target to stop the OpenSSL server
stop_server:
	@echo "Stopping OpenSSL server..."
	@pkill -f "openssl s_server"
	@sleep 2 # Ensure the server has stopped

# Target to run Zig tests
test: $(CLIENT_CERT_FILE) $(CLIENT_KEY_FILE) start_server
	@echo "Running Zig tests..."
	zig test http2/tls.zig -I./boringssl/include -L./boringssl/build/ssl -L./boringssl/build/crypto -lssl -lcrypto -lc++
	$(MAKE) stop_server
	@echo "Checking OpenSSL server log..."
	@cat $(LOG_FILE)

# Target to clean up generated files
clean:
	rm -f $(SERVER_CERT_FILE) $(SERVER_KEY_FILE) $(CLIENT_CERT_FILE) $(CLIENT_KEY_FILE) $(DH_PARAMS_FILE) $(LOG_FILE)

.PHONY: all start_server test clean stop_server

update:
	git submodule update --init --recursive

test-tls:
	zig test http2/tls.zig -I./boringssl/include -L./boringssl/build/ssl -L./boringssl/build/crypto -lssl -lcrypto -lc++

build:
	$(ZIG) build -freference-trace

build-boringssl:
	cd boringssl && cmake -DCMAKE_BUILD_TYPE=Release -B build && make -C build

build-boringssl-unoptimized:
	cd boringssl && cmake -B build && make -C build

create-bindings:
	zig translate-c -I boringssl/include boringssl/include/openssl/ssl.h > http2/boringssl/boringssl-bindings.zig

build-lib:
	$(ZIG) build-lib http2/connection.zig -lc -Iboringssl/include

init-export:
	export LDFLAGS="-L/usr/local/opt/zlib/lib"
