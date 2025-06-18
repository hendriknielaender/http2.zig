const std = @import("std");
const boringssl = @import("bindings/boringssl-bindings.zig");

/// TLS operation errors.
/// These errors cover initialization, handshake, and I/O failures.
pub const TlsError = error{
    InitFailed,
    HandshakeFailed,
    WriteFailed,
    ReadFailed,
    InvalidContext,
    InvalidSocket,
    WouldBlock,
    ConnectionClosed,
};

/// TLS server context for HTTP/2 over TLS connections.
/// Wraps BoringSSL SSL_CTX and provides ALPN negotiation for h2.
///
/// 1) Create once at startup:
///    ```zig
///    var tls_ctx = try TlsServerContext.init(
///        std.heap.page_allocator,
///        "server_cert.pem",
///        "server_key.pem"
///    );
///    defer tls_ctx.deinit();
///    ```
///
/// 2) For each accepted TCP connection:
///    ```zig
///    var tls_conn = try tls_ctx.accept(conn.handle);
///    defer tls_conn.deinit();
///    // Wrap and pass tls_conn.reader(), tls_conn.writer() to your http2.Connection
///    ```
pub const TlsServerContext = struct {
    allocator: std.mem.Allocator,
    ctx: ?*boringssl.SSL_CTX,

    /// Create a new server TLS context with the given certificate and key files.
    /// We also set ALPN to "h2" for HTTP/2 usage.
    pub fn init(
        allocator: std.mem.Allocator,
        cert_path: []const u8,
        key_path: []const u8,
    ) !TlsServerContext {
        // Initialize BoringSSL library state.
        // These are mostly no-ops in modern BoringSSL versions.
        _ = boringssl.SSL_library_init();
        _ = boringssl.SSL_load_error_strings();

        // Create SSL method for server-side TLS.
        // SSLv23_server_method() negotiates the highest available TLS version.
        const method = boringssl.SSLv23_server_method();
        if (method == null) {
            return TlsError.InitFailed;
        }

        const ctx_ptr = boringssl.SSL_CTX_new(method);
        if (ctx_ptr == null) {
            return TlsError.InitFailed;
        }

        var self = TlsServerContext{
            .allocator = allocator,
            .ctx = ctx_ptr,
        };

        // Let BoringSSL and LibreSSL negotiate TLS version naturally
        // Don't force specific versions
        
        // Use broader cipher suite for compatibility
        const cipher_list = "ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384";
        if (boringssl.SSL_CTX_set_cipher_list(ctx_ptr, cipher_list.ptr) != 1) {
            return TlsError.InitFailed;
        }

        // Configure ALPN for dual HTTP/2 and HTTP/1.1 support
        try self.set_alpn("h2");

        // Load TLS certificate and private key from filesystem.
        try self.load_certificate_and_key(cert_path, key_path);

        return self;
    }

    /// Free the SSL_CTX resources.
    pub fn deinit(self: *TlsServerContext) void {
        if (self.ctx) |ctx_val| {
            boringssl.SSL_CTX_free(ctx_val);
            self.ctx = null;
        }
    }

    /// Create a new TLS connection with BIO pair for proper async I/O
    /// This avoids socket FD conflicts with libxev
    pub fn createAsyncConnection(self: *TlsServerContext, socket_fd: std.posix.fd_t) !TlsServerConnection {
        _ = socket_fd; // We'll use BIO pairs instead

        // Assert valid context
        std.debug.assert(self.ctx != null);

        if (self.ctx == null) {
            return TlsError.InvalidContext;
        }

        const ssl_connection = boringssl.SSL_new(self.ctx);
        if (ssl_connection == null) {
            return TlsError.InvalidContext;
        }

        // Create BIO pair for async I/O
        var internal_bio: ?*boringssl.BIO = null;
        var network_bio: ?*boringssl.BIO = null;

        // Create a BIO pair with reasonable buffer sizes
        if (boringssl.BIO_new_bio_pair(&internal_bio, 16384, &network_bio, 16384) != 1) {
            boringssl.SSL_free(ssl_connection);
            return TlsError.InitFailed;
        }

        // Connect SSL to internal BIO
        boringssl.SSL_set_bio(ssl_connection, internal_bio, internal_bio);

        // Set SSL to server mode
        boringssl.SSL_set_accept_state(ssl_connection);

        return TlsServerConnection{
            .allocator = self.allocator,
            .ssl = ssl_connection,
            .handshake_state = .need_handshake,
            .internal_bio = internal_bio,
            .network_bio = network_bio,
        };
    }

    /// Accept a new TLS connection (legacy blocking version)
    pub fn accept(self: *TlsServerContext, socket_fd: std.posix.fd_t) !TlsServerConnection {
        var connection = try self.createAsyncConnection(socket_fd);

        // Perform the server‐side TLS handshake. On success, returns 1.
        const handshake_result = boringssl.SSL_accept(connection.ssl);
        if (handshake_result != 1) {
            // Clear the error queue to avoid spam from invalid clients
            _ = boringssl.ERR_clear_error();
            connection.deinit();
            return TlsError.HandshakeFailed;
        }

        return connection;
    }

    /// Sets the ALPN protocols on the server context to exactly the given `alpn_proto` (e.g. "h2").
    fn set_alpn(self: *TlsServerContext, alpn_proto: []const u8) !void {
        _ = alpn_proto; // Ignore single protocol parameter, we'll advertise both
        
        // Advertise both h2 and http/1.1 using SSL_CTX_set_alpn_protos
        // Wire format: [2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1']
        const protocols = [_]u8{ 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        
        const rc = boringssl.SSL_CTX_set_alpn_protos(
            self.ctx,
            &protocols,
            protocols.len,
        );
        if (rc != 0) {
            return TlsError.InitFailed;
        }
        
        // Also set callback for protocol selection priority (h2 preferred)
        const callback = struct {
            fn alpn_select_callback(
                ssl: ?*boringssl.SSL,
                out: [*c][*c]const u8,
                outlen: [*c]u8,
                input: [*c]const u8,
                inlen: c_uint,
                arg: ?*anyopaque,
            ) callconv(.C) c_int {
                _ = ssl;
                _ = arg;

                // Search for h2 first (preferred)
                var protocol_index: c_uint = 0;
                while (protocol_index < inlen) {
                    if (protocol_index >= inlen) break;
                    
                    const protocol_length = input[protocol_index];
                    if (protocol_index + 1 + protocol_length > inlen) break;

                    // Check for h2 (preferred)
                    if (protocol_length == 2 and protocol_index + 3 <= inlen) {
                        if (input[protocol_index + 1] == 'h' and input[protocol_index + 2] == '2') {
                            out.* = &input[protocol_index + 1];
                            outlen.* = 2;
                            return boringssl.SSL_TLSEXT_ERR_OK;
                        }
                    }

                    protocol_index += 1 + protocol_length;
                }
                
                // Search for http/1.1 (fallback)
                protocol_index = 0;
                while (protocol_index < inlen) {
                    if (protocol_index >= inlen) break;
                    
                    const protocol_length = input[protocol_index];
                    if (protocol_index + 1 + protocol_length > inlen) break;

                    // Check for http/1.1
                    if (protocol_length == 8 and protocol_index + 9 <= inlen) {
                        const http11_bytes = "http/1.1";
                        var match = true;
                        for (0..8) |i| {
                            if (input[protocol_index + 1 + i] != http11_bytes[i]) {
                                match = false;
                                break;
                            }
                        }
                        if (match) {
                            out.* = &input[protocol_index + 1];
                            outlen.* = 8;
                            return boringssl.SSL_TLSEXT_ERR_OK;
                        }
                    }

                    protocol_index += 1 + protocol_length;
                }

                return boringssl.SSL_TLSEXT_ERR_NOACK;
            }
        }.alpn_select_callback;

        boringssl.SSL_CTX_set_alpn_select_cb(self.ctx, callback, null);
    }

    /// Load server certificate and private key files (PEM) into the SSL_CTX.
    fn load_certificate_and_key(
        self: *TlsServerContext,
        cert_path: []const u8,
        key_path: []const u8,
    ) !void {
        // Read files fully into memory with reasonable size limits
        const max_cert_size = 1024 * 1024; // 1MB max for certificate file
        const max_key_size = 1024 * 1024; // 1MB max for private key file

        // Assert reasonable file size bounds
        std.debug.assert(max_cert_size > 0);
        std.debug.assert(max_key_size > 0);

        const certificate_data = try std.fs.cwd().readFileAlloc(self.allocator, cert_path, max_cert_size);
        defer self.allocator.free(certificate_data);

        const private_key_data = try std.fs.cwd().readFileAlloc(self.allocator, key_path, max_key_size);
        defer self.allocator.free(private_key_data);

        // Load certificate from in‐memory bytes with bounds checking
        std.debug.assert(certificate_data.len > 0);
        std.debug.assert(certificate_data.len <= max_cert_size);

        const certificate_length: c_long = @intCast(certificate_data.len);
        const certificate_bio = boringssl.BIO_new_mem_buf(certificate_data.ptr, certificate_length);
        if (certificate_bio == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.BIO_free(certificate_bio);

        const x509_certificate = boringssl.PEM_read_bio_X509(certificate_bio, null, null, null);
        if (x509_certificate == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.X509_free(x509_certificate);

        if (boringssl.SSL_CTX_use_certificate(self.ctx, x509_certificate) != 1) {
            return TlsError.InitFailed;
        }

        // Load private key from in‐memory bytes with bounds checking
        std.debug.assert(private_key_data.len > 0);
        std.debug.assert(private_key_data.len <= max_key_size);

        const private_key_length: c_long = @intCast(private_key_data.len);
        const private_key_bio = boringssl.BIO_new_mem_buf(private_key_data.ptr, private_key_length);
        if (private_key_bio == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.BIO_free(private_key_bio);

        const private_key = boringssl.PEM_read_bio_PrivateKey(private_key_bio, null, null, null);
        if (private_key == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.EVP_PKEY_free(private_key);

        if (boringssl.SSL_CTX_use_PrivateKey(self.ctx, private_key) != 1) {
            return TlsError.InitFailed;
        }

        // Verify the key matches the certificate.
        if (boringssl.SSL_CTX_check_private_key(self.ctx) != 1) {
            return TlsError.InitFailed;
        }
    }
};

/// TLS handshake state for async operations
pub const TlsHandshakeState = enum {
    need_handshake,
    want_read,
    want_write,
    complete,
    failed,
};

/// A single server‐side TLS connection for async operations
/// Supports both blocking and non-blocking handshake modes
pub const TlsServerConnection = struct {
    allocator: std.mem.Allocator,
    ssl: ?*boringssl.SSL,
    handshake_state: TlsHandshakeState,
    // BIO pair for async I/O with libxev
    internal_bio: ?*boringssl.BIO,
    network_bio: ?*boringssl.BIO,

    /// Initialize with handshake pending
    pub fn init(allocator: std.mem.Allocator, ssl: *boringssl.SSL) TlsServerConnection {
        return TlsServerConnection{
            .allocator = allocator,
            .ssl = ssl,
            .handshake_state = .need_handshake,
            .internal_bio = null,
            .network_bio = null,
        };
    }

    /// Clean up SSL resources.
    pub fn deinit(self: *TlsServerConnection) void {
        // Prevent double-free by checking if already cleaned up
        if (self.ssl == null) return;

        if (self.ssl) |ssl_val| {
            boringssl.SSL_free(ssl_val);
            self.ssl = null;
        }

        // Clear BIO pointers (they're managed by BoringSSL)
        self.internal_bio = null;
        self.network_bio = null;
    }

    /// Attempt async TLS handshake - returns current state
    /// Handles BoringSSL's async operations properly with libxev
    pub fn doAsyncHandshake(self: *TlsServerConnection) TlsHandshakeState {
        if (self.handshake_state == .complete or self.handshake_state == .failed) {
            return self.handshake_state;
        }

        if (self.ssl == null) {
            std.log.err("SSL object is null", .{});
            self.handshake_state = .failed;
            return .failed;
        }

        // Use SSL_do_handshake for async operations instead of SSL_accept
        const handshake_result = boringssl.SSL_do_handshake(self.ssl);

        if (handshake_result == 1) {
            // Handshake completed successfully
            self.handshake_state = .complete;
            return .complete;
        }

        // Check what SSL wants us to do
        const ssl_error = boringssl.SSL_get_error(self.ssl, handshake_result);

        switch (ssl_error) {
            boringssl.SSL_ERROR_WANT_READ => {
                self.handshake_state = .want_read;
                return .want_read;
            },
            boringssl.SSL_ERROR_WANT_WRITE => {
                self.handshake_state = .want_write;
                return .want_write;
            },
            else => {
                // Get more detailed error info
                const err_code = boringssl.ERR_get_error();
                if (err_code != 0) {
                    var err_buf: [256]u8 = undefined;
                    _ = boringssl.ERR_error_string_n(err_code, &err_buf, err_buf.len);
                    std.log.err("SSL handshake failed with error {}: {s}", .{ ssl_error, err_buf });
                } else {
                    std.log.err("SSL handshake failed with error: {}", .{ssl_error});
                }
                self.handshake_state = .failed;
                return .failed;
            },
        }
    }

    /// Check if handshake is complete
    pub fn isHandshakeComplete(self: *TlsServerConnection) bool {
        return self.handshake_state == .complete;
    }
    
    /// Get the negotiated ALPN protocol
    pub fn getNegotiatedProtocol(self: *TlsServerConnection) ?[]const u8 {
        if (self.ssl == null) {
            return null;
        }
        
        var data: [*c]const u8 = undefined;
        var len: c_uint = undefined;
        
        boringssl.SSL_get0_alpn_selected(self.ssl, &data, &len);
        
        if (len == 0 or data == null) {
            return null;
        }
        
        return data[0..len];
    }

    /// Feed encrypted data from network to the TLS engine
    pub fn feedEncryptedData(self: *TlsServerConnection, data: []const u8) !usize {
        if (self.network_bio == null) {
            return TlsError.InvalidContext;
        }

        const written = boringssl.BIO_write(self.network_bio, data.ptr, @intCast(data.len));
        if (written <= 0) {
            return 0;
        }

        return @intCast(written);
    }

    /// Read encrypted data from TLS engine to send to network
    pub fn readEncryptedData(self: *TlsServerConnection, buffer: []u8) !usize {
        if (self.network_bio == null) {
            return TlsError.InvalidContext;
        }

        const read_bytes = boringssl.BIO_read(self.network_bio, buffer.ptr, @intCast(buffer.len));
        if (read_bytes <= 0) {
            // Check if BIO would retry
            if (boringssl.BIO_should_retry(self.network_bio) != 0) {
                return 0;
            }
            return 0;
        }

        return @intCast(read_bytes);
    }

    /// Check if TLS engine has encrypted data to send
    pub fn hasEncryptedDataToSend(self: *TlsServerConnection) bool {
        if (self.network_bio == null) {
            return false;
        }

        // Check if there's pending data in the network BIO
        const pending = boringssl.BIO_pending(self.network_bio);
        return pending > 0;
    }

    /// Provide a std.io.Reader interface to read from TLS.
    pub fn reader(self: *TlsServerConnection) std.io.Reader(*TlsServerConnection, TlsError, readFn) {
        return .{ .context = self };
    }

    fn readFn(self: *TlsServerConnection, buffer: []u8) TlsError!usize {
        return self.read_tls(buffer);
    }

    /// Provide a std.io.Writer interface to write to TLS.
    pub fn writer(self: *TlsServerConnection) std.io.Writer(*TlsServerConnection, TlsError, writeFn) {
        return .{ .context = self };
    }

    fn writeFn(self: *TlsServerConnection, data: []const u8) TlsError!usize {
        self.write_tls(data) catch |err| return err;
        return data.len;
    }

    /// A single SSL_read call. Returns bytes read, or an error.
    fn read_tls(self: *TlsServerConnection, read_buffer: []u8) !usize {
        // Assert valid SSL context and buffer
        std.debug.assert(self.ssl != null);
        std.debug.assert(read_buffer.len <= std.math.maxInt(c_int));

        if (self.ssl == null) {
            return TlsError.InvalidContext;
        }
        if (read_buffer.len == 0) {
            return 0;
        }

        const ssl_connection = self.ssl.?;
        const buffer_length: c_int = @intCast(read_buffer.len);
        const bytes_read_count = boringssl.SSL_read(ssl_connection, read_buffer.ptr, buffer_length);

        if (bytes_read_count > 0) {
            // The function returns !usize, so let the compiler infer `usize` for @intCast.
            return @intCast(bytes_read_count);
        }

        // For <=0 return, check the error code.
        const ssl_error_code = boringssl.SSL_get_error(ssl_connection, bytes_read_count);

        switch (ssl_error_code) {
            boringssl.SSL_ERROR_WANT_READ => {
                return TlsError.WouldBlock;
            },
            boringssl.SSL_ERROR_WANT_WRITE => {
                return TlsError.WouldBlock;
            },
            boringssl.SSL_ERROR_ZERO_RETURN => {
                // Clean shutdown - client closed the TLS connection
                std.log.debug("TLS connection closed cleanly by client", .{});
                return TlsError.ConnectionClosed;
            },
            boringssl.SSL_ERROR_SYSCALL => {
                // System call error - could be connection closed
                if (bytes_read_count == 0) {
                    std.log.debug("TLS connection closed by client (SYSCALL)", .{});
                    return TlsError.ConnectionClosed;
                } else {
                    std.log.err("SSL_read SYSCALL error: {}", .{ssl_error_code});
                    return TlsError.ReadFailed;
                }
            },
            boringssl.SSL_ERROR_SSL => {
                // SSL protocol error - could be connection reset by peer
                std.log.debug("SSL protocol error (connection likely closed by client): {}", .{ssl_error_code});
                return TlsError.ConnectionClosed;
            },
            else => {
                std.log.err("SSL_read failed with error: {}", .{ssl_error_code});
                return TlsError.ReadFailed;
            },
        }
    }

    /// Write all `data` through SSL_write until fully consumed or error.
    fn write_tls(self: *TlsServerConnection, write_data: []const u8) !void {
        // Assert valid SSL context and data size
        std.debug.assert(self.ssl != null);
        std.debug.assert(write_data.len <= std.math.maxInt(c_int));

        if (self.ssl == null) {
            return TlsError.InvalidContext;
        }
        var bytes_written_offset: u32 = 0;
        while (bytes_written_offset < write_data.len) {
            const ssl_connection = self.ssl.?;
            const remaining_bytes = write_data.len - bytes_written_offset;
            const remaining_bytes_int: c_int = @intCast(remaining_bytes);
            const bytes_written_count = boringssl.SSL_write(ssl_connection, write_data.ptr + bytes_written_offset, remaining_bytes_int);
            if (bytes_written_count <= 0) {
                const ssl_error_code = boringssl.SSL_get_error(ssl_connection, bytes_written_count);
                switch (ssl_error_code) {
                    boringssl.SSL_ERROR_WANT_READ, boringssl.SSL_ERROR_WANT_WRITE => return TlsError.WouldBlock,
                    else => {
                        const error_message =
                            boringssl.ERR_error_string(@intCast(ssl_error_code), null);
                        std.debug.print(
                            "SSL_write error: code={d} msg={s}\n",
                            .{ ssl_error_code, error_message },
                        );
                        return TlsError.WriteFailed;
                    },
                }
            }
            // Increase offset by the number of bytes written, cast to u32.
            bytes_written_offset += @intCast(bytes_written_count);
        }
    }
};
