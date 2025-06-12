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

        // Configure ALPN for HTTP/2 negotiation.
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

    /// Accept a new TLS connection on the given TCP file descriptor, completing the server handshake.
    /// Returns a TlsServerConnection that wraps the SSL pointer.
    pub fn accept(self: *TlsServerContext, fd: std.posix.fd_t) !TlsServerConnection {
        if (self.ctx == null) {
            return TlsError.InvalidContext;
        }
        if (fd == -1) {
            return TlsError.InvalidSocket;
        }

        const ssl_ptr = boringssl.SSL_new(self.ctx);
        if (ssl_ptr == null) {
            return TlsError.InvalidContext;
        }

        // Convert fd to c_int using @intCast, since SSL_set_fd expects c_int.
        const c_fd: c_int = @intCast(fd);
        if (boringssl.SSL_set_fd(ssl_ptr, c_fd) == 0) {
            boringssl.SSL_free(ssl_ptr);
            return TlsError.InvalidContext;
        }

        // Transition SSL object into server (accept) mode.
        boringssl.SSL_set_accept_state(ssl_ptr);

        // Perform the server‐side TLS handshake. On success, returns 1.
        const handshake_res = boringssl.SSL_accept(ssl_ptr);
        if (handshake_res != 1) {
            const err_code = boringssl.SSL_get_error(ssl_ptr, handshake_res);
            const err_str = boringssl.ERR_error_string(@intCast(err_code), null);
            std.debug.print(
                "TLS handshake failed with code={d}, msg={s}\n",
                .{ err_code, err_str },
            );
            boringssl.SSL_free(ssl_ptr);
            return TlsError.HandshakeFailed;
        }

        return TlsServerConnection{
            .allocator = self.allocator,
            .ssl = ssl_ptr,
        };
    }

    /// Sets up ALPN callback for server-side protocol negotiation.
    /// For servers, we use SSL_CTX_set_alpn_select_cb instead of SSL_CTX_set_alpn_protos.
    fn set_alpn(self: *TlsServerContext, alpn_proto: []const u8) !void {
        _ = alpn_proto; // We'll hardcode "h2" in the callback for now
        
        // Set the ALPN selection callback for server-side negotiation
        boringssl.SSL_CTX_set_alpn_select_cb(self.ctx, alpn_select_callback, null);
    }
    
    /// ALPN selection callback - called when client sends ALPN extension
    fn alpn_select_callback(
        ssl: ?*boringssl.SSL,
        out: [*c][*c]const u8,
        outlen: [*c]u8,
        in: [*c]const u8,
        inlen: c_uint,
        arg: ?*anyopaque,
    ) callconv(.c) c_int {
        _ = ssl;
        _ = arg;
        
        // Search for "h2" in the client's ALPN list
        var offset: c_uint = 0;
        while (offset < inlen) {
            const proto_len = in[offset];
            if (offset + 1 + proto_len > inlen) break;
            
            // Check if this protocol is "h2"
            if (proto_len == 2 and 
                in[offset + 1] == 'h' and in[offset + 2] == '2') {
                // Found "h2" - select it
                out.* = in + offset + 1;
                outlen.* = 2;
                return boringssl.SSL_TLSEXT_ERR_OK;
            }
            
            offset += 1 + proto_len;
        }
        
        // "h2" not found in client list
        return boringssl.SSL_TLSEXT_ERR_NOACK;
    }

    /// Load server certificate and private key files (PEM) into the SSL_CTX.
    fn load_certificate_and_key(
        self: *TlsServerContext,
        cert_path: []const u8,
        key_path: []const u8,
    ) !void {
        // Read files fully into memory.
        const max_size = std.math.maxInt(usize);

        const cert_data = try std.fs.cwd().readFileAlloc(self.allocator, cert_path, max_size);
        defer self.allocator.free(cert_data);

        const key_data = try std.fs.cwd().readFileAlloc(self.allocator, key_path, max_size);
        defer self.allocator.free(key_data);

        // Load certificate from in‐memory bytes.
        const cert_len: c_long = @intCast(cert_data.len);
        const cert_bio = boringssl.BIO_new_mem_buf(cert_data.ptr, cert_len);
        if (cert_bio == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.BIO_free(cert_bio);

        const x509_cert = boringssl.PEM_read_bio_X509(cert_bio, null, null, null);
        if (x509_cert == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.X509_free(x509_cert);

        if (boringssl.SSL_CTX_use_certificate(self.ctx, x509_cert) != 1) {
            return TlsError.InitFailed;
        }

        // Load private key from in‐memory bytes.
        const key_len: c_long = @intCast(key_data.len);
        const key_bio = boringssl.BIO_new_mem_buf(key_data.ptr, key_len);
        if (key_bio == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.BIO_free(key_bio);

        const pkey = boringssl.PEM_read_bio_PrivateKey(key_bio, null, null, null);
        if (pkey == null) {
            return TlsError.InitFailed;
        }
        defer _ = boringssl.EVP_PKEY_free(pkey);

        if (boringssl.SSL_CTX_use_PrivateKey(self.ctx, pkey) != 1) {
            return TlsError.InitFailed;
        }

        // Verify the key matches the certificate.
        if (boringssl.SSL_CTX_check_private_key(self.ctx) != 1) {
            return TlsError.InitFailed;
        }
    }
};

/// A single server‐side TLS connection, post‐handshake, wrapping the SSL pointer.
/// You can retrieve a Reader/Writer pair to pass into your HTTP/2 library.
pub const TlsServerConnection = struct {
    allocator: std.mem.Allocator,
    ssl: ?*boringssl.SSL,

    /// Clean up SSL resources.
    pub fn deinit(self: *TlsServerConnection) void {
        if (self.ssl) |ssl_val| {
            boringssl.SSL_free(ssl_val);
        }
        self.ssl = null;
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
    fn read_tls(self: *TlsServerConnection, buffer: []u8) !usize {
        if (self.ssl == null) {
            return TlsError.InvalidContext;
        }
        if (buffer.len == 0) {
            return 0;
        }

        const ssl_val = self.ssl.?;
        const len_i: c_int = @intCast(buffer.len);
        const bytes_read = boringssl.SSL_read(ssl_val, buffer.ptr, len_i);
        if (bytes_read > 0) {
            // The function returns !usize, so let the compiler infer `usize` for @intCast.
            return @intCast(bytes_read);
        }

        // For <=0 return, check the error code.
        const err_code = boringssl.SSL_get_error(ssl_val, bytes_read);
        switch (err_code) {
            boringssl.SSL_ERROR_WANT_READ, boringssl.SSL_ERROR_WANT_WRITE => return TlsError.WouldBlock,
            else => {
                const err_str = boringssl.ERR_error_string(@intCast(err_code), null);
                std.debug.print(
                    "SSL_read error: code={d} msg={s}\n",
                    .{ err_code, err_str },
                );
                return TlsError.ReadFailed;
            },
        }
    }

    /// Write all `data` through SSL_write until fully consumed or error.
    fn write_tls(self: *TlsServerConnection, data: []const u8) !void {
        if (self.ssl == null) {
            return TlsError.InvalidContext;
        }
        var offset: usize = 0;
        while (offset < data.len) {
            const ssl_val = self.ssl.?;
            const remaining = data.len - offset;
            const rem_i: c_int = @intCast(remaining);
            const written = boringssl.SSL_write(ssl_val, data.ptr + offset, rem_i);
            if (written <= 0) {
                const err_code = boringssl.SSL_get_error(ssl_val, written);
                switch (err_code) {
                    boringssl.SSL_ERROR_WANT_READ, boringssl.SSL_ERROR_WANT_WRITE => return TlsError.WouldBlock,
                    else => {
                        const err_str =
                            boringssl.ERR_error_string(@intCast(err_code), null);
                        std.debug.print(
                            "SSL_write error: code={d} msg={s}\n",
                            .{ err_code, err_str },
                        );
                        return TlsError.WriteFailed;
                    },
                }
            }
            // Increase offset by the number of bytes written, cast to usize.
            offset += @intCast(written);
        }
    }
};
