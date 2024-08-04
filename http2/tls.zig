const std = @import("std");
const boringssl = @import("boringssl/boringssl-bindings.zig");

pub const TlsError = error{
    InitFailed,
    HandshakeFailed,
    WriteFailed,
    ReadFailed,
    InvalidContext,
    InvalidSocket,
};

pub const TlsContext = struct {
    ctx: ?*boringssl.SSL_CTX,
    ssl: ?*boringssl.SSL,
    allocator: *std.mem.Allocator,

    pub fn init(allocator: *std.mem.Allocator) !TlsContext {
        _ = boringssl.SSL_library_init();
        _ = boringssl.SSL_load_error_strings();

        const method = boringssl.SSLv23_method();
        if (method == null) return TlsError.InitFailed;

        const ctx = boringssl.SSL_CTX_new(method);
        if (ctx == null) return TlsError.InitFailed;

        return TlsContext{
            .ctx = ctx,
            .ssl = null,
            .allocator = allocator,
        };
    }

    pub fn connect(self: *TlsContext, fd: c_int) !void {
        if (fd == -1) return TlsError.InvalidSocket;

        self.ssl = boringssl.SSL_new(self.ctx);
        if (self.ssl == null) return TlsError.InvalidContext;

        // Load client certificate
        const client_cert_file = "client_cert.pem";
        const client_key_file = "client_key.pem";

        const max_bytes = std.math.maxInt(usize);
        const client_cert = try std.fs.cwd().readFileAlloc(self.allocator.*, client_cert_file, max_bytes);
        defer self.allocator.free(client_cert);

        const client_key = try std.fs.cwd().readFileAlloc(self.allocator.*, client_key_file, max_bytes);
        defer self.allocator.free(client_key);

        const cert_len: c_long = @intCast(client_cert.len);
        const bio_cert = boringssl.BIO_new_mem_buf(client_cert.ptr, cert_len);
        if (bio_cert == null) return TlsError.InvalidContext;
        defer _ = boringssl.BIO_free(bio_cert);

        const x509_cert = boringssl.PEM_read_bio_X509(bio_cert, null, null, null);
        if (x509_cert == null) return TlsError.InvalidContext;
        defer boringssl.X509_free(x509_cert);

        const client_len: c_long = @intCast(client_key.len);
        const bio_key = boringssl.BIO_new_mem_buf(client_key.ptr, client_len);
        if (bio_key == null) return TlsError.InvalidContext;
        defer _ = boringssl.BIO_free(bio_key);

        const pkey = boringssl.PEM_read_bio_PrivateKey(bio_key, null, null, null);
        if (pkey == null) return TlsError.InvalidContext;
        defer boringssl.EVP_PKEY_free(pkey);

        if (boringssl.SSL_use_certificate(self.ssl, x509_cert) != 1) {
            return TlsError.InvalidContext;
        }

        if (boringssl.SSL_use_PrivateKey(self.ssl, pkey) != 1) {
            return TlsError.InvalidContext;
        }

        if (boringssl.SSL_set_fd(self.ssl, @intCast(fd)) == 0) {
            return TlsError.InvalidContext;
        }

        std.debug.print("Attempting SSL connect...\n", .{});
        const result = boringssl.SSL_connect(self.ssl);
        if (result != 1) {
            const error_code: u32 = @intCast(boringssl.SSL_get_error(self.ssl, result));
            const error_str = boringssl.ERR_error_string(error_code, null);
            std.debug.print("SSL_connect failed with error code: {d}, error: {s}\n", .{ error_code, error_str });
            return TlsError.HandshakeFailed;
        }
        std.debug.print("SSL connect successful.\n", .{});
    }

    pub fn write(self: *TlsContext, data: []const u8) !void {
        if (self.ssl == null) return TlsError.InvalidContext;
        std.debug.print("Attempting SSL write...\n", .{});
        const bytes_written = boringssl.SSL_write(self.ssl, data.ptr, @intCast(data.len));
        if (bytes_written <= 0) {
            const error_code = boringssl.SSL_get_error(self.ssl, bytes_written);
            const error_str = boringssl.ERR_error_string(@intCast(error_code), null);
            std.debug.print("SSL_write failed with error code: {d}, error: {s}\n", .{ error_code, error_str });
            return TlsError.WriteFailed;
        }
        std.debug.print("SSL write successful.\n", .{});
    }

    pub fn read(self: *TlsContext, buffer: []u8) !usize {
        if (self.ssl == null) return TlsError.InvalidContext;
        std.debug.print("Attempting SSL read...\n", .{});

        const timeout_ms = 5000; // 5 seconds timeout
        const start_time = std.time.milliTimestamp();
        var ret: c_int = 0;

        while (true) {
            const current_time = std.time.milliTimestamp();
            const elapsed_time = current_time - start_time;
            std.debug.print("SSL_read loop: start_time={d}, current_time={d}, elapsed_time={d}\n", .{ start_time, current_time, elapsed_time });
            ret = boringssl.SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
            if (ret > 0) break;

            const error_code = boringssl.SSL_get_error(self.ssl, ret);
            std.debug.print("SSL_read result={d}, error_code={d}\n", .{ ret, error_code });
            if (error_code == boringssl.SSL_ERROR_WANT_READ or error_code == boringssl.SSL_ERROR_WANT_WRITE) {
                if (elapsed_time > timeout_ms) {
                    std.debug.print("SSL_read timed out after {d} milliseconds.\n", .{timeout_ms});
                    return TlsError.ReadFailed;
                }
                std.debug.print("SSL_read retrying after 10 milliseconds.\n", .{});
                std.time.sleep(10 * std.time.ns_per_ms); // Sleep for 10 milliseconds
                continue;
            } else {
                const error_str = boringssl.ERR_error_string(@intCast(error_code), null);
                std.debug.print("SSL_read failed with error code: {d}, error: {s}\n", .{ error_code, error_str });
                return TlsError.ReadFailed;
            }
        }

        std.debug.print("SSL read successful, read {d} bytes.\n", .{ret});
        return @intCast(ret);
    }

    pub fn deinit(self: *TlsContext) void {
        if (self.ssl) |ssl| {
            boringssl.SSL_free(ssl);
        }
        if (self.ctx) |ctx| {
            boringssl.SSL_CTX_free(ctx);
        }
    }
};

// Unit test for TLS context initialization and data transmission
test "TLS context initialization and encryption/decryption" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();

    std.debug.print("Initializing TLS context...\n", .{});
    var ctx = try TlsContext.init(&allocator);
    defer ctx.deinit();

    std.debug.print("Parsing server address...\n", .{});
    const server_address = "127.0.0.1";
    const server_port = 4433;
    const addr = try std.net.Address.parseIp(server_address, server_port);

    std.debug.print("Connecting to server...\n", .{});
    var conn = try std.net.tcpConnectToAddress(addr);
    defer conn.close();

    std.debug.print("Establishing TLS connection...\n", .{});
    try ctx.connect(conn.handle);

    const message = "Hello, secure world!";
    std.debug.print("Sending message: {s}\n", .{message});
    try ctx.write(message);

    std.debug.print("Reading response...\n", .{});
    var buffer: [1024]u8 = undefined;
    const len = try ctx.read(&buffer);
    const response = buffer[0..len];
    std.debug.print("Received: {s}\n", .{response});

    try std.testing.expect(response.len > 0);
}
