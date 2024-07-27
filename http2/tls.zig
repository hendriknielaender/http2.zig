const std = @import("std");

// Import generated BoringSSL bindings
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

        if (boringssl.SSL_set_fd(self.ssl, @intCast(fd)) == 0) {
            return TlsError.InvalidContext;
        }

        if (boringssl.SSL_connect(self.ssl) != 1) {
            return TlsError.HandshakeFailed;
        }
    }

    pub fn write(self: *TlsContext, data: []const u8) !void {
        if (self.ssl == null) return TlsError.InvalidContext;
        if (boringssl.SSL_write(self.ssl, data.ptr, @intCast(data.len)) <= 0) {
            return TlsError.WriteFailed;
        }
    }

    pub fn read(self: *TlsContext, buffer: []u8) !usize {
        if (self.ssl == null) return TlsError.InvalidContext;
        const ret = boringssl.SSL_read(self.ssl, buffer.ptr, @intCast(buffer.len));
        if (ret <= 0) return TlsError.ReadFailed;
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

    var ctx = try TlsContext.init(&allocator);
    defer ctx.deinit();

    // Test environment setup - connect to a test server
    // For actual tests, a local TLS server or a mock server is required
    const server_address = "127.0.0.1";
    const server_port = 4433;
    const addr = try std.net.Address.parseIp(server_address, server_port);
    var conn = try std.net.tcpConnectToAddress(addr);
    defer conn.close();

    try ctx.connect(conn.handle);

    // Test writing data
    const message = "Hello, secure world!";
    try ctx.write(message);

    // Test reading data
    var buffer: [1024]u8 = undefined;
    const len = try ctx.read(&buffer);
    const response = buffer[0..len];
    std.debug.print("Received: {s}\n", .{response});

    try std.testing.expect(response.len > 0);
}
