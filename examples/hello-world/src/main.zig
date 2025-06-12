const std = @import("std");
const http2 = @import("http2");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Starting HTTP/2 server with TLS...\n", .{});
    try run_tls_http2(allocator);
}

fn run_tls_http2(allocator: std.mem.Allocator) !void {
    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    var tls_ctx = try http2.tls.TlsServerContext.init(
        allocator,
        "cert.pem",
        "key.pem",
    );
    defer tls_ctx.deinit();

    std.debug.print("Listening on 127.0.0.1:9001 (TLS HTTP/2); press Ctrl-C to exit...\n", .{});

    while (true) {
        var conn = listener.accept() catch |err| {
            std.debug.print("Accept failed: {any}\n", .{err});
            continue;
        };

        handle_tls_connection(allocator, &tls_ctx, conn) catch |err| {
            std.debug.print("TLS connection handling failed: {any}\n", .{err});
        };

        conn.stream.close();
    }
}

fn handle_tls_connection(
    allocator: std.mem.Allocator,
    tls_ctx: *http2.tls.TlsServerContext,
    conn: std.net.Server.Connection,
) !void {
    std.debug.print("Accepted TLS connection from: {any}\n", .{conn.address});

    var tls_conn = try tls_ctx.accept(conn.stream.handle);
    defer tls_conn.deinit();

    const reader = tls_conn.reader().any();
    const writer = tls_conn.writer().any();

    var allocator_mut = allocator;

    var server_conn = http2.Connection(std.io.AnyReader, std.io.AnyWriter).init(&allocator_mut, reader, writer, true) catch |err| switch (err) {
        error.BrokenPipe, error.ConnectionResetByPeer => {
            return;
        },
        else => return err,
    };
    defer server_conn.deinit();

    server_conn.handle_connection() catch |err| switch (err) {
        error.BrokenPipe, error.ConnectionResetByPeer, error.UnexpectedEOF => {
            return;
        },
        error.ProtocolError, error.CompressionError, error.StreamClosed => {
            std.debug.print("Protocol error handled gracefully: {any}\n", .{err});
            return;
        },
        else => return err,
    };
}
