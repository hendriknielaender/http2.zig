const std = @import("std");
const http2 = @import("http2/connection.zig");
const hpack = @import("http2/hpack.zig");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Hpack = hpack.Hpack;

pub fn main() !void {
    const address = try std.net.Address.resolveIp("0.0.0.0", 8081);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:8081...\n", .{});

    while (true) {
        var conn = try listener.accept();
        //defer conn.stream.close(); // Ensure stream is closed

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        var server_conn = Connection.init(@constCast(&std.heap.page_allocator), conn.stream.reader().any(), conn.stream.writer().any(), true) catch |err| {
            if (err == error.InvalidPreface) {
                std.debug.print("Invalid HTTP/2 preface, closing connection\n", .{});
            } else if (err == error.BrokenPipe) {
                std.debug.print("Client disconnected (BrokenPipe)\n", .{});
            } else {
                std.debug.print("Error during connection initialization: {s}\n", .{@errorName(err)});
            }
            continue; // Continue accepting new connections after handling error
        };

        // Handle the HTTP/2 connection
        server_conn.handleConnection() catch |err| {
            if (err == error.BrokenPipe) {
                std.debug.print("Client disconnected (BrokenPipe)\n", .{});
            } else {
                std.debug.print("Error handling connection: {s}\n", .{@errorName(err)});
            }
        };
        std.debug.print("Connection from {any} closed\n", .{conn.address});
    }
}
