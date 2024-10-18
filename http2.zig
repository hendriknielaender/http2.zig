const std = @import("std");
const http2 = @import("http2/connection.zig");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);

pub fn main() !void {
    const address = try std.net.Address.resolveIp("0.0.0.0", 8081);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:8081...\n", .{});

    while (true) {
        var conn = try listener.accept();
        defer conn.stream.close(); // Ensure the stream is closed after handling the connection

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        var server_conn = Connection.init(@constCast(&std.heap.page_allocator), conn.stream.reader().any(), conn.stream.writer().any(), true) catch |err| {
            std.debug.print("Failed to initialize connection: {}\n", .{err});
            continue;
        };
        defer server_conn.deinit();

        // Handle connection and errors during the process
        server_conn.handle_connection() catch |err| {
            std.debug.print("Error handling connection: {}\n", .{err});
            // Optionally, send a GOAWAY frame or perform other cleanup
        };

        std.debug.print("Connection from {any} closed\n", .{conn.address});
    }
}
