const std = @import("std");
const http2 = @import("http2/connection.zig");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);

pub fn main() !void {
    // Setup a TCP listener on port 8080
    const address = try std.net.Address.resolveIp("127.0.0.1", 8080);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:8080...\n", .{});

    while (true) {
        // Accept a new TCP connection
        var conn = try listener.accept();
        defer conn.stream.close();

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        // Create a new HTTP/2 connection
        var server_conn = try Connection.init(@constCast(&std.heap.page_allocator), conn.stream.reader().any(), conn.stream.writer().any(), true);
        // defer server_conn.deinit();

        // Handle the HTTP/2 connection, including the SETTINGS frame and initial preface
        try handleHttp2Connection(&server_conn);
    }
}

fn handleHttp2Connection(server_conn: *Connection) !void {
    // Send the SETTINGS frame to the client
    try server_conn.sendSettings();
    std.debug.print("Sent HTTP/2 SETTINGS frame\n", .{});

    // Loop to process incoming frames
    while (true) {
        // Receive an HTTP/2 frame
        const frame = try server_conn.receiveFrame();
        std.debug.print("Received frame of type: {s}, stream ID: {d}\n", .{ @tagName(frame.header.frame_type), frame.header.stream_id });

        // Handle different types of frames
        switch (frame.header.frame_type) {
            .SETTINGS => {
                std.debug.print("Received SETTINGS frame\n", .{});
                // Send an ACK for the SETTINGS frame
                try server_conn.sendSettingsAck();
                std.debug.print("Sent SETTINGS ACK\n", .{});
            },
            .PING => {
                std.debug.print("Received PING frame, responding with PONG\n", .{});
                // Send PONG frame in response to PING
                try server_conn.sendPong(frame.payload);
            },
            .WINDOW_UPDATE => {
                std.debug.print("Received WINDOW_UPDATE frame\n", .{});
                // Handle window updates (adjust send/recv window size)
                try server_conn.handleWindowUpdate(frame);
            },
            .HEADERS => {
                std.debug.print("Received HEADERS frame\n", .{});
                // Here you could implement header processing logic, e.g. parsing request headers
            },
            .DATA => {
                std.debug.print("Received DATA frame\n", .{});
                // Handle data frame, which could involve reading the payload and responding
            },
            .GOAWAY => {
                std.debug.print("Received GOAWAY frame, closing connection\n", .{});
                return; // Gracefully close connection on GOAWAY
            },
            else => {
                std.debug.print("Unhandled frame type: {s}\n", .{@tagName(frame.header.frame_type)});
            },
        }
    }
}
