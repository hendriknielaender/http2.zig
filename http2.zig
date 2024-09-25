const std = @import("std");
const http2 = @import("http2/connection.zig");
const hpack = @import("http2/hpack.zig");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Hpack = hpack.Hpack;

pub fn main() !void {
    const address = try std.net.Address.resolveIp("0.0.0.0", 8080);

    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:8080...\n", .{});

    while (true) {
        var conn = try listener.accept();
        defer conn.stream.close(); // Ensure stream is closed

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        var server_conn = Connection.init(@constCast(&std.heap.page_allocator), conn.stream.reader().any(), conn.stream.writer().any(), true) catch |err| {
            if (err == error.InvalidPreface) {
                std.debug.print("Invalid HTTP/2 preface, closing connection\n", .{});
                // Connection will close after GOAWAY is sent
            } else if (err == error.BrokenPipe) {
                std.debug.print("Client disconnected (BrokenPipe)\n", .{});
            } else {
                std.debug.print("Error during connection initialization: {s}\n", .{@errorName(err)});
            }
            continue; // Continue accepting new connections after handling error
        };

        handleHttp2Connection(&server_conn) catch |err| {
            if (err == error.BrokenPipe) {
                std.debug.print("Client disconnected (BrokenPipe)\n", .{});
            } else {
                std.debug.print("Error handling connection: {s}\n", .{@errorName(err)});
            }
        };

        std.debug.print("Closing connection from: {any}\n", .{conn.address});
    }
}

fn handleHttp2Connection(server_conn: *Connection) !void {
    // Send the SETTINGS frame to the client
    try server_conn.sendSettings();
    std.debug.print("Sent HTTP/2 SETTINGS frame\n", .{});

    // Loop to process incoming frames
    while (true) {
        const frame = server_conn.receiveFrame() catch |err| {
            if (err == error.BrokenPipe or err == error.ConnectionResetByPeer) {
                std.debug.print("Client disconnected: {any}\n", .{err});
                return server_conn.close();
            }
            return err;
        };

        std.debug.print("Received frame of type: {s}, stream ID: {d}\n", .{ @tagName(frame.header.frame_type), frame.header.stream_id });

        switch (frame.header.frame_type) {
            .SETTINGS => {
                std.debug.print("Received SETTINGS frame\n", .{});
                try server_conn.applyFrameSettings(frame);
                try server_conn.sendSettingsAck();
                std.debug.print("Sent SETTINGS ACK\n", .{});
            },
            .PING => {
                std.debug.print("Received PING frame, responding with PONG\n", .{});
                try server_conn.sendPong(frame.payload);
            },
            .WINDOW_UPDATE => {
                std.debug.print("Received WINDOW_UPDATE frame\n", .{});
                try server_conn.handleWindowUpdate(frame);
            },
            .HEADERS => {
                std.debug.print("Received HEADERS frame\n", .{});
                try processRequest(server_conn, frame.header.stream_id);
            },
            .DATA => {
                std.debug.print("Received DATA frame\n", .{});
                // Handle data frame
            },
            .GOAWAY => {
                std.debug.print("Received GOAWAY frame, closing connection\n", .{});
                return server_conn.close();
            },
            else => {
                std.debug.print("Unknown frame type: {s}\n", .{@tagName(frame.header.frame_type)});
            },
        }
    }
}

fn processRequest(server_conn: *Connection, stream_id: u31) !void {
    std.debug.print("Processing request for stream ID: {d}\n", .{stream_id});
    var dynamic_table = try Hpack.DynamicTable.init(@constCast(&std.heap.page_allocator), 4096); // Initialize dynamic table with 4KB size

    // Prepare a basic response: "Hello, World!"
    const response_body = "Hello, World!";
    const response_headers = [_]Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    };

    var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buffer.deinit();

    // Encode headers and write them to the buffer
    for (response_headers) |header| {
        try Hpack.encodeHeaderField(header, &dynamic_table, &buffer);
    }

    const encoded_headers = buffer.items;

    // Send HEADERS frame
    var headers_frame = http2.Frame{
        .header = http2.FrameHeader{
            .length = @intCast(encoded_headers.len),
            .frame_type = .HEADERS,
            .flags = http2.FrameFlags{
                .value = http2.FrameFlags.END_HEADERS, // Mark end of headers
            },
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = encoded_headers,
    };
    try headers_frame.write(server_conn.writer);

    // Send DATA frame with "Hello, World!" response
    var data_frame = http2.Frame{
        .header = http2.FrameHeader{
            .length = @intCast(response_body.len),
            .frame_type = .DATA,
            .flags = http2.FrameFlags{
                .value = http2.FrameFlags.END_STREAM, // Mark end of stream
            },
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = response_body,
    };
    try data_frame.write(server_conn.writer);

    std.debug.print("Sent 200 OK response with body: \"Hello, World!\"\n", .{});
}
