const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Stream = http2.Stream;
const FrameFlags = http2.FrameFlags;
const FrameHeader = http2.FrameHeader;
const FrameType = http2.FrameType;
const Frame = http2.Frame;

pub fn main() !void {
    var allocator = std.heap.page_allocator; // Changed 'const' to 'var' to make it mutable
    const address = try std.net.Address.resolveIp("0.0.0.0", 9001);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    std.debug.print("Listening on 0.0.0.0:9001; press Ctrl-C to exit...\n", .{});

    while (true) {
        var con = try listener.accept();
        defer con.stream.close();
        std.debug.print("Accepted Connection from: {any}\n", .{con.address});

        const reader = con.stream.reader().any();
        const writer = con.stream.writer().any();

        // Pass the mutable allocator to Connection.init
        var connection = try Connection.init(&allocator, reader, writer, true);

        try processConnection(&connection);
    }
}

fn processConnection(connection: *Connection) !void {
    try connection.sendSettings();

    while (true) {
        const frame = try Frame.read(connection.reader, connection.allocator);

        std.debug.print("Processing frame: {any}\n", .{frame.header.frame_type});

        switch (frame.header.frame_type) {
            .SETTINGS => {
                std.debug.print("Processing SETTINGS frame.\n", .{});
                try connection.applyFrameSettings(frame);
                try connection.sendSettingsAck();
            },
            .HEADERS => {
                std.debug.print("Processing HEADERS frame.\n", .{});
                try sendHelloWorldResponse(connection, frame.header.stream_id);
            },
            .RST_STREAM => {
                std.debug.print("Processing RST_STREAM frame.\n", .{});
                return; // Stop processing this connection
            },
            else => {
                std.debug.print("Ignoring frame of type: {any}\n", .{@tagName(frame.header.frame_type)});
            },
        }
    }
}

fn sendHelloWorldResponse(connection: *Connection, stream_id: u31) !void {
    const headers_payload = &[_]u8{ ':', 's', 't', 'a', 't', 'u', 's', '2', '0', '0' }; // HTTP/2 pseudo-header

    var response_headers = Frame.init(FrameHeader{
        .length = @intCast(headers_payload.len),
        .frame_type = FrameType.HEADERS,
        .flags = FrameFlags.init(FrameFlags.END_HEADERS),
        .reserved = false,
        .stream_id = stream_id,
    }, headers_payload);

    try response_headers.write(connection.writer);

    const hello_world_message = "Hello, World!";
    var data_frame = Frame.init(FrameHeader{
        .length = @intCast(hello_world_message.len),
        .frame_type = FrameType.DATA,
        .flags = FrameFlags.init(FrameFlags.END_STREAM),
        .reserved = false,
        .stream_id = stream_id,
    }, hello_world_message);

    try data_frame.write(connection.writer);

    std.debug.print("Sent 'Hello, World!' response.\n", .{});
}

/// Converts a hexadecimal string to a byte array.
/// Assumes the input string is well-formed and that `output` is large enough.
fn hexToBytes(hex: []const u8, output: *[8]u8) void {
    var i: usize = 0; // Explicitly declare `i` as a runtime integer type
    while (i < hex.len) : (i += 2) {
        const upper = parseHexDigit(hex[i]) << 4;
        const lower = parseHexDigit(hex[i + 1]);
        output[i / 2] = @intCast(upper | lower);
    }
}

fn parseHexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => @panic("Invalid hex digit"),
    };
}
