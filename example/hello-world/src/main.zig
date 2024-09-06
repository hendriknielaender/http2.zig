const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Stream = http2.Stream;
const FrameFlags = http2.FrameFlags;
const FrameHeader = http2.FrameHeader;
const FrameType = http2.FrameType;
const Frame = http2.Frame;
const Hpack = http2.Hpack.Hpack;

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
    while (true) {
        const frame = try connection.receiveFrame();

        std.debug.print("Processing frame: {any}\n", .{frame.header.frame_type});

        switch (frame.header.frame_type) {
            .SETTINGS => {
                try connection.applyFrameSettings(frame);
                try connection.sendSettingsAck();
            },
            .HEADERS => {
                // Process incoming headers frame
                var dynamic_table = try Hpack.DynamicTable.init(connection.allocator, 4096);
                defer dynamic_table.table.deinit();

                const decoded_header = try Hpack.decodeHeaderField(frame.payload, &dynamic_table);
                std.debug.print("Decoded header: {s} = {s}\n", .{ decoded_header.name, decoded_header.value });

                // Send HTTP/2 response after headers are received
                try connection.sendResponse(frame.header.stream_id);
            },
            else => {
                std.debug.print("Ignoring frame of type: {any}\n", .{frame.header.frame_type});
            },
        }
    }
}

fn sendHelloWorldResponse(connection: *Connection, stream_id: u31) !void {
    // Ensure the :status pseudo-header is present
    const status_field = Hpack.HeaderField.init(":status", "200");

    // Use HPACK to encode the headers
    var dynamic_table = try Hpack.DynamicTable.init(connection.allocator, 4096);
    defer dynamic_table.table.deinit();

    const encoded_headers = try Hpack.encodeHeaderField(status_field, &dynamic_table);
    defer connection.allocator.free(encoded_headers);

    // Write the headers frame with END_HEADERS flag
    var response_headers = Frame.init(FrameHeader{
        .length = @intCast(encoded_headers.len),
        .frame_type = FrameType.HEADERS,
        .flags = FrameFlags.init(FrameFlags.END_HEADERS),
        .reserved = false,
        .stream_id = stream_id,
    }, encoded_headers);

    try response_headers.write(connection.writer);

    // Write the "Hello, World!" message with the END_STREAM flag
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