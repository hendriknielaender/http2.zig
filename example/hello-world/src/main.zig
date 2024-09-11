const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const FrameFlags = http2.FrameFlags;
const FrameHeader = http2.FrameHeader;
const FrameType = http2.FrameType;
const Frame = http2.Frame;
const Hpack = http2.Hpack.Hpack;

pub fn main() !void {
    var allocator = std.heap.page_allocator;
    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 0.0.0.0:9001; press Ctrl-C to exit...\n", .{});

    while (true) {
        var con = try listener.accept();
        defer con.stream.close();
        std.debug.print("Accepted Connection from: {any}\n", .{con.address});

        var connection = try Connection.init(&allocator, con.stream.reader().any(), con.stream.writer().any(), true);
        try processConnection(&connection);
    }
}

fn processConnection(connection: *Connection) !void {
    var dynamic_table = try Hpack.DynamicTable.init(connection.allocator, 4096);
    defer dynamic_table.table.deinit();

    var method_found = false;
    var path_found = false;
    var scheme_found = false;
    var authority_found = false;
    var path: []const u8 = "/";
    var scheme: []const u8 = "https";

    while (true) {
        const frame = try Frame.read(connection.reader, connection.allocator);

        std.debug.print("Read FrameHeader: {any} bytes, type {any}, flags {any}, stream_id {any}\n", .{ frame.header.length, @intFromEnum(frame.header.frame_type), frame.header.flags.value, frame.header.stream_id });

        switch (frame.header.frame_type) {
            FrameType.SETTINGS => {
                std.debug.print("Received SETTINGS frame, sending ACK.\n", .{});
                try connection.sendSettingsAck();
            },
            FrameType.WINDOW_UPDATE => {
                std.debug.print("Received WINDOW_UPDATE frame.\n", .{});
                try connection.handleWindowUpdate(frame);
            },
            FrameType.PRIORITY => {
                std.debug.print("Received PRIORITY frame.\n", .{});
            },
            FrameType.HEADERS => {
                try handleHeaders(connection, &dynamic_table, frame, &method_found, &path_found, &scheme_found, &authority_found, &path, &scheme);
                break;
            },
            else => {
                std.debug.print("Unexpected frame type {any}\n", .{@intFromEnum(frame.header.frame_type)});
            },
        }
    }

    if (!method_found) return error.MissingMethod;
    if (!path_found) path = "/";
    if (!scheme_found) scheme = "https";

    try connection.close();
}

fn handleHeaders(
    connection: *Connection,
    dynamic_table: *Hpack.DynamicTable,
    frame: Frame,
    method_found: *bool,
    path_found: *bool,
    scheme_found: *bool,
    authority_found: *bool,
    path: *[]const u8,
    scheme: *[]const u8,
) !void {
    std.debug.print("Received HEADERS frame.\n", .{});
    std.debug.print("Payload: {any}\n", .{frame.payload});

    const decoded_header = try Hpack.decodeHeaderField(frame.payload, dynamic_table);

    std.debug.print("Decoded header: {any} = {any}\n", .{ decoded_header.name, decoded_header.value });

    if (std.mem.eql(u8, decoded_header.name, ":method")) {
        method_found.* = true;
        std.debug.print("Found :method = {any}\n", .{decoded_header.value});
    } else if (std.mem.eql(u8, decoded_header.name, ":path")) {
        path_found.* = true;
        path.* = decoded_header.value;
        std.debug.print("Found :path = {any}\n", .{decoded_header.value});
    } else if (std.mem.eql(u8, decoded_header.name, ":scheme")) {
        scheme_found.* = true;
        scheme.* = decoded_header.value;
        std.debug.print("Found :scheme = {any}\n", .{decoded_header.value});
    } else if (std.mem.eql(u8, decoded_header.name, ":authority")) {
        authority_found.* = true;
        std.debug.print("Found :authority = {any}\n", .{decoded_header.value});
    }

    try connection.sendResponse(frame.header.stream_id);
}

pub fn sendResponse(self: *@This(), stream_id: u31) !void {
    var dynamic_table = try Hpack.DynamicTable.init(self.allocator, 4096);
    defer dynamic_table.table.deinit();

    // Define the response headers in the correct order
    const response_headers = [_]Hpack.HeaderField{
        Hpack.HeaderField{ .name = ":status", .value = "200" },
        Hpack.HeaderField{ .name = "content-type", .value = "text/plain" },
    };

    var encoded_headers = try self.allocator.alloc(u8, 1024);
    defer self.allocator.free(encoded_headers);
    var header_len: usize = 0;

    // Encode headers using HPACK
    for (response_headers) |header| {
        const static_index = Hpack.StaticTable.getStaticIndex(header.name, header.value);
        if (static_index) |index| {
            encoded_headers[header_len] = 0x80 | index; // Use indexed representation
            header_len += 1;
        } else {
            encoded_headers[header_len] = 0x00; // Literal header without indexing
            header_len += 1;

            // Encode header name
            const name_bytes = header.name;
            encoded_headers[header_len] = @intCast(name_bytes.len);
            header_len += 1;
            try std.mem.copy(u8, encoded_headers[header_len..], name_bytes);
            header_len += name_bytes.len;

            // Encode header value
            const value_bytes = header.value;
            encoded_headers[header_len] = @intCast(value_bytes.len);
            header_len += 1;
            try std.mem.copy(u8, encoded_headers[header_len..], value_bytes);
            header_len += value_bytes.len;
        }
    }

    std.debug.print("Total encoded headers length: {d}\n", .{header_len});
    std.debug.print("Encoded headers (hex): ");
    for (0..header_len) |i| {
        std.debug.print("{x} ", .{encoded_headers[i]});
    }
    std.debug.print("\n", .{});

    // Send HEADERS frame
    var headers_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(header_len),
            .frame_type = .HEADERS,
            .flags = FrameFlags{ .value = FrameFlags.END_HEADERS }, // Ensure END_HEADERS flag is set
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = encoded_headers[0..header_len],
    };
    try headers_frame.write(self.writer);

    // Send DATA frame with "Hello, World!" body
    const response_body = "Hello, World!";
    var data_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(response_body.len),
            .frame_type = .DATA,
            .flags = FrameFlags{ .value = FrameFlags.END_STREAM }, // Set END_STREAM flag
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = response_body,
    };
    try data_frame.write(self.writer);

    try self.writer.flush();
}

fn encodeLiteralHeader(dest: []u8, header: Hpack.HeaderField) !usize {
    var len: usize = 0;
    dest[len] = 0x00;
    len += 1;

    dest[len] = @intCast(header.name.len);
    len += 1;
    std.mem.copy(u8, dest[len..], header.name) catch return error.BufferTooSmall;
    len += header.name.len;

    dest[len] = @intCast(header.value.len);
    len += 1;
    std.mem.copy(u8, dest[len..], header.value) catch return error.BufferTooSmall;
    len += header.value.len;

    return len;
}
