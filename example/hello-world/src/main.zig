const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Hpack = http2.Hpack.Hpack;

pub fn main() !void {
    var allocator = std.heap.page_allocator;
    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:9001; press Ctrl-C to exit...\n", .{});

    while (true) {
        var conn = try listener.accept();
        defer conn.stream.close();

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        var connection = try Connection.init(
            &allocator,
            conn.stream.reader().any(),
            conn.stream.writer().any(),
            true,
        );

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
        const frame = try http2.Frame.read(connection.reader, connection.allocator);

        std.debug.print(
            "Read FrameHeader: {d} bytes, type {s}, flags {d}, stream_id {d}\n",
            .{
                frame.header.length,
                @tagName(frame.header.frame_type),
                frame.header.flags.value,
                frame.header.stream_id,
            },
        );

        switch (frame.header.frame_type) {
            .SETTINGS => {
                std.debug.print("Received SETTINGS frame, sending ACK.\n", .{});
                try connection.sendSettingsAck();
            },
            .WINDOW_UPDATE => {
                std.debug.print("Received WINDOW_UPDATE frame.\n", .{});
                try connection.handleWindowUpdate(frame);
            },
            .PRIORITY => {
                std.debug.print("Received PRIORITY frame.\n", .{});
            },
            .HEADERS => {
                try handleHeaders(
                    connection,
                    &dynamic_table,
                    frame,
                    &method_found,
                    &path_found,
                    &scheme_found,
                    &authority_found,
                    &path,
                    &scheme,
                );
                break;
            },
            else => {
                std.debug.print("Unexpected frame type {s}\n", .{@tagName(frame.header.frame_type)});
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
    frame: http2.Frame,
    method_found: *bool,
    path_found: *bool,
    scheme_found: *bool,
    authority_found: *bool,
    path: *[]const u8,
    scheme: *[]const u8,
) !void {
    std.debug.print("Received HEADERS frame.\n", .{});
    std.debug.print("Payload: {s}\n", .{frame.payload});

    var payload_index: usize = 0;
    while (payload_index < frame.payload.len) {
        const remaining_payload = frame.payload[payload_index..];

        // Use connection's allocator
        var decoded = try Hpack.decodeHeaderField(remaining_payload, dynamic_table, connection.allocator);
        defer decoded.deinit();

        // Update the payload index based on how many bytes were consumed
        payload_index += decoded.bytes_consumed;

        std.debug.print("Decoded header: {s} = {s}\n", .{ decoded.header.name, decoded.header.value });

        if (std.mem.eql(u8, decoded.header.name, ":method")) {
            method_found.* = true;
            std.debug.print("Found :method = {s}\n", .{decoded.header.value});
        } else if (std.mem.eql(u8, decoded.header.name, ":path")) {
            path_found.* = true;
            path.* = decoded.header.value;
            std.debug.print("Found :path = {s}\n", .{decoded.header.value});
        } else if (std.mem.eql(u8, decoded.header.name, ":scheme")) {
            scheme_found.* = true;
            scheme.* = decoded.header.value;
            std.debug.print("Found :scheme = {s}\n", .{decoded.header.value});
        } else if (std.mem.eql(u8, decoded.header.name, ":authority")) {
            authority_found.* = true;
            std.debug.print("Found :authority = {s}\n", .{decoded.header.value});
        }
    }

    try connection.sendResponse(frame.header.stream_id);
}

pub fn sendResponse(self: *Connection, stream_id: u31) !void {
    var dynamic_table = try Hpack.DynamicTable.init(self.allocator, 4096, 4096);
    defer dynamic_table.table.deinit();

    const response_headers = [_]Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    };

    var encoded_headers_list = std.ArrayList(u8).init(self.allocator);
    defer encoded_headers_list.deinit();

    // Keep track of allocated encoded headers for later deallocation
    var encoded_headers = std.ArrayList([]const u8).init(self.allocator);
    defer encoded_headers.deinit();

    for (response_headers) |header| {
        const encoded_header = try Hpack.encodeHeaderField(header, &dynamic_table, self.allocator);
        try encoded_headers_list.appendSlice(encoded_header);
        // Store the allocated slice for later deallocation
        try encoded_headers.append(encoded_header);
    }

    // Send HEADERS frame
    var headers_frame = http2.Frame{
        .header = http2.FrameHeader{
            .length = @intCast(encoded_headers_list.items.len),
            .frame_type = .HEADERS,
            .flags = http2.FrameFlags{ .value = http2.FrameFlags.END_HEADERS },
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = encoded_headers_list.items,
    };
    try headers_frame.write(self.writer);

    // Now it's safe to free the allocated encoded headers
    for (encoded_headers.items) |encoded_header| {
        self.allocator.free(encoded_header);
    }

    // Send DATA frame with "Hello, World!" body
    const response_body = "Hello, World!";
    var data_frame = http2.Frame{
        .header = http2.FrameHeader{
            .length = @intCast(response_body.len),
            .frame_type = .DATA,
            .flags = http2.FrameFlags{ .value = http2.FrameFlags.END_STREAM },
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = response_body,
    };
    try data_frame.write(self.writer);

    try self.writer.flush();
}
