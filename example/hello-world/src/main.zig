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
    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
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

pub fn processConnection(connection: *Connection) !void {
    var dynamic_table = try Hpack.DynamicTable.init(connection.allocator, 4096);
    defer dynamic_table.table.deinit();

    var method_found = false;
    var path_found = false;
    var scheme_found = false;
    var authority_found = false;
    var path: []const u8 = "/"; // Default to "/"
    var scheme: []const u8 = "https"; // Default to "https"

    while (true) {
        const frame = try Frame.read(connection.reader, connection.allocator);

        std.debug.print("Read FrameHeader: frame.FrameHeader{{ .length = {d}, .frame_type = {any}, .flags = {any}, .reserved = {any}, .stream_id = {d} }}\n", .{ frame.header.length, @intFromEnum(frame.header.frame_type), frame.header.flags.value, frame.header.reserved, frame.header.stream_id });

        if (frame.header.frame_type == FrameType.SETTINGS) {
            std.debug.print("Received SETTINGS frame, acknowledging.\n", .{});
            try connection.sendSettingsAck();
        } else if (frame.header.frame_type == FrameType.WINDOW_UPDATE) {
            std.debug.print("Received WINDOW_UPDATE frame, stream ID: {d}\n", .{frame.header.stream_id});
            try connection.handleWindowUpdate(frame);
        } else if (frame.header.frame_type == FrameType.HEADERS) {
            std.debug.print("Received HEADERS frame, payload length: {d}, stream_id: {d}\n", .{ frame.header.length, frame.header.stream_id });
            std.debug.print("Raw frame payload (hex): ", .{});
            for (frame.payload) |byte| {
                std.debug.print("{x} ", .{byte});
            }
            std.debug.print("\n", .{});

            // Decode the header fields using HPACK
            const decoded_header = try Hpack.decodeHeaderField(frame.payload, &dynamic_table);
            std.debug.print("Decoded header: {s} = {any}\n", .{ decoded_header.name, decoded_header.value });

            // Handle pseudo-headers
            if (std.mem.eql(u8, decoded_header.name, ":method")) {
                method_found = true;
                std.debug.print("Found :method = {s}\n", .{decoded_header.value});
            } else if (std.mem.eql(u8, decoded_header.name, ":path")) {
                path_found = true;
                path = decoded_header.value;
                std.debug.print("Found :path = {s}\n", .{decoded_header.value});
            } else if (std.mem.eql(u8, decoded_header.name, ":scheme")) {
                scheme_found = true;
                scheme = decoded_header.value;
                std.debug.print("Found :scheme = {s}\n", .{decoded_header.value});
            } else if (std.mem.eql(u8, decoded_header.name, ":authority")) {
                authority_found = true;
                std.debug.print("Found :authority = {s}\n", .{decoded_header.value});
            } else if (frame.header.frame_type == FrameType.PRIORITY) {
                std.debug.print("Received PRIORITY frame, stream ID: {d}\n", .{frame.header.stream_id});
                // Optionally handle priority logic here.
                // For now, we simply acknowledge receiving it.
            }

            // After decoding, respond to the client
            try connection.sendResponse(frame.header.stream_id);
            break; // Stop the loop after sending the response
        } else {
            std.debug.print("Unexpected frame type: {any}\n", .{@intFromEnum(frame.header.frame_type)});
        }
    }

    // Ensure required pseudo-headers are present
    if (!method_found) return error.MissingMethod;
    if (!path_found) {
        std.debug.print("Path not found, using default path '/'.\n", .{});
        path = "/"; // Set default path if none is provided
    }
    if (!scheme_found) {
        std.debug.print("Scheme not found, using default scheme 'https'.\n", .{});
        scheme = "https"; // Set default scheme if none is provided
    }

    // Use the `path` and `scheme` variables in your processing logic as needed

    // Close the connection gracefully after response is sent
    try connection.close();
}

pub fn sendResponse(self: *@This(), stream_id: u31) !void {
    var dynamic_table = try Hpack.DynamicTable.init(self.allocator, 4096);
    defer dynamic_table.table.deinit();

    // Define the response headers
    // Define the headers to be sent, using static index where possible
    const response_headers = [_]Hpack.HeaderField{
        Hpack.HeaderField{ .name = ":status", .value = "200" },
        Hpack.HeaderField{ .name = "content-type", .value = "text/plain" },
        Hpack.HeaderField{ .name = ":method", .value = "GET" }, // Example of using the :method pseudo-header
    };

    // Allocate buffer for encoded headers
    var encoded_headers = try self.allocator.alloc(u8, 1024);
    var header_len: usize = 0;

    // Iterate over headers and encode using HPACK
    for (response_headers) |header| {
        const static_index = Hpack.StaticTable.getStaticIndex(header.name, header.value);
        if (static_index != null) {
            std.debug.print("Using static index for header: {s} = {s}, index: {d}\n", .{ header.name, header.value, static_index.? });
            encoded_headers[header_len] = 0x80 | static_index.?; // HPACK indexed header field
            header_len += 1;
        } else {
            // Encode as literal header field without indexing
            encoded_headers[header_len] = 0x00; // Literal Header without indexing
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

            std.debug.print("Encoded literal header: {s} = {s}, total bytes: {d}\n", .{ header.name, header.value, header_len });
        }
    }

    std.debug.print("Total encoded headers length: {d}\n", .{header_len});

    // Print encoded headers in hex for verification
    std.debug.print("Encoded headers (hex): ", .{});
    for (0..header_len) |i| {
        std.debug.print("{x} ", .{encoded_headers[i]});
    }
    std.debug.print("\n", .{});

    // Sending HEADERS frame
    var headers_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(header_len),
            .frame_type = .HEADERS,
            .flags = FrameFlags{ .value = FrameFlags.END_HEADERS },
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = encoded_headers[0..header_len],
    };
    try headers_frame.write(self.writer);

    // Send DATA frame
    const response_body = "Hello, World!";
    var data_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(response_body.len),
            .frame_type = .DATA,
            .flags = FrameFlags{ .value = FrameFlags.END_STREAM },
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = response_body,
    };
    try data_frame.write(self.writer);

    std.debug.print("Sent DATA frame with payload length: {d}, END_STREAM flag set.\n", .{response_body.len});

    // Flush the writer to ensure all data is sent
    try self.writer.flush();

    std.debug.print("Finished sending response, stream {d}.\n", .{stream_id});
}
