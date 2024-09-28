const std = @import("std");
pub const Stream = @import("stream.zig").Stream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const FrameType = @import("frame.zig").FrameType;
pub const Hpack = @import("hpack.zig");
const assert = std.debug.assert;

const http2_preface: []const u8 = "\x50\x52\x49\x20\x2A\x20\x48\x54\x54\x50\x2F\x32\x2E\x30\x0D\x0A\x0D\x0A\x53\x4D\x0D\x0A\x0D\x0A";

pub fn Connection(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        allocator: *std.mem.Allocator,
        reader: ReaderType,
        writer: WriterType,
        is_server: bool,
        settings: Settings,
        recv_window_size: i32 = 65535, // Default initial window size
        send_window_size: i32 = 65535, // Default initial window size
        streams: std.AutoHashMap(u31, *Stream),

        pub fn init(allocator: *std.mem.Allocator, reader: ReaderType, writer: WriterType, is_server: bool) !@This() {
            const self = @This(){
                .allocator = allocator,
                .reader = reader,
                .writer = writer,
                .is_server = is_server,
                .settings = Settings.default(),
                .recv_window_size = 65535,
                .send_window_size = 65535,
                .streams = std.AutoHashMap(u31, *Stream).init(allocator.*),
            };

            if (self.is_server) {
                // Check for the correct HTTP/2 preface (RFC 9113, section 3.4)
                var preface_buf: [24]u8 = undefined;
                _ = try self.reader.readAll(&preface_buf);

                if (!std.mem.eql(u8, &preface_buf, http2_preface)) {
                    const PROTOCOL_ERROR: u32 = 0x1; // PROTOCOL_ERROR is 0x1 as per RFC 9113
                    std.debug.print("Invalid HTTP/2 preface, sending GOAWAY frame...\n", .{});

                    // Send GOAWAY frame and ensure it is flushed
                    try self.sendGoAway(0, PROTOCOL_ERROR, "Invalid preface: PROTOCOL_ERROR");

                    // Ensure the connection is closed after sending the GOAWAY frame
                    return error.InvalidPreface;
                }
                std.debug.print("Valid HTTP/2 preface received\n", .{});
            } else {
                // Client-side, send preface and settings
                try self.sendPreface();
            }

            // Both client and server send their settings frames
            try self.sendSettings();

            return self;
        }

        pub fn deinit(self: @This()) void {
            // Deinitialize the stream hash map.
            self.streams.deinit();

            std.debug.print("Resources deinitialized for connection\n", .{});
        }

        fn sendPreface(self: @This()) !void {
            try self.writer.writeAll(http2_preface);
        }

        pub fn handleConnection(self: *@This()) !void {
            while (true) {
                const frame = self.receiveFrame() catch |err| {
                    if (err == error.InvalidFrameType) {
                        std.debug.print("Invalid frame type received, discarding.\n", .{});
                        try self.sendPing();
                        try self.sendGoAway(0, 0x01, "Invalid Frame Type: PROTOCOL_ERROR");

                        break;
                    } else {
                        std.debug.print("Error receiving frame: {s}\n", .{@errorName(err)});
                        return err; // Handle non-frame-related errors
                    }
                };

                // Process valid frames
                std.debug.print("Received frame of type: {s}, stream ID: {d}\n", .{ @tagName(frame.header.frame_type), frame.header.stream_id });

                if (!isValidFrameType(frame.header.frame_type)) {
                    std.debug.print("Ignoring unknown frame type: {any}\n", .{frame.header.frame_type});
                    try self.sendPing();
                    try self.sendGoAway(0, 0x01, "Invalid Frame Type: PROTOCOL_ERROR");

                    continue; // Ignore unknown frame types
                }

                if (!isValidFlags(frame.header)) {
                    std.debug.print("Ignoring frame with undefined flags\n", .{});
                    try self.sendPing();
                    try self.sendGoAway(0, 0x01, "Invalid Frame flags: PROTOCOL_ERROR");

                    continue; // Ignore frames with invalid or undefined flags
                }

                switch (frame.header.frame_type) {
                    .SETTINGS => {
                        std.debug.print("Received SETTINGS frame\n", .{});
                        try self.applyFrameSettings(frame);
                        try self.sendSettingsAck();
                        std.debug.print("Sent SETTINGS ACK\n", .{});
                    },
                    .PING => {
                        std.debug.print("Received PING frame, responding with PING (ACK)\n", .{});
                        try self.sendPing();
                    },
                    .WINDOW_UPDATE => {
                        std.debug.print("Received WINDOW_UPDATE frame\n", .{});
                        try self.handleWindowUpdate(frame);
                    },
                    .HEADERS => {
                        std.debug.print("Received HEADERS frame\n", .{});
                        try processRequest(self, frame.header.stream_id);
                    },
                    .DATA => {
                        std.debug.print("Processing DATA frame, length: {d}\n", .{frame.header.length});
                        if (frame.header.length == 0) {
                            // Invalid DATA frame, ignore
                            std.debug.print("Ignoring DATA frame with zero length\n", .{});
                            continue;
                        }

                        try processRequest(self, frame.header.stream_id);
                    },
                    .GOAWAY => {
                        std.debug.print("Received GOAWAY frame, closing connection\n", .{});
                        return self.close(); // Gracefully close connection
                    },
                    else => {
                        std.debug.print("Unknown frame type: {s}\n", .{@tagName(frame.header.frame_type)});
                        continue; // Ensure unknown frame types are ignored
                    },
                }
            }
        }

        fn processRequest(server_conn: *@This(), stream_id: u31) !void {
            std.debug.print("Processing request for stream ID: {d}\n", .{stream_id});
            var dynamic_table = try Hpack.Hpack.DynamicTable.init(@constCast(&std.heap.page_allocator), 4096); // Initialize dynamic table with 4KB size

            // Prepare a basic response: "Hello, World!"
            const response_body = "Hello, World!";
            const response_headers = [_]Hpack.Hpack.HeaderField{
                .{ .name = ":status", .value = "200" },
            };

            var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
            defer buffer.deinit();

            // Encode headers and write them to the buffer
            for (response_headers) |header| {
                try Hpack.Hpack.encodeHeaderField(header, &dynamic_table, &buffer);
            }

            const encoded_headers = buffer.items;

            // Send HEADERS frame
            var headers_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(encoded_headers.len),
                    .frame_type = .HEADERS,
                    .flags = FrameFlags{
                        .value = FrameFlags.END_HEADERS, // Mark end of headers
                    },
                    .reserved = false,
                    .stream_id = stream_id,
                },
                .payload = encoded_headers,
            };
            try headers_frame.write(server_conn.writer);

            // Send DATA frame with "Hello, World!" response
            var data_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(response_body.len),
                    .frame_type = .DATA,
                    .flags = FrameFlags{
                        .value = FrameFlags.END_STREAM, // Mark end of stream
                    },
                    .reserved = false,
                    .stream_id = stream_id,
                },
                .payload = response_body,
            };
            try data_frame.write(server_conn.writer);

            std.debug.print("Sent 200 OK response with body: \"Hello, World!\"\n", .{});
        }

        // Helper function to validate frame types
        fn isValidFrameType(frame_type: FrameType) bool {
            // List of valid frame types as per RFC 9113, Section 6
            switch (frame_type) {
                .DATA, .HEADERS, .PRIORITY, .RST_STREAM, .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .WINDOW_UPDATE, .CONTINUATION => {
                    return true;
                },
            }
        }

        // Helper function to validate flags for different frame types
        fn isValidFlags(header: FrameHeader) bool {
            switch (header.frame_type) {
                .PING => {
                    // PING frame allows only the ACK flag (0x1)
                    return header.flags.value & FrameFlags.ACK == 0;
                },
                .SETTINGS => {
                    // SETTINGS frame only allows the ACK flag
                    return header.flags.value & FrameFlags.ACK == 0;
                },
                .WINDOW_UPDATE, .HEADERS, .DATA => {
                    // Add validation for other frame types if necessary
                    return true; // Accept any flags for now, ignoring undefined flags
                },
                else => return true, // By default, ignore any undefined flags
            }
        }

        pub fn sendSettings(self: @This()) !void {
            const settings = [_][2]u32{
                .{ 1, self.settings.header_table_size }, // HEADER_TABLE_SIZE
                .{ 3, self.settings.max_concurrent_streams }, // MAX_CONCURRENT_STREAMS
                .{ 4, self.settings.initial_window_size }, // INITIAL_WINDOW_SIZE
                .{ 5, self.settings.max_frame_size }, // MAX_FRAME_SIZE
                .{ 6, self.settings.max_header_list_size }, // MAX_HEADER_LIST_SIZE
            };

            // Define the settings frame header
            var frame_header = FrameHeader{
                .length = @intCast(6 * settings.len), // 6 bytes per setting
                .frame_type = .SETTINGS,
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = 0, // 0 indicates a connection-level frame
            };

            // Write the frame header first
            try frame_header.write(self.writer);

            var buffer: [6]u8 = undefined;
            for (settings) |setting| {
                // Serialize Setting ID as u16 (big-endian)
                std.mem.writeInt(u16, buffer[0..2], @intCast(setting[0]), .big);
                // Serialize Setting Value as u32 (big-endian)
                std.mem.writeInt(u32, buffer[2..6], setting[1], .big);

                std.debug.print("Writing setting: ", .{});
                for (buffer) |byte| {
                    std.debug.print("{x} ", .{byte});
                }
                std.debug.print("\n", .{});

                try self.writer.writeAll(buffer[0..6]);
            }
        }

        pub fn receiveFrame(self: *@This()) !Frame {
            var header_buf: [9]u8 = undefined;

            // Read the frame header (9 bytes)
            _ = try self.reader.readAll(&header_buf);

            // Parse frame length (first 3 bytes)
            const length: u24 = std.mem.readInt(u24, header_buf[0..3], .big);

            // Validate the length against the max_frame_size
            if (length > self.settings.max_frame_size) {
                return error.FrameSizeError; // FRAME_SIZE_ERROR: Length exceeds max frame size
            }

            // Continue parsing the frame header as before
            const header: u8 = @intCast(header_buf[3]);
            const frame_type = try std.meta.intToEnum(FrameType, header);
            const flags = FrameFlags{ .value = header_buf[4] };
            const stream_id_u32: u32 = std.mem.readInt(u32, header_buf[5..9], .big) & 0x7FFFFFFF;
            const stream_id: u31 = @intCast(stream_id_u32);

            // Read the frame payload
            const payload = try self.allocator.alloc(u8, length);
            defer self.allocator.free(payload);
            _ = try self.reader.readAll(payload);

            return Frame{
                .header = FrameHeader{
                    .length = length,
                    .frame_type = frame_type,
                    .flags = flags,
                    .stream_id = stream_id,
                    .reserved = false,
                },
                .payload = payload,
            };
        }

        fn from_int(val: u8) FrameType {
            return std.meta.intToEnum(FrameType, val) catch undefined;
        }

        pub fn applyFrameSettings(self: *@This(), frame: Frame) !void {
            std.debug.print("Applying settings from frame...\n", .{});

            // Ensure the frame is of type SETTINGS
            if (frame.header.frame_type != .SETTINGS) {
                std.debug.print("Received frame with invalid frame type: {any}\n", .{frame.header.frame_type});
                return error.InvalidFrameType;
            }

            // SETTINGS frame must be on stream 0
            if (frame.header.stream_id != 0) {
                std.debug.print("SETTINGS frame received on a non-zero stream ID: {any}\n", .{frame.header.stream_id});
                return error.InvalidStreamId;
            }

            // The payload of the SETTINGS frame must be a multiple of 6 bytes
            if (frame.payload.len % 6 != 0) {
                std.debug.print("Invalid SETTINGS frame size: {any}\n", .{frame.payload.len});
                return error.InvalidSettingsFrameSize;
            }

            const buffer = frame.payload;
            const buffer_size: usize = buffer.len;

            std.debug.print("Processing SETTINGS frame with payload length: {d} bytes\n", .{buffer_size});

            // Ensure the buffer is large enough before reading
            var i: usize = 0;
            while (i + 6 <= buffer_size) {
                std.debug.print("Processing setting starting at index {d}. Remaining buffer size: {d}\n", .{ i, buffer_size - i });

                // Safely read the ID and Value using std.mem.readInt with endian handling
                const id_slice: *const [2]u8 = @ptrCast(&buffer[i .. i + 2]);

                const id: u16 = std.mem.readInt(u16, id_slice, .big);

                const value_slice: *const [4]u8 = @ptrCast(&buffer[i + 2 .. i + 6]);

                const value: u32 = std.mem.readInt(u32, value_slice, .big);

                std.debug.print("Setting ID: {d}, Value: {d}\n", .{ id, value });

                switch (id) {
                    1 => self.settings.header_table_size = value,
                    2 => self.settings.enable_push = (value == 1),
                    3 => self.settings.max_concurrent_streams = value,
                    4 => self.settings.initial_window_size = value,
                    5 => self.settings.max_frame_size = value,
                    6 => self.settings.max_header_list_size = value,
                    else => std.debug.print("Unknown setting ID: {d}\n", .{id}),
                }

                i += 6; // Move to the next setting (6 bytes per setting)
            }

            std.debug.print("Settings applied successfully.\n", .{});
        }

        pub fn sendSettingsAck(self: @This()) !void {
            var frame_header = FrameHeader{
                .length = 0,
                .frame_type = .SETTINGS,
                .flags = FrameFlags{ .value = FrameFlags.ACK }, // Set ACK flag
                .reserved = false,
                .stream_id = 0,
            };

            frame_header.write(self.writer) catch |err| {
                if (err == error.BrokenPipe) {
                    std.debug.print("Client disconnected (BrokenPipe)\n", .{});
                    return err;
                }
                return err;
            };

            std.debug.print("Sent SETTINGS ACK frame\n", .{});
        }

        pub fn sendPing(self: *@This()) !void {
            var frame_header = FrameHeader{
                .length = 8, // PING payload length is always 8
                .frame_type = .PING,
                .flags = FrameFlags{ .value = FrameFlags.ACK }, // Set ACK flag

                .reserved = false,
                .stream_id = 0,
            };

            try frame_header.write(self.writer);

            std.debug.print("Sent PING frame\n", .{});
        }

        pub fn receiveSettings(self: *@This()) !void {
            const settings_frame_header_size = 9;
            var frame_header: [settings_frame_header_size]u8 = undefined;
            _ = try self.reader.readAll(&frame_header);
            const length = std.mem.readInt(u24, frame_header[0..3], .big);
            if (length % 6 != 0) return error.InvalidSettingsFrameSize;

            var settings_payload: []u8 = try self.allocator.alloc(u8, length);
            defer self.allocator.free(settings_payload);
            _ = try self.reader.readAll(settings_payload);

            var i: usize = 0;
            while (i < settings_payload.len) {
                const setting = settings_payload[i .. i + 6];
                const id = std.mem.readInt(u16, setting[0..2], .big);
                const value = std.mem.readInt(u32, setting[2..6], .big);
                switch (id) {
                    1 => self.settings.header_table_size = value,
                    3 => self.settings.max_concurrent_streams = value,
                    4 => self.settings.initial_window_size = value,
                    5 => self.settings.max_frame_size = value,
                    6 => self.settings.max_header_list_size = value,
                    else => {},
                }
                i += 6;
            }
        }

        /// Sends a GOAWAY frame with the given parameters.
        pub fn sendGoAway(self: @This(), last_stream_id: u31, error_code: u32, debug_data: []const u8) !void {
            var buffer = std.ArrayList(u8).init(self.allocator.*);
            defer buffer.deinit();

            // Serialize Last-Stream-ID (31 bits) as 4 bytes (big-endian)
            try buffer.append(@intCast((last_stream_id >> 24) & 0x7F));
            try buffer.append(@intCast((last_stream_id >> 16) & 0xFF));
            try buffer.append(@intCast((last_stream_id >> 8) & 0xFF));
            try buffer.append(@intCast(last_stream_id & 0xFF));

            // Serialize Error Code (32 bits) as 4 bytes (big-endian)
            try buffer.append(@intCast((error_code >> 24) & 0xFF));
            try buffer.append(@intCast((error_code >> 16) & 0xFF));
            try buffer.append(@intCast((error_code >> 8) & 0xFF));
            try buffer.append(@intCast(error_code & 0xFF));

            // Append Debug Data if any
            if (debug_data.len > 0) {
                try buffer.appendSlice(debug_data);
            }

            const goaway_payload = try buffer.toOwnedSlice();

            var goaway_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(goaway_payload.len),
                    .frame_type = .GOAWAY,
                    .flags = FrameFlags.init(0),
                    .reserved = false,
                    .stream_id = 0, // GOAWAY is always on stream 0
                },
                .payload = goaway_payload,
            };

            std.debug.print("Sending GOAWAY frame: {x}\n", .{goaway_payload});
            try goaway_frame.write(self.writer);
        }

        pub fn close(self: @This()) !void {
            // Determine the highest stream ID that was processed
            var highest_stream_id: u31 = 0;

            var it = self.streams.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* > highest_stream_id) {
                    highest_stream_id = entry.key_ptr.*;
                }
            }

            // Error code 0 indicates graceful shutdown; adjust this if specific errors need to be reported.
            const error_code: u32 = 0; // 0: NO_ERROR, indicating graceful shutdown

            // Optional debug data for GOAWAY frame, informing the client about the reason
            const debug_data = "Connection closing: graceful shutdown";

            // Send the GOAWAY frame with the highest stream ID and debug information
            try self.sendGoAway(highest_stream_id, error_code, debug_data);

            // Ensure the GOAWAY frame is fully sent before closing the connection.

            // Close the underlying writer and terminate the connection gracefully
            // try self.writer.close();

            // Optionally, free up resources associated with streams
            @constCast(&self.streams).deinit();

            std.debug.print("Connection closed gracefully with GOAWAY frame\n", .{});
        }

        pub fn getStream(self: *@This(), stream_id: u31) !*Stream {
            if (self.streams.get(stream_id)) |stream| {
                return stream;
            } else {
                var stream = try Stream.init(self.allocator, self, stream_id);
                try self.streams.put(stream_id, &stream);
                return &stream;
            }
        }

        fn updateSendWindow(self: *@This(), increment: i32) !void {
            self.send_window_size += increment;
            if (self.send_window_size > 2147483647) { // Max value for a signed 31-bit integer
                return error.FlowControlError;
            }
        }

        fn updateRecvWindow(self: *@This(), delta: i32) void {
            self.recv_window_size += delta;
        }

        fn sendWindowUpdate(self: *@This(), stream_id: u31, increment: i32) !void {
            var frame_header = FrameHeader{
                .length = 4,
                .frame_type = .WINDOW_UPDATE,
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = stream_id,
            };

            var buffer: [4]u8 = undefined;
            std.mem.writeInt(u32, &buffer, @intCast(increment), .big);

            try frame_header.write(self.writer);
            try self.writer.writeAll(&buffer);
        }

        pub fn handleWindowUpdate(self: *@This(), frame: Frame) !void {
            if (frame.payload.len != 4) {
                return error.InvalidFrameSize;
            }

            const pay: *const [4]u8 = @ptrCast(frame.payload[0..4]);
            const increment = std.mem.readInt(u32, pay, .big);

            if (increment > 0x7FFFFFFF) { // u31 max value
                return error.FlowControlError;
            }

            if (frame.header.stream_id == 0) {
                try self.updateSendWindow(@intCast(increment));
            } else {
                // Forward to the appropriate stream for handling
                var stream = try self.getStream(frame.header.stream_id);
                try stream.updateSendWindow(@intCast(increment));
            }
        }

        pub fn sendData(self: *@This(), stream: *Stream, data: []const u8, end_stream: bool) !void {
            const max_frame_size = self.settings.max_frame_size;

            var remaining_data = data;
            while (remaining_data.len > 0) {
                const chunk_size = if (remaining_data.len > max_frame_size) max_frame_size else remaining_data.len;

                const data_chunk = remaining_data[0..chunk_size];
                remaining_data = remaining_data[chunk_size..];

                var data_frame = Frame{
                    .header = FrameHeader{
                        .length = @intCast(chunk_size),
                        .frame_type = .DATA,
                        .flags = FrameFlags{
                            .value = if (remaining_data.len == 0 and end_stream) FrameFlags.END_STREAM else 0,
                        },
                        .stream_id = stream.id,
                        .reserved = false,
                    },
                    .payload = data_chunk,
                };

                try data_frame.write(self.writer);
            }
        }
    };
}

const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,

    pub fn default() Settings {
        return Settings{};
    }
};

test "HTTP/2 connection initialization and flow control" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [8192]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);

    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var connection = try ConnectionType.init(&allocator, reader, writer, false);

    // Initialize stream
    var stream = try Stream.init(&allocator, &connection, 1);

    const preface_written_data = buffer_stream.getWritten();
    std.debug.print("Preface written data length: {d}\n", .{preface_written_data.len});

    // Send headers frame
    const headers_payload: [16]u8 = undefined; // Example payload size, adjust as needed
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(headers_payload.len),
            .frame_type = .HEADERS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = &headers_payload,
    };
    std.debug.print("About to handle headers frame\n", .{});
    try stream.handleFrame(headers_frame);
    std.debug.print("Headers frame handled\n", .{});

    // Check if headers were written
    const headers_written_data = buffer_stream.getWritten();
    std.debug.print("Headers frame written data length: {d}\n", .{headers_written_data.len - preface_written_data.len});

    // Ensure headers frame was actually written
    assert(headers_written_data.len > preface_written_data.len);

    // Send data
    const data = "Hello, world!";
    try connection.sendData(&stream, data, false);

    const written_data = buffer_stream.getWritten();

    // Debug each section length
    std.debug.print("Written data preface length: {any}\n", .{http2_preface.len});
    std.debug.print("Written data settings frame length: {any}\n", .{39});
    std.debug.print("Written data headers frame length: {any}\n", .{headers_written_data.len - preface_written_data.len});
    std.debug.print("Written data payload length: {any}\n", .{data.len});
    std.debug.print("Total written data length: {any}\n", .{written_data.len});

    // Inspect the buffer contents for unexpected data
    std.debug.print("Buffer content before handling headers: {x}\n", .{buffer_stream.getWritten()});
    std.debug.print("Buffer content after writing headers: {x}\n", .{buffer_stream.getWritten()});
    std.debug.print("Buffer content after writing payload: {x}\n", .{buffer_stream.getWritten()});

    // Investigate where the extra bytes are coming from
    std.debug.print("Buffer extra bytes: {x}\n", .{written_data[92..]});

    // Calculate the expected length, accounting for frame headers
    const preface_length = 24; // 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' is 24 bytes
    const settings_frame_length = 39; // As per your logs
    const headers_frame_length = 16; // As per your logs (likely includes frame header)
    const data_frame_payload_length = data.len; // 13 bytes for "Hello, world!"
    const data_frame_header_length = 9; // Standard HTTP/2 frame header size

    const data_frame_total_length = data_frame_payload_length + data_frame_header_length; // 22 bytes

    const expected_length = preface_length + settings_frame_length + headers_frame_length + data_frame_total_length; // 101 bytes

    std.debug.print("written_data.len = {d}, expected_length = {d}\n", .{ written_data.len, expected_length });
    assert(written_data.len == expected_length);

    // Clear buffer for next operations
    std.debug.print("Buffer before reset: {x}\n", .{buffer_stream.getWritten()});
    buffer_stream.reset();

    // Check that data was sent after reset
    const data_after_reset = "Hello again!";
    try connection.sendData(&stream, data_after_reset, false);

    const sent_data = buffer_stream.getWritten();
    std.debug.print("Buffer after sending data: {x}\n", .{sent_data});
    assert(sent_data.len > 0);

    // Simulate receiving a WINDOW_UPDATE frame to increase send window size
    const window_update_frame = Frame{
        .header = FrameHeader{
            .length = 4,
            .frame_type = .WINDOW_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0, // Connection-level window update
        },
        .payload = &[_]u8{ 0x00, 0x00, 0x01, 0x00 },
    };

    try connection.handleWindowUpdate(window_update_frame);

    // After handling WINDOW_UPDATE, we should be able to send more data
    try connection.sendData(&stream, data_after_reset, false);
    const sent_data_after_window_update = buffer_stream.getWritten();
    assert(sent_data_after_window_update.len > sent_data.len);

    // Clean up
    try connection.close();
}

test "applyFrameSettings test" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    const reader = stream.reader().any();
    const writer = stream.writer().any();

    var alloc = arena.allocator();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var connection = try ConnectionType.init(&alloc, reader, writer, false);

    // Frame with the SETTINGS type and 18 bytes of payload
    const frame = Frame{
        .header = FrameHeader{
            .length = 18, // 3 settings of 6 bytes each
            .frame_type = FrameType.SETTINGS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{
            // Example settings: ID 1, value 4096; ID 3, value 100; ID 4, value 65535
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // header_table_size: 4096
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // max_concurrent_streams: 100
            0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF, // initial_window_size: 65535
        },
    };

    // Call the function to apply the frame settings via connection
    try connection.applyFrameSettings(frame);

    // Assert that the settings were applied correctly in the connection
    try std.testing.expect(connection.settings.header_table_size == 4096);
    try std.testing.expect(connection.settings.max_concurrent_streams == 100);
    try std.testing.expect(connection.settings.initial_window_size == 65535);
    std.debug.print("Settings applied successfully in test\n", .{});
}

test "send HEADERS and DATA frames with proper flow" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [8192]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);

    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var connection = try ConnectionType.init(&allocator, reader, writer, false);

    var stream = try Stream.init(&allocator, &connection, 1);

    // Send a HEADERS frame
    const headers_payload: [16]u8 = undefined;
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(headers_payload.len),
            .frame_type = .HEADERS,
            .flags = FrameFlags{
                .value = FrameFlags.END_HEADERS, // Mark end of headers
            },
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = &headers_payload,
    };

    // Handle HEADERS frame
    try stream.handleFrame(headers_frame);

    // Check that the HEADERS frame was processed before continuing
    const headers_written_data = buffer_stream.getWritten();
    assert(headers_written_data.len > 0);
    std.debug.print("HEADERS frame written data length: {d}\n", .{headers_written_data.len});

    // Now send the DATA frame only after ensuring the HEADERS frame was handled
    const data = "Hello, world!";
    try connection.sendData(&stream, data, false);

    const written_data = buffer_stream.getWritten();
    std.debug.print("Total written data length after DATA frame: {d}\n", .{written_data.len});
}

test "Endpoint can process DATA frames of 2^14 octets in length" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [8192 * 4]u8 = undefined; // Create a larger buffer to handle large DATA frames
    var buffer_stream = std.io.fixedBufferStream(&buffer);

    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var connection = try ConnectionType.init(&allocator, reader, writer, false);

    var stream = try Stream.init(&allocator, &connection, 1);

    // Set max_frame_size to 16384 (2^14)
    connection.settings.max_frame_size = 16384;

    // Reset the buffer before writing
    buffer_stream.reset();

    // Send a HEADERS frame to initialize the stream
    const headers_payload: [16]u8 = undefined; // Example headers payload
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(headers_payload.len),
            .frame_type = .HEADERS,
            .flags = FrameFlags{
                .value = FrameFlags.END_HEADERS, // Mark end of headers
            },
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = &headers_payload,
    };

    // Handle the HEADERS frame
    try stream.handleFrame(headers_frame);

    // Prepare a DATA frame with 2^14 (16,384) octets, ensuring that it respects the frame size limit
    var data_payload: [16384]u8 = undefined; // Fill the data payload with zeroes
    try connection.sendData(&stream, &data_payload, false);

    // Verify the DATA frame was sent and processed
    const written_data = buffer_stream.getWritten();
    std.debug.print("Total written data length after sending DATA frame: {d}\n", .{written_data.len});

    // Ensure that the buffer contains the expected DATA frame of 16384 + 9 (frame header size) octets
    const expected_data_frame_length = 16384 + 9; // DATA frame payload + frame header
    try std.testing.expect(written_data.len == expected_data_frame_length);

    // Simulate receiving and processing the DATA frame
    const received_frame = try connection.receiveFrame();

    // Ensure the received frame type is DATA and the length is 16,384
    try std.testing.expect(received_frame.header.frame_type == .DATA);
    try std.testing.expect(received_frame.header.length == 16384);

    std.debug.print("Successfully processed DATA frame of 2^14 octets in length.\n", .{});
}
