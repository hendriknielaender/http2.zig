const std = @import("std");
pub const Stream = @import("stream.zig").Stream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const FrameType = @import("frame.zig").FrameType;
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
                // Check for the correct HTTP/2 preface
                var preface_buf: [24]u8 = undefined;
                _ = try self.reader.readAll(&preface_buf);
                if (!std.mem.eql(u8, &preface_buf, http2_preface)) {
                    return error.InvalidPreface;
                }
                std.debug.print("Valid HTTP/2 preface received\n", .{});
            } else {
                try self.sendPreface();
            }

            try self.sendSettings();
            return self;
        }

        fn sendPreface(self: @This()) !void {
            try self.writer.writeAll(http2_preface);
        }

        pub fn sendSettings(self: @This()) !void {
            const settings = [_][2]u32{
                .{ 1, self.settings.header_table_size },
                .{ 3, self.settings.max_concurrent_streams },
                .{ 4, self.settings.initial_window_size },
                .{ 5, self.settings.max_frame_size },
                .{ 6, self.settings.max_header_list_size },
            };

            // Define the settings frame header
            var frame_header = FrameHeader{
                .length = @intCast(6 * settings.len),
                .frame_type = .SETTINGS,
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = 0, // 0 indicates a connection-level frame
            };

            // Write the frame header first
            try frame_header.write(self.writer);

            var buffer: [6]u8 = undefined;
            for (settings) |setting| {
                std.mem.writeInt(u16, buffer[0..2], @intCast(setting[0]), .big);
                std.mem.writeInt(u32, buffer[2..6], setting[1], .big);

                std.debug.print("Writing setting: ", .{});
                for (buffer) |byte| {
                    std.debug.print("{x} ", .{byte});
                }
                std.debug.print("\n", .{});

                try self.writer.writeAll(buffer[0..6]);
            }
        }

        fn from_int(val: u8) FrameType {
            return std.meta.intToEnum(FrameType, val) catch undefined;
        }

        pub fn receiveFrame(self: *@This()) !Frame {
            var header_buf: [9]u8 = undefined; // Frame header size is 9 bytes
            _ = try self.reader.readAll(&header_buf);

            std.debug.print("Raw header bytes: {x}\n", .{header_buf});

            // Read frame type from the header buffer
            const frame_type_u8: u8 = @intCast(header_buf[3]);
            std.debug.print("Read frame_type_u8: {any} (dec: {d})\n", .{ frame_type_u8, frame_type_u8 });

            const frame_type = from_int(frame_type_u8);

            if (frame_type == undefined) {
                std.debug.print("Invalid frame type received: {d} (hex: {any})\n", .{ frame_type_u8, frame_type_u8 });
                std.debug.print("Full header buffer for context: {any}\n", .{header_buf});
                return error.InvalidFrameType;
            }

            if (frame_type == .SETTINGS) {
                std.debug.print("Valid SETTINGS frame received.\n", .{});
            }

            const stream_id_u32: u32 = std.mem.readInt(u32, header_buf[5..9], .big) & 0x7FFFFFFF;
            const stream_id: u31 = @intCast(stream_id_u32);

            const frame_header = FrameHeader{
                .length = std.mem.readInt(u24, header_buf[0..3], .big),
                .frame_type = frame_type,
                .flags = FrameFlags.init(header_buf[4]),
                .reserved = (header_buf[5] & 0x80) != 0,
                .stream_id = stream_id,
            };

            std.debug.print("Received frame header: {any}\n", .{frame_header});

            const payload: []u8 = try self.allocator.alloc(u8, frame_header.length);
            defer self.allocator.free(payload);

            _ = try self.reader.readAll(payload);

            std.debug.print("Frame payload length: {d}\n", .{frame_header.length});

            // Return valid frame
            return Frame{
                .header = frame_header,
                .payload = payload,
            };
        }

        pub fn applyFrameSettings(self: *@This(), frame: Frame) !void {
            std.debug.print("Applying settings from frame...\n", .{});

            // Ensure the frame type is SETTINGS
            if (frame.header.frame_type != .SETTINGS) {
                return error.InvalidFrameType;
            }

            // The payload of the SETTINGS frame is already read into `frame.payload`
            if (frame.payload.len % 6 != 0) {
                return error.InvalidSettingsFrameSize;
            }

            var i: usize = 0;
            while (i + 6 <= frame.payload.len) {
                const setting = frame.payload[i .. i + 6];

                // Decode setting ID and value
                const id = std.mem.readInt(u16, setting[0..2], .big);
                const value = std.mem.readInt(u32, setting[2..6], .big);

                std.debug.print("Setting ID: {d}, Value: {d}\n", .{ id, value });

                // Apply the settings based on ID
                switch (id) {
                    1 => self.settings.header_table_size = value,
                    2 => {
                        if (value > 1) return error.InvalidSettingsValue;
                        self.settings.enable_push = (value == 1);
                    },
                    3 => self.settings.max_concurrent_streams = value,
                    4 => self.settings.initial_window_size = value,
                    5 => self.settings.max_frame_size = value,
                    6 => self.settings.max_header_list_size = value,
                    else => std.debug.print("Unknown setting ID: {}\n", .{id}),
                }

                i += 6;
            }

            std.debug.print("Settings applied successfully.\n", .{});
        }

        pub fn sendSettingsAck(self: @This()) !void {
            var frame_header = FrameHeader{
                .length = 0,
                .frame_type = .SETTINGS,
                .flags = FrameFlags{ .value = 1 }, // Set ACK flag
                .reserved = false,
                .stream_id = 0,
            };

            try frame_header.write(self.writer);
            std.debug.print("Sent SETTINGS ACK frame\n", .{});
        }

        pub fn sendPong(self: *@This(), payload: []const u8) !void {
            // Ensure the payload length is exactly 8 bytes as per the HTTP/2 specification for PING frames.
            if (payload.len != 8) {
                return error.InvalidPingPayload;
            }

            var frame_header = FrameHeader{
                .length = 8, // PING payload length is always 8
                .frame_type = .PING,
                .flags = FrameFlags.init(FrameFlags.ACK),
                .reserved = false,
                .stream_id = 0,
            };

            try frame_header.write(self.writer);
            try self.writer.writeAll(payload);
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

        pub fn close(self: @This()) !void {
            var goaway_frame: [17]u8 = undefined;
            std.mem.writeInt(u24, goaway_frame[0..3], 8, .big);
            goaway_frame[3] = 0x7; // type (GOAWAY)
            goaway_frame[4] = 0; // flags
            std.mem.writeInt(u32, goaway_frame[5..9], 0, .big); // last stream ID
            std.mem.writeInt(u32, goaway_frame[9..13], 0, .big); // error code
            try self.writer.writeAll(&goaway_frame);
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
            std.debug.print("sendData called with data length: {d}\n", .{data.len});

            if (data.len > self.send_window_size) {
                return error.FlowControlError;
            }

            try stream.sendData(data, end_stream);

            self.send_window_size -= @intCast(data.len);

            if (self.send_window_size < 0) {
                // Send a WINDOW_UPDATE frame to increase the window size
                try self.sendWindowUpdate(0, 65535); // Increase by a default value, adjust as necessary
            }

            std.debug.print("sendData completed with send_window_size: {d}\n", .{self.send_window_size});
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
    try connection.sendData(&stream, data);

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
    try connection.sendData(&stream, data_after_reset);

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
    try connection.sendData(&stream, data_after_reset);
    const sent_data_after_window_update = buffer_stream.getWritten();
    assert(sent_data_after_window_update.len > sent_data.len);

    // Clean up
    try connection.close();
}
