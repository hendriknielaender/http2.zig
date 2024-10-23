const std = @import("std");
const assert = std.debug.assert;
const Frame = @import("frame.zig").Frame;
const FrameHeader = @import("frame.zig").FrameHeader;
const FrameType = @import("frame.zig").FrameType;
const FrameTypes = @import("frame.zig");
const FrameFlags = @import("frame.zig").FrameFlags;
const Connection = @import("connection.zig").Connection;
const Hpack = @import("hpack.zig").Hpack;

const log = std.log.scoped(.stream);

pub const StreamState = enum {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
};

/// Represents an HTTP/2 Stream
pub const Stream = struct {
    id: u32,
    state: StreamState,
    conn: *Connection(std.io.AnyReader, std.io.AnyWriter),
    recv_window_size: i32,
    send_window_size: i32,
    recv_headers: std.ArrayList(u8),
    send_headers: std.ArrayList(u8),
    recv_data: std.ArrayList(u8),
    send_data: std.ArrayList(u8),
    header_block_fragments: std.ArrayList(u8),
    expecting_continuation: bool,
    request_complete: bool = false,

    pub fn init(allocator: *std.mem.Allocator, conn: *Connection(std.io.AnyReader, std.io.AnyWriter), id: u32) !*Stream {
        const self = try allocator.create(Stream);
        self.* = Stream{
            .id = id,
            .state = .Idle,
            .conn = conn,
            .recv_window_size = 65535, // Default initial window size
            .send_window_size = 65535, // Default initial window size
            .recv_headers = std.ArrayList(u8).init(allocator.*),
            .send_headers = std.ArrayList(u8).init(allocator.*),
            .recv_data = std.ArrayList(u8).init(allocator.*),
            .send_data = std.ArrayList(u8).init(allocator.*),
            .header_block_fragments = std.ArrayList(u8).init(allocator.*),
            .expecting_continuation = false,
        };
        return self;
    }

    pub fn deinit(self: *Stream) void {
        if (self.expecting_continuation) {
            self.conn.expecting_continuation_stream_id = null;
        }
        self.recv_headers.deinit();
        self.send_headers.deinit();
        self.recv_data.deinit();
        self.send_data.deinit();
        self.header_block_fragments.deinit();
        self.conn.allocator.destroy(self);
    }

    /// Handles incoming frames for the stream
    pub fn handleFrame(self: *Stream, frame: Frame) !void {
        log.debug("Handling frame type: {d}, stream ID: {d}\n", .{ frame.header.frame_type, frame.header.stream_id });

        // Check if the stream is closed
        if (self.state == .Closed) {
            // Only PRIORITY frames are allowed on closed streams
            if (frame.header.frame_type != FrameTypes.FRAME_TYPE_PRIORITY) {
                log.err("Received frame type {d} on closed stream {d}: STREAM_CLOSED\n", .{ frame.header.frame_type, self.id });

                // Send GOAWAY with STREAM_CLOSED error code
                try self.conn.send_goaway(self.conn.highest_stream_id(), 0x5, "Frame received on closed stream: STREAM_CLOSED");
                self.conn.goaway_sent = true;
                return error.StreamClosed;
            }
        }

        if (self.state == .HalfClosedRemote) {
            if (frame.header.frame_type != FrameTypes.FRAME_TYPE_WINDOW_UPDATE and
                frame.header.frame_type != FrameTypes.FRAME_TYPE_PRIORITY and
                frame.header.frame_type != FrameTypes.FRAME_TYPE_RST_STREAM)
            {
                log.err("Received frame type {d} on half-closed (remote) stream {d}: STREAM_CLOSED\n", .{ frame.header.frame_type, self.id });
                try self.sendRstStream(0x5); // STREAM_CLOSED
                return error.StreamClosed;
            }
        }

        // Check if we're expecting a CONTINUATION frame
        if (self.expecting_continuation and frame.header.frame_type != FrameTypes.FRAME_TYPE_CONTINUATION) {
            // Protocol error: received a frame other than CONTINUATION while expecting CONTINUATION
            log.err("Received frame type {d} while expecting CONTINUATION frame: PROTOCOL_ERROR\n", .{frame.header.frame_type});
            try self.conn.send_goaway(0, 0x01, "Expected CONTINUATION frame: PROTOCOL_ERROR");
            return error.ProtocolError;
        }

        switch (frame.header.frame_type) {
            FrameTypes.FRAME_TYPE_HEADERS => {
                log.debug("Handling HEADERS frame\n", .{});
                if (frame.header.flags.value & FrameFlags.END_STREAM != 0) {
                    self.state = StreamState.HalfClosedRemote;
                    log.debug("Stream {d}: Transitioned to HalfClosedRemote\n", .{self.id});
                }
                try self.handleHeadersFrame(frame);
            },
            FrameTypes.FRAME_TYPE_CONTINUATION => {
                log.debug("Handling CONTINUATION frame\n", .{});
                try self.handleContinuationFrame(frame);
            },
            FrameTypes.FRAME_TYPE_DATA => {
                log.debug("Handling DATA frame\n", .{});
                try self.handleData(frame);
            },
            FrameTypes.FRAME_TYPE_WINDOW_UPDATE => try self.handleWindowUpdate(frame),
            FrameTypes.FRAME_TYPE_RST_STREAM => try self.handleRstStream(),
            FrameTypes.FRAME_TYPE_PRIORITY => {
                log.debug("Handling PRIORITY frame\n", .{});
                try self.handlePriorityFrame(frame);
            },
            else => {
                // Handle other frame types or ignore them as appropriate
                log.debug("Received frame type {d} which is not handled in current state\n", .{frame.header.frame_type});
            },
        }

        // After handling the frame, check if the request is complete
        if (self.request_complete) {
            // Process the request
            try self.conn.process_request(self);
        }

        log.debug("Frame handling completed for stream ID: {d}\n", .{frame.header.stream_id});
    }

    fn handlePriorityFrame(self: *Stream, frame: Frame) !void {
        if (frame.payload.len != 5) {
            return error.FrameSizeError;
        }

        const payload = frame.payload;

        // Read the 4-byte Stream Dependency field
        const stream_dependency = (@as(u32, payload[0]) << 24) |
            (@as(u32, payload[1]) << 16) |
            (@as(u32, payload[2]) << 8) |
            (@as(u32, payload[3]));

        // The most significant bit is the 'E' bit (Exclusive flag)
        const exclusive = (stream_dependency & 0x80000000) != 0;
        const dependency_stream_id = stream_dependency & 0x7FFFFFFF; // Clear the 'E' bit

        // Read the 1-byte Weight field
        const weight = payload[4]; // Weight is between 1 and 256

        // Check for self-dependency
        if (dependency_stream_id == self.id) {
            log.err("Stream {d} has a dependency on itself: PROTOCOL_ERROR\n", .{self.id});
            try self.sendRstStream(0x1); // PROTOCOL_ERROR
            self.state = .Closed;
            return error.ProtocolError;
        }

        // For now, we just log the priority information
        log.debug(
            "Stream {d} depends on stream {d} (exclusive: {any}), weight: {d}\n",
            .{ self.id, dependency_stream_id, exclusive, weight },
        );
    }

    pub fn sendRstStream(self: *@This(), error_code: u32) !void {
        var frame_header = FrameHeader{
            .length = 4,
            .frame_type = FrameTypes.FRAME_TYPE_RST_STREAM, // 3 for RST_STREAM
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = self.id, // Ensure correct stream ID
        };

        // Write the frame header
        try frame_header.write(self.conn.writer);

        // Write the error code as a 4-byte big-endian integer
        var error_code_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, error_code_bytes[0..4], error_code, .big);
        try self.conn.writer.writeAll(&error_code_bytes);

        log.debug("Sent RST_STREAM frame with error code {d} for stream ID {d}\n", .{ error_code, self.id });
    }

    fn handleHeadersFrame(self: *Stream, frame: Frame) !void {
        if (self.expecting_continuation) {
            // Protocol error: already expecting continuation on this stream
            log.err("Received HEADERS frame while expecting CONTINUATION on stream {d}: PROTOCOL_ERROR\n", .{self.id});
            try self.conn.send_goaway(0, 0x1, "Unexpected HEADERS frame while expecting CONTINUATION: PROTOCOL_ERROR");
            return error.ProtocolError;
        }

        // Update stream state based on current state and the frame received
        switch (self.state) {
            .Idle => {
                // Receiving a HEADERS frame in idle state is valid; transition to Open
                self.state = .Open;
            },
            .ReservedLocal, .ReservedRemote => {
                // Receiving a HEADERS frame in Reserved state is a protocol error
                log.err("HEADERS frame received in reserved state on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                try self.conn.send_goaway(0, 0x1, "HEADERS frame received in reserved state: PROTOCOL_ERROR");
                return error.ProtocolError;
            },
            .Open, .HalfClosedRemote => {
                // Valid to receive HEADERS frame; proceed without state change
            },
            .HalfClosedLocal, .Closed => {
                // Invalid to receive HEADERS frame; send GOAWAY with PROTOCOL_ERROR
                log.err("HEADERS frame received in invalid state on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                try self.conn.send_goaway(0, 0x1, "HEADERS frame received in invalid state: PROTOCOL_ERROR");
                return error.ProtocolError;
            },
        }

        // Append the header block fragment
        try self.header_block_fragments.appendSlice(frame.payload);

        if (frame.header.flags.isEndHeaders()) {
            // Attempt to decode the header block
            try self.decodeHeaderBlock();
            self.header_block_fragments.clearAndFree();
        } else {
            // Set expectation for CONTINUATION frames
            self.expecting_continuation = true;
            self.conn.expecting_continuation_stream_id = self.id;
        }

        if (frame.header.flags.isEndStream()) {
            if (self.state == .Open) {
                self.state = .HalfClosedRemote;
            } else if (self.state == .HalfClosedLocal) {
                self.state = .Closed;
            }
            self.request_complete = true; // Set the flag
        }

        log.debug("Frame handling completed for stream ID: {d}\n", .{frame.header.stream_id});
    }

    fn handleContinuationFrame(self: *Stream, frame: Frame) !void {
        if (!self.expecting_continuation) {
            // Protocol error: not expecting continuation on this stream
            log.err("Received unexpected CONTINUATION frame on stream {d}: PROTOCOL_ERROR\n", .{self.id});
            try self.conn.send_goaway(0, 0x1, "Unexpected CONTINUATION frame: PROTOCOL_ERROR");
            return error.ProtocolError;
        }

        // Append the continuation fragment
        try self.header_block_fragments.appendSlice(frame.payload);

        if (frame.header.flags.isEndHeaders()) {
            // Attempt to decode the complete header block
            try self.decodeHeaderBlock();
            self.header_block_fragments.clearAndFree();

            // Clear the continuation expectation
            self.expecting_continuation = false;
            self.conn.expecting_continuation_stream_id = null;
        }

        log.debug("Frame handling completed for stream ID: {d}\n", .{frame.header.stream_id});
    }

    fn decodeHeaderBlock(self: *Stream) !void {
        const header_block = self.header_block_fragments.items;

        var headers = std.ArrayList(Hpack.HeaderField).init(self.conn.allocator.*);
        defer {
            // Deinitialize headers and free allocated strings
            for (headers.items) |header| {
                self.conn.allocator.free(header.name);
                self.conn.allocator.free(header.value);
            }
            headers.deinit();
        }

        var cursor: usize = 0;
        while (cursor < header_block.len) {
            const remaining_data = header_block[cursor..];

            var decoded_header = Hpack.decodeHeaderField(remaining_data, &self.conn.hpack_dynamic_table, self.conn.allocator) catch |err| {
                // Decompression failed
                log.err("Header decompression failed: {}\n", .{err});
                try self.conn.send_goaway(0, 0x09, "Compression Error: COMPRESSION_ERROR");
                return error.CompressionError;
            };

            // Copy the header name and value to new allocations
            const header_copy = Hpack.HeaderField{
                .name = try self.conn.allocator.dupe(u8, decoded_header.header.name),
                .value = try self.conn.allocator.dupe(u8, decoded_header.header.value),
            };
            try headers.append(header_copy);

            // Now it's safe to deinitialize the decoded_header
            decoded_header.deinit();

            cursor += decoded_header.bytes_consumed;
        }

        // Successfully decoded headers
        log.debug("Successfully decoded headers:\n", .{});
        for (headers.items) |header| {
            log.debug("{s}: {s}\n", .{ header.name, header.value });
        }

        // You can now process the headers as needed...
        // For example, store them in the stream's recv_headers list
    }

    fn handleData(self: *Stream, frame: Frame) !void {
        if (self.state != .Open and self.state != .HalfClosedLocal) {
            return error.InvalidStreamState;
        }

        // Handle the PADDED flag
        var payload = frame.payload;
        var pad_length: u8 = 0;
        if ((frame.header.flags.value & FrameFlags.PADDED) != 0) {
            if (payload.len < 1) {
                // Payload is too short to contain Pad Length field
                return error.ProtocolError;
            }
            pad_length = payload[0];
            payload = payload[1..];

            if (@as(u32, pad_length) > payload.len) {
                // Pad length exceeds remaining payload length
                return error.ProtocolError;
            }

            // Remove padding from payload
            payload = payload[0 .. payload.len - @as(u32, pad_length)];
        }

        // Now 'payload' contains the actual data without padding
        try self.recv_data.appendSlice(payload);
        self.recv_window_size -= @intCast(frame.header.length);
        if (self.recv_window_size < 0) {
            return error.FlowControlError;
        }

        if (frame.header.flags.isEndStream()) {
            if (self.state == .Open) {
                self.state = .HalfClosedRemote;
            } else if (self.state == .HalfClosedLocal) {
                self.state = .Closed;
            }
            self.request_complete = true;
        }
    }

    fn handleWindowUpdate(self: *Stream, frame: Frame) !void {
        if (self.state == .Idle) {
            log.err("WINDOW_UPDATE received on idle stream {d}\n", .{self.id});
            return error.InvalidStreamState;
        }

        // Existing code to handle WINDOW_UPDATE frame
        // Ensure the payload is at least 4 bytes long
        if (frame.payload.len != 4) {
            return error.InvalidFrameSize;
        }

        // Read the first 4 bytes as a u32, assuming the data is in big-endian order
        const pay: *const [4]u8 = @ptrCast(frame.payload[0..4]);
        const increment = std.mem.readInt(u32, pay, .big);

        // Ensure the increment does not exceed the u32 limit
        if (increment > 0x7FFFFFFF) {
            return error.FlowControlError;
        }

        self.send_window_size += @intCast(increment);
        if (self.send_window_size > 2147483647) { // u32 maximum value
            return error.FlowControlError;
        }
    }

    fn handleRstStream(self: *Stream) !void {
        log.debug("Received RST_STREAM frame\n", .{});

        if (self.state == .Idle) {
            log.err("RST_STREAM received on idle stream {d}\n", .{self.id});
            return error.IdleStreamError;
        }

        // Handle RST_STREAM frame
        self.state = .Closed;
    }

    /// Updates the send window size for the stream
    pub fn updateSendWindow(self: *Stream, increment: i32) !void {
        self.send_window_size += increment;
        if (self.send_window_size > 2147483647) { // u32 maximum value
            return error.FlowControlError;
        }
    }

    /// Sends data over the stream
    pub fn sendData(self: *Stream, data: []const u8, end_stream: bool) !void {
        if (self.state != .Open and self.state != .HalfClosedLocal) {
            return error.InvalidStreamState;
        }
        if (data.len > self.send_window_size) {
            return error.FlowControlError;
        }
        try self.send_data.appendSlice(data);
        self.send_window_size -= @intCast(data.len);

        const frame_flags = if (end_stream) FrameFlags.init(FrameFlags.END_STREAM) else FrameFlags.init(0);

        var frame = Frame{
            .header = FrameHeader{
                .length = @intCast(data.len),
                .frame_type = FrameTypes.FRAME_TYPE_DATA,
                .flags = frame_flags,
                .reserved = false,
                .stream_id = self.id,
            },
            .payload = data,
        };

        try frame.write(self.conn.writer);
    }

    /// Closes the stream gracefully
    pub fn close(self: *Stream) !void {
        self.state = .Closed;
        const frame = Frame{
            .header = FrameHeader{
                .length = 0,
                .frame_type = FrameTypes.FRAME_TYPE_RST_STREAM,
                .flags = .{},
                .stream_id = self.id,
            },
            .payload = &[_]u8{},
        };
        try frame.write(self.conn.writer);
    }
};

test "create and handle stream" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);

    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var conn = try ConnectionType.init(&allocator, reader, writer, false);

    var stream = try Stream.init(&allocator, &conn, 1);

    // Manually set the flags value for the end_headers flag
    const end_headers_flag: u8 = 0x4; // Assuming 0x4 represents END_HEADERS
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = @intCast(4),
            .frame_type = FrameTypes.FRAME_TYPE_HEADERS,
            .flags = FrameFlags.init(end_headers_flag),
            .reserved = false,
            .stream_id = 1,
        },
        .payload = &[_]u8{ 0x82, 0x86, 0x44, 0x89 }, // Example header block
    };
    try stream.handleFrame(headers_frame);
    try std.testing.expectEqual(@as(usize, 4), stream.recv_headers.items.len);

    const data = "Hello, world!";
    try stream.sendData(data, false);

    const writtenData = buffer_stream.getWritten();
    try std.testing.expect(writtenData.len > 0);
}
