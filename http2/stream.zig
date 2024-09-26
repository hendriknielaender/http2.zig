const std = @import("std");
const assert = std.debug.assert;
const Frame = @import("frame.zig").Frame;
const FrameHeader = @import("frame.zig").FrameHeader;
const FrameType = @import("frame.zig").FrameType;
const FrameFlags = @import("frame.zig").FrameFlags;
const Connection = @import("connection.zig").Connection;

pub const StreamState = enum {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
};

/// Represents an HTTP/2 Stream
pub const Stream = struct {
    id: u31,
    state: StreamState,
    conn: *Connection(std.io.AnyReader, std.io.AnyWriter),
    recv_window_size: i32,
    send_window_size: i32,
    recv_headers: std.ArrayList(u8),
    send_headers: std.ArrayList(u8),
    recv_data: std.ArrayList(u8),
    send_data: std.ArrayList(u8),

    pub fn init(allocator: *std.mem.Allocator, conn: *Connection(std.io.AnyReader, std.io.AnyWriter), id: u31) !Stream {
        return Stream{
            .id = id,
            .state = .Idle,
            .conn = conn,
            .recv_window_size = 65535, // Default initial window size
            .send_window_size = 65535, // Default initial window size
            .recv_headers = std.ArrayList(u8).init(allocator.*),
            .send_headers = std.ArrayList(u8).init(allocator.*),
            .recv_data = std.ArrayList(u8).init(allocator.*),
            .send_data = std.ArrayList(u8).init(allocator.*),
        };
    }

    pub fn deinit(self: *Stream, allocator: *std.mem.Allocator) void {
        self.recv_headers.deinit(allocator);
        self.send_headers.deinit(allocator);
        self.recv_data.deinit(allocator);
        self.send_data.deinit(allocator);
    }

    /// Handles incoming frames for the stream
    pub fn handleFrame(self: *Stream, frame: Frame) !void {
        std.debug.print("Handling frame type: {d}, stream ID: {d}\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id });

        switch (frame.header.frame_type) {
            FrameType.HEADERS => {
                std.debug.print("Handling HEADERS frame\n", .{});
                try self.handleHeaders(frame);

                // Ensure only actual data is written, not zeros
                try self.conn.writer.writeAll(frame.payload);
            },
            FrameType.DATA => {
                std.debug.print("Handling DATA frame\n", .{});
                try self.handleData(frame);
            },
            FrameType.WINDOW_UPDATE => try self.handleWindowUpdate(frame),
            FrameType.RST_STREAM => try self.handleRstStream(),
            else => {},
        }

        std.debug.print("Frame handling completed for stream ID: {d}\n", .{frame.header.stream_id});
    }

    fn handleHeaders(self: *Stream, frame: Frame) !void {
        std.debug.print("Appending headers data of length: {d}\n", .{frame.payload.len});

        if (self.state == .Idle or self.state == .HalfClosedRemote) {
            self.state = .Open;
        }

        try self.recv_headers.appendSlice(frame.payload);

        std.debug.print("Total received headers data length: {d}\n", .{self.recv_headers.items.len});

        if (frame.header.flags.isEndStream()) {
            self.state = .HalfClosedRemote;
        }
    }

    fn handleData(self: *Stream, frame: Frame) !void {
        if (self.state != .Open and self.state != .HalfClosedRemote) {
            return error.InvalidStreamState;
        }
        try self.recv_data.appendSlice(frame.payload);
        self.recv_window_size -= @intCast(frame.header.length);
        if (self.recv_window_size < 0) {
            return error.FlowControlError;
        }
        if (frame.header.flags.isEndStream()) {
            self.state = .HalfClosedRemote;
        }
    }

    fn handleWindowUpdate(self: *Stream, frame: Frame) !void {
        // Ensure the payload is at least 4 bytes long
        if (frame.payload.len < 4) {
            return error.InvalidFrameSize;
        }

        // Read the first 4 bytes as a u32, assuming the data is in big-endian order
        const pay: *const [4]u8 = @ptrCast(frame.payload[0..4]);
        const increment = std.mem.readInt(u32, pay, .big);

        // Ensure the increment does not exceed the u31 limit
        if (increment > 0x7FFFFFFF) {
            return error.FlowControlError;
        }

        self.send_window_size += @intCast(increment);
        if (self.send_window_size > 2147483647) { // u31 maximum value
            return error.FlowControlError;
        }
    }

    fn handleRstStream(self: *Stream) !void {
        self.state = .Closed;
    }

    /// Updates the send window size for the stream
    pub fn updateSendWindow(self: *Stream, increment: i32) !void {
        self.send_window_size += increment;
        if (self.send_window_size > 2147483647) { // u31 maximum value
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
                .frame_type = .DATA,
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
                .frame_type = .RST_STREAM,
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
            .length = 16,
            .frame_type = .HEADERS,
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
