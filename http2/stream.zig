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

    /// Handles incoming frames for the stream
    pub fn handleFrame(self: *Stream, frame: Frame) !void {
        switch (frame.header.frame_type) {
            FrameType.HEADERS => try self.handleHeaders(frame),
            FrameType.DATA => try self.handleData(frame),
            FrameType.WINDOW_UPDATE => try self.handleWindowUpdate(frame),
            FrameType.RST_STREAM => try self.handleRstStream(frame),
            else => {},
        }
    }

    fn handleHeaders(self: *Stream, frame: Frame) !void {
        if (self.state == .Idle or self.state == .HalfClosedRemote) {
            self.state = .Open;
        }
        try self.recv_headers.appendSlice(frame.payload);
        if (frame.header.flags.end_stream) {
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
        if (frame.header.flags.end_stream) {
            self.state = .HalfClosedRemote;
        }
    }

    fn handleWindowUpdate(self: *Stream, frame: Frame) !void {
        const increment = std.mem.readInt(u31, frame.payload, .big);
        self.send_window_size += @intCast(increment);
        if (self.send_window_size > 2147483647) {
            return error.FlowControlError;
        }
    }

    fn handleRstStream(self: *Stream) !void {
        self.state = .Closed;
    }

    /// Sends data over the stream
    pub fn sendData(self: *Stream, data: []const u8) !void {
        if (self.state != .Open and self.state != .HalfClosedLocal) {
            return error.InvalidStreamState;
        }
        if (data.len > self.send_window_size) {
            return error.FlowControlError;
        }
        try self.send_data.appendSlice(data);
        self.send_window_size -= @intCast(data.len);
        const frame = Frame{
            .header = FrameHeader{
                .length = @intCast(data.len),
                .frame_type = .DATA,
                .flags = .{ .end_stream = false }, // Set appropriately
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
    try stream.sendData(data);

    const writtenData = buffer_stream.getWritten();
    try std.testing.expect(writtenData.len > 0);
}
