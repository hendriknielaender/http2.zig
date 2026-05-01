const std = @import("std");
const assert = std.debug.assert;
const http2 = @import("http2.zig");
const max_frame_size_default = http2.max_frame_size_default;
threadlocal var frame_scratch: [max_frame_size_default]u8 = undefined;
pub const FrameType = enum(u8) {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9,
    PRIORITY_UPDATE = 0x10,
    pub fn isValid(self: FrameType) bool {
        return switch (self) {
            .DATA,
            .HEADERS,
            .PRIORITY,
            .RST_STREAM,
            .SETTINGS,
            .PUSH_PROMISE,
            .PING,
            .GOAWAY,
            .WINDOW_UPDATE,
            .CONTINUATION,
            .PRIORITY_UPDATE,
            => true,
        };
    }
    pub fn fromU8(value: u8) ?FrameType {
        return switch (value) {
            0x0 => .DATA,
            0x1 => .HEADERS,
            0x2 => .PRIORITY,
            0x3 => .RST_STREAM,
            0x4 => .SETTINGS,
            0x5 => .PUSH_PROMISE,
            0x6 => .PING,
            0x7 => .GOAWAY,
            0x8 => .WINDOW_UPDATE,
            0x9 => .CONTINUATION,
            0x10 => .PRIORITY_UPDATE,
            else => null,
        };
    }
};
pub const FRAME_TYPE_DATA = @intFromEnum(FrameType.DATA);
pub const FRAME_TYPE_HEADERS = @intFromEnum(FrameType.HEADERS);
pub const FRAME_TYPE_PRIORITY = @intFromEnum(FrameType.PRIORITY);
pub const FRAME_TYPE_RST_STREAM = @intFromEnum(FrameType.RST_STREAM);
pub const FRAME_TYPE_SETTINGS = @intFromEnum(FrameType.SETTINGS);
pub const FRAME_TYPE_PUSH_PROMISE = @intFromEnum(FrameType.PUSH_PROMISE);
pub const FRAME_TYPE_PING = @intFromEnum(FrameType.PING);
pub const FRAME_TYPE_GOAWAY = @intFromEnum(FrameType.GOAWAY);
pub const FRAME_TYPE_WINDOW_UPDATE = @intFromEnum(FrameType.WINDOW_UPDATE);
pub const FRAME_TYPE_CONTINUATION = @intFromEnum(FrameType.CONTINUATION);
pub const FRAME_TYPE_PRIORITY_UPDATE = @intFromEnum(FrameType.PRIORITY_UPDATE);
/// Represents the flags of an HTTP/2 frame
pub const FrameFlags = struct {
    value: u8,
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
    pub const ACK: u8 = 0x1;
    pub fn init(value: u8) FrameFlags {
        return FrameFlags{ .value = value };
    }
    pub fn has(self: FrameFlags, flag: u8) bool {
        return (self.value & flag) != 0;
    }
    pub fn setEndStream(self: *FrameFlags) void {
        self.value |= FrameFlags.END_STREAM;
    }
    pub fn isEndStream(self: FrameFlags) bool {
        return self.has(FrameFlags.END_STREAM);
    }
    pub fn setEndHeaders(self: *FrameFlags) void {
        self.value |= FrameFlags.END_HEADERS;
    }
    pub fn isEndHeaders(self: FrameFlags) bool {
        return self.has(FrameFlags.END_HEADERS);
    }
    pub fn setPadded(self: *FrameFlags) void {
        self.value |= FrameFlags.PADDED;
    }
    pub fn isPadded(self: FrameFlags) bool {
        return self.has(FrameFlags.PADDED);
    }
    pub fn setPriority(self: *FrameFlags) void {
        self.value |= FrameFlags.PRIORITY;
    }
    pub fn isPriority(self: FrameFlags) bool {
        return self.has(FrameFlags.PRIORITY);
    }
    pub fn setAck(self: *FrameFlags) void {
        self.value |= FrameFlags.ACK;
    }
    pub fn isAck(self: FrameFlags) bool {
        return self.has(FrameFlags.ACK);
    }
};
/// Represents an HTTP/2 frame header
pub const FrameHeader = struct {
    length: u32,
    frame_type: FrameType,
    flags: FrameFlags,
    reserved: bool,
    stream_id: u32,
    pub fn read(reader: *std.Io.Reader) !FrameHeader {
        var buffer: [9]u8 = undefined;
        try reader.readSliceAll(&buffer);
        // Parse the 24-bit length from the first three bytes
        const length: u32 = (@as(u32, buffer[0]) << 16) | (@as(u32, buffer[1]) << 8) | @as(u32, buffer[2]);
        // Ensure the length is within 24 bits
        if (length > 0xFFFFFF) {
            return error.InvalidFrameLength;
        }
        const frame_type_u8: u8 = buffer[3];
        const frame_type = FrameType.fromU8(frame_type_u8) orelse return error.InvalidFrameType;
        const flags = FrameFlags.init(buffer[4]);
        // Parse the 31-bit stream ID from the last four bytes
        const stream_id_raw = std.mem.readInt(u32, buffer[5..9], .big);
        const reserved: bool = (stream_id_raw & 0x80000000) != 0;
        const stream_id: u32 = stream_id_raw & 0x7FFFFFFF;
        return FrameHeader{
            .length = length,
            .frame_type = frame_type,
            .flags = flags,
            .reserved = reserved,
            .stream_id = stream_id,
        };
    }
    pub fn write(self: *FrameHeader, writer: *std.Io.Writer) !void {
        var buffer: [9]u8 = undefined;
        // Ensure the length fits into 24 bits
        if (self.length > 0xFFFFFF) {
            return error.InvalidFrameLength;
        }
        // Write the 24-bit length into the first three bytes
        buffer[0] = @intCast((self.length >> 16) & 0xFF);
        buffer[1] = @intCast((self.length >> 8) & 0xFF);
        buffer[2] = @intCast(self.length & 0xFF);
        buffer[3] = @intFromEnum(self.frame_type);
        buffer[4] = self.flags.value;
        // Combine the reserved bit and stream ID
        var stream_id_raw: u32 = self.stream_id & 0x7FFFFFFF;
        if (self.reserved) {
            stream_id_raw |= 0x80000000;
        }
        std.mem.writeInt(u32, buffer[5..9], stream_id_raw, .big);
        try writer.writeAll(&buffer);
    }
};
/// Represents an HTTP/2 frame
pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
    padding_length: ?u8 = null,
    pub fn init(header: FrameHeader, payload: []const u8) Frame {
        return Frame{ .header = header, .payload = payload };
    }
    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.payload = &[_]u8{};
    }
    pub fn read(reader: *std.Io.Reader, allocator: std.mem.Allocator) !Frame {
        const header = try FrameHeader.read(reader);
        var payload_length = header.length;
        var padding_length: ?u8 = null;
        if (header.flags.isPadded()) {
            padding_length = try reader.takeByte();
            if (padding_length.? >= payload_length) {
                return error.InvalidPaddingLength;
            }
            payload_length -= @as(u32, padding_length.? + 1); // Subtract padding length
        }
        const payload = try allocator.alloc(u8, payload_length);
        try reader.readSliceAll(payload);
        if (padding_length != null) {
            _ = try reader.discard(.limited(padding_length.?));
        }
        return Frame{
            .header = header,
            .payload = payload,
            .padding_length = padding_length,
        };
    }
    pub fn write(self: *Frame, writer: *std.Io.Writer) !void {
        // Write the frame header first
        try self.header.write(writer);
        // Write the payload only if it's not empty
        if (self.payload.len > 0) {
            try writer.writeAll(self.payload[0..self.header.length]);
        }
        // Handle padding if necessary
        if (self.header.flags.isPadded()) {
            const padding_length = self.padding_length orelse unreachable;
            var padding: [255]u8 = undefined; // Max padding length per frame is 255
            for (&padding) |*byte| byte.* = 0; // Initialize padding with zeros
            try writer.writeAll(padding[0..padding_length]);
        }
    }
};
test "frame header read and write" {
    var buffer: [9]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    var header = FrameHeader{
        .length = 16,
        .frame_type = FrameType.SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    };
    try header.write(&writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const read_header = try FrameHeader.read(&reader);
    assert(read_header.length == header.length);
    assert(read_header.frame_type == header.frame_type);
    assert(read_header.flags.value == header.flags.value);
    assert(read_header.reserved == header.reserved);
    assert(read_header.stream_id == header.stream_id);
}
test "frame read and write" {
    var allocator_buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&allocator_buffer);
    const allocator = fba.allocator();
    var io_buffer: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&io_buffer);
    var payload: [16]u8 = undefined;
    for (&payload) |*byte| {
        byte.* = 0xaa;
    }
    var frame = Frame.init(FrameHeader{
        .length = 16,
        .frame_type = FrameType.SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    }, &payload);
    try frame.write(&writer);

    var reader: std.Io.Reader = .fixed(writer.buffered());
    const read_frame = try Frame.read(&reader, allocator);
    assert(read_frame.header.length == frame.header.length);
    assert(read_frame.header.frame_type == frame.header.frame_type);
    assert(read_frame.header.flags.value == frame.header.flags.value);
    assert(read_frame.header.reserved == frame.header.reserved);
    assert(read_frame.header.stream_id == frame.header.stream_id);
    assert(std.mem.eql(u8, read_frame.payload, frame.payload));
}
