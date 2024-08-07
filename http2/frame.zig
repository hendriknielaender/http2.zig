const std = @import("std");
const assert = std.debug.assert;

/// Represents the type of an HTTP/2 frame
pub const FrameType = enum(u8) {
    DATA = 0,
    HEADERS = 1,
    PRIORITY = 2,
    RST_STREAM = 3,
    SETTINGS = 4,
    PUSH_PROMISE = 5,
    PING = 6,
    GOAWAY = 7,
    WINDOW_UPDATE = 8,
    CONTINUATION = 9,
};

/// Represents the flags of an HTTP/2 frame
pub const FrameFlags = struct {
    value: u8,

    pub const END_STREAM = 0x1;
    pub const END_HEADERS = 0x4;
    pub const PADDED = 0x8;
    pub const PRIORITY = 0x20;

    pub fn init(value: u8) FrameFlags {
        return FrameFlags{ .value = value };
    }

    pub fn setEndStream(self: *FrameFlags) void {
        self.value |= FrameFlags.END_STREAM;
    }

    pub fn isEndStream(self: FrameFlags) bool {
        return (self.value & FrameFlags.END_STREAM) != 0;
    }

    pub fn setEndHeaders(self: *FrameFlags) void {
        self.value |= FrameFlags.END_HEADERS;
    }

    pub fn isEndHeaders(self: FrameFlags) bool {
        return (self.value & FrameFlags.END_HEADERS) != 0;
    }

    pub fn setPadded(self: *FrameFlags) void {
        self.value |= FrameFlags.PADDED;
    }

    pub fn isPadded(self: FrameFlags) bool {
        return (self.value & FrameFlags.PADDED) != 0;
    }

    pub fn setPriority(self: *FrameFlags) void {
        self.value |= FrameFlags.PRIORITY;
    }

    pub fn isPriority(self: FrameFlags) bool {
        return (self.value & FrameFlags.PRIORITY) != 0;
    }
};

/// Represents an HTTP/2 frame header
pub const FrameHeader = struct {
    length: u24,
    frame_type: FrameType,
    flags: FrameFlags,
    reserved: bool,
    stream_id: u31,

    pub fn read(reader: anytype) !FrameHeader {
        var buffer: [9]u8 = undefined;
        _ = try reader.readAll(&buffer);

        std.debug.print("Buffer content: {x}\n", .{buffer});

        const length: u24 = std.mem.readInt(u24, buffer[0..3], .big);
        const frame_type_value: u8 = buffer[3];
        if (frame_type_value > @intFromEnum(FrameType.CONTINUATION)) {
            std.debug.print("Invalid frame_type_value: {}\n", .{frame_type_value});
            return error.InvalidEnumValue;
        }

        const frame_type: FrameType = @enumFromInt(frame_type_value);
        const flags = FrameFlags.init(buffer[4]);
        const reserved: bool = (buffer[5] & 0x80) != 0;
        const stream_id: u31 = @intCast(std.mem.readInt(u32, buffer[5..9], .big) & 0x7fffffff);

        return FrameHeader{
            .length = length,
            .frame_type = frame_type,
            .flags = flags,
            .reserved = reserved,
            .stream_id = stream_id,
        };
    }

    pub fn write(self: *FrameHeader, writer: anytype) !void {
        var buffer: [9]u8 = undefined;
        std.mem.writeInt(u24, buffer[0..3], self.length, .big);
        buffer[3] = @intFromEnum(self.frame_type);
        buffer[4] = self.flags.value;
        const reserved: u8 = @intFromBool(self.reserved);
        const stream_id: u8 = @intCast(self.stream_id >> 24);
        buffer[5] = ((reserved << 7) | stream_id);

        std.mem.writeInt(u32, buffer[5..9], self.stream_id & 0x7fffffff, .big);
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

    pub fn read(reader: anytype, allocator: *std.mem.Allocator) !Frame {
        const header = try FrameHeader.read(reader);

        var payload_length = header.length;
        var padding_length: ?u8 = null;

        if (header.flags.isPadded()) {
            padding_length = try reader.readByte();
            payload_length -= @as(u24, padding_length.? + 1); // Account for the padding length byte
        }

        const payload = try allocator.alloc(u8, payload_length);
        defer allocator.free(payload);

        _ = try reader.readAll(payload);

        if (padding_length != null) {
            // Skip padding bytes
            _ = try reader.skipBytes(@as(u64, padding_length.?), .{});
        }

        return Frame{
            .header = header,
            .payload = payload,
            .padding_length = padding_length,
        };
    }

    pub fn write(self: *Frame, writer: anytype) !void {
        try self.header.write(writer);

        if (self.header.flags.isPadded()) {
            const padding_length = self.padding_length orelse unreachable;
            try writer.writeByte(padding_length);
            try writer.writeAll(self.payload);
            // Write padding bytes (all zeros)
            var padding: [255]u8 = undefined; // Max padding length per frame is 255
            try writer.writeAll(padding[0..padding_length]);
        } else {
            try writer.writeAll(self.payload);
        }
    }
};

test "frame header read and write" {
    var buffer: [9]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();
    var reader = stream.reader();

    var header = FrameHeader{
        .length = 16,
        .frame_type = .SETTINGS, // Ensure this is a valid enum value
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    };

    // Initialize the buffer with zeroes
    buffer = std.mem.zeroes([9]u8);

    // Write to the buffer
    try header.write(&writer);

    // Debugging output: check what was actually written
    std.debug.print("Written buffer: {x}\n", .{buffer});

    // Recreate the FixedBufferStream to reset the read position
    stream = std.io.fixedBufferStream(&buffer);
    reader = stream.reader();

    // Read the header back
    const read_header = try FrameHeader.read(&reader);
    assert(read_header.length == header.length);
    assert(read_header.frame_type == header.frame_type);
    assert(read_header.flags.value == header.flags.value);
    assert(read_header.reserved == header.reserved);
    assert(read_header.stream_id == header.stream_id);
}

test "frame read and write" {
    var buffer: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    var allocator = fba.allocator();

    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();
    var reader = stream.reader();

    var payload: [16]u8 = undefined;

    // Initialize the payload with a known pattern
    for (&payload) |*byte| {
        byte.* = 0xaa;
    }

    var frame = Frame.init(FrameHeader{
        .length = 16,
        .frame_type = .SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    }, &payload);

    try frame.write(&writer);

    std.debug.print("Written buffer: {x}\n", .{buffer[0..25]});

    // Manually copy the data from buffer to read_buffer
    var read_buffer: [4096]u8 = undefined;
    for (buffer, 0..) |byte, i| {
        read_buffer[i] = byte;
    }

    // Use the read_buffer for reading
    var read_stream = std.io.fixedBufferStream(&read_buffer);
    reader = read_stream.reader();

    // Read the frame back from the buffer
    const read_frame = try Frame.read(&reader, &allocator);

    // Assert that the read frame matches the written frame
    assert(read_frame.header.length == frame.header.length);
    assert(read_frame.header.frame_type == frame.header.frame_type);
    assert(read_frame.header.flags.value == frame.header.flags.value);
    assert(read_frame.header.reserved == frame.header.reserved);
    assert(read_frame.header.stream_id == frame.header.stream_id);
    assert(std.mem.eql(u8, read_frame.payload, frame.payload));

    // Debugging output: check the read frame payload
    std.debug.print("Read frame payload: {x}\n", .{read_frame.payload});
}
