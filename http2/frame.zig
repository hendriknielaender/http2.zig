const std = @import("std");
const assert = std.debug.assert;

/// Represents the type of an HTTP/2 frame
const FrameType = enum(u8) {
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
const FrameFlags = struct {
    value: u8,

    fn init(value: u8) FrameFlags {
        return FrameFlags{ .value = value };
    }
};

/// Represents an HTTP/2 frame header
const FrameHeader = struct {
    length: u24,
    frame_type: FrameType,
    flags: FrameFlags,
    reserved: bool,
    stream_id: u31,

    pub fn read(reader: anytype) !FrameHeader {
        var buffer: [9]u8 = undefined;
        _ = try reader.readAll(&buffer);

        const length: u24 = std.mem.readInt(u24, buffer[0..3], .big);
        const frame_type_value: u8 = buffer[3];
        if (frame_type_value > @intFromEnum(FrameType.CONTINUATION)) {
            return error.InvalidEnumValue;
        }
        const frame_type: FrameType = @enumFromInt(frame_type_value);
        const flags = FrameFlags.init(buffer[4]);
        const reserved: bool = @bitCast(@intFromBool(buffer[5] & 0x80 != 0));
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
        const reserved_bit: u8 = @intFromBool(self.reserved);
        const stream_id_high: u8 = @truncate(self.stream_id >> 24);
        buffer[5] = (reserved_bit << 7) | stream_id_high;
        const stream_id_low: u32 = @intCast(self.stream_id & 0x7fffffff);
        std.mem.writeInt(u32, buffer[5..9], stream_id_low, .big);
        try writer.writeAll(&buffer);
    }
};

/// Represents an HTTP/2 frame
const Frame = struct {
    header: FrameHeader,
    payload: []const u8,

    pub fn init(header: FrameHeader, payload: []const u8) Frame {
        return Frame{ .header = header, .payload = payload };
    }

    pub fn read(reader: anytype, allocator: *std.mem.Allocator) !Frame {
        const header = try FrameHeader.read(reader);
        const payload = try allocator.alloc(u8, header.length);
        defer allocator.free(payload);

        _ = try reader.readAll(payload);
        return Frame.init(header, payload);
    }

    pub fn write(self: *Frame, writer: anytype) !void {
        try self.header.write(writer);
        try writer.writeAll(self.payload);
    }
};

test "frame header read and write" {
    var buffer: [4096]u8 = undefined;

    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();
    var reader = stream.reader();

    var header = FrameHeader{
        .length = 16,
        .frame_type = .SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    };

    try header.write(&writer);

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

    const payload: [16]u8 = undefined;

    var frame = Frame.init(FrameHeader{
        .length = 16,
        .frame_type = .SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    }, &payload);

    try frame.write(&writer);

    const read_frame = try Frame.read(&reader, &allocator);

    assert(read_frame.header.length == frame.header.length);
    assert(read_frame.header.frame_type == frame.header.frame_type);
    assert(read_frame.header.flags.value == frame.header.flags.value);
    assert(read_frame.header.reserved == frame.header.reserved);
    assert(read_frame.header.stream_id == frame.header.stream_id);
    assert(std.mem.eql(u8, read_frame.payload, frame.payload));
}
