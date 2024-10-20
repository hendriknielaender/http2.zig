const std = @import("std");
const assert = std.debug.assert;

const log = std.log.scoped(.frame);

pub const FrameType = u8;

// Define constants for known frame types
pub const FRAME_TYPE_DATA = 0x0;
pub const FRAME_TYPE_HEADERS = 0x1;
pub const FRAME_TYPE_PRIORITY = 0x2;
pub const FRAME_TYPE_RST_STREAM = 0x3;
pub const FRAME_TYPE_SETTINGS = 0x4;
pub const FRAME_TYPE_PUSH_PROMISE = 0x5;
pub const FRAME_TYPE_PING = 0x6;
pub const FRAME_TYPE_GOAWAY = 0x7;
pub const FRAME_TYPE_WINDOW_UPDATE = 0x8;
pub const FRAME_TYPE_CONTINUATION = 0x9;

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

    pub fn read(reader: anytype) !FrameHeader {
        var buffer: [9]u8 = undefined;
        _ = try reader.readAll(&buffer);

        // Parse the 24-bit length from the first three bytes
        const length: u32 = (@as(u32, buffer[0]) << 16) | (@as(u32, buffer[1]) << 8) | @as(u32, buffer[2]);

        // Ensure the length is within 24 bits
        if (length > 0xFFFFFF) {
            return error.InvalidFrameLength;
        }

        const frame_type: u8 = buffer[3];

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

    pub fn read2(reader: anytype) !FrameHeader {
        var buffer: [9]u8 = undefined;
        _ = try reader.readAll(&buffer);

        log.debug("Buffer content: {x}\n", .{buffer});

        // Parse the 24-bit length from the first three bytes
        const length: u32 = (@as(u32, buffer[0]) << 16) | (@as(u32, buffer[1]) << 8) | @as(u32, buffer[2]);

        // Ensure the length is within 24 bits
        if (length > 0xFFFFFF) {
            return error.InvalidFrameLength;
        }

        const frame_type_value: u8 = buffer[3];
        if (frame_type_value > @intFromEnum(FrameType.CONTINUATION)) {
            log.err("Invalid frame_type_value: {}\n", .{frame_type_value});
            return error.InvalidEnumValue;
        }

        const frame_type: FrameType = @enumFromInt(frame_type_value);
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

    pub fn write(self: *FrameHeader, writer: anytype) !void {
        var buffer: [9]u8 = undefined;

        // Ensure the length fits into 24 bits
        if (self.length > 0xFFFFFF) {
            return error.InvalidFrameLength;
        }

        // Write the 24-bit length into the first three bytes
        buffer[0] = @intCast((self.length >> 16) & 0xFF);
        buffer[1] = @intCast((self.length >> 8) & 0xFF);
        buffer[2] = @intCast(self.length & 0xFF);

        buffer[3] = self.frame_type;
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

    pub fn deinit(self: *Frame, allocator: *std.mem.Allocator) void {
        allocator.free(self.payload);
        self.payload = &[_]u8{};
    }

    pub fn read(reader: anytype, allocator: *std.mem.Allocator) !Frame {
        const header = try FrameHeader.read(reader);
        log.debug("Read FrameHeader: {any}\n", .{header});

        var payload_length = header.length;
        var padding_length: ?u8 = null;

        if (header.flags.isPadded()) {
            padding_length = try reader.readByte();
            if (padding_length.? >= payload_length) {
                return error.InvalidPaddingLength;
            }
            payload_length -= @as(u32, padding_length.? + 1); // Subtract padding length
            log.debug("Padding length: {}\n", .{padding_length.?});
        }

        const payload = try allocator.alloc(u8, payload_length);
        _ = try reader.readAll(payload);

        if (padding_length != null) {
            _ = try reader.skipBytes(@as(u64, padding_length.?), .{});
        }

        return Frame{
            .header = header,
            .payload = payload,
            .padding_length = padding_length,
        };
    }

    pub fn write(self: *Frame, writer: anytype) !void {
        // Write the frame header first
        try self.header.write(writer);

        log.debug("Frame.write called with payload length: {d}\n", .{self.payload.len});

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
    var stream = std.io.fixedBufferStream(&buffer);
    var writer = stream.writer();
    var reader = stream.reader();

    var header = FrameHeader{
        .length = 16,
        .frame_type = FRAME_TYPE_SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    };

    // Initialize the buffer with zeroes
    buffer = std.mem.zeroes([9]u8);

    // Write to the buffer
    try header.write(&writer);

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

    // Create the frame with the payload
    var frame = Frame.init(FrameHeader{
        .length = 16,
        .frame_type = FRAME_TYPE_SETTINGS,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = 0,
    }, &payload);

    try frame.write(&writer);

    std.debug.print("Written buffer: {x}\n", .{buffer[0..25]});

    // Copy the data from buffer to read_buffer
    var read_buffer: [4096]u8 = undefined;
    for (buffer, 0..) |byte, i| {
        read_buffer[i] = byte;
    }

    // Use the read_buffer for reading
    var read_stream = std.io.fixedBufferStream(&read_buffer);
    reader = read_stream.reader();

    // Read the frame back from the buffer
    const read_frame = try Frame.read(&reader, &allocator);

    std.debug.print("Read FrameHeader: {any}\n", .{read_frame.header});
    std.debug.print("Read payload: {x}\n", .{read_frame.payload});
    std.debug.print("Original payload: {x}\n", .{frame.payload});

    // Assert that the read frame matches the written frame
    assert(read_frame.header.length == frame.header.length);
    assert(read_frame.header.frame_type == frame.header.frame_type);
    assert(read_frame.header.flags.value == frame.header.flags.value);
    assert(read_frame.header.reserved == frame.header.reserved);
    assert(read_frame.header.stream_id == frame.header.stream_id);

    // Compare payloads directly; should be the same
    assert(std.mem.eql(u8, read_frame.payload, frame.payload));

    std.debug.print("Read frame payload: {x}\n", .{read_frame.payload});
}
