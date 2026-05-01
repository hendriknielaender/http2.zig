//! HTTP/2 frame header parsing.
//!
//! Frame headers are 9 byte, byte-packed records. The receive path must accept
//! unknown frame types, so the hot parser is intentionally scalar and lenient.
//! The old strict SIMD and batch parsers were not wired into the wire-format
//! read loop and did not match variable-length HTTP/2 frame payload layout.

const std = @import("std");
const frame = @import("frame.zig");
const builtin = @import("builtin");

pub const FrameFlags = frame.FrameFlags;

pub const ParsedFrameHeader = struct {
    length: u32,
    frame_type: u8,
    flags: FrameFlags,
    reserved: bool,
    stream_id: u32,
};

pub const SIMDFrameParser = struct {
    const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const has_avx2 = blk: {
        if (builtin.cpu.arch == .x86_64) {
            break :blk std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
        }
        break :blk false;
    };

    pub fn parseFrameHeaderLenient(data: []const u8) error{
        InsufficientData,
        InvalidFrameLength,
    }!ParsedFrameHeader {
        if (data.len < 9) {
            return error.InsufficientData;
        }

        const length = (@as(u32, data[0]) << 16) |
            (@as(u32, data[1]) << 8) |
            @as(u32, data[2]);
        if (length > 0xFFFFFF) {
            return error.InvalidFrameLength;
        }

        const stream_id_raw = std.mem.readInt(u32, data[5..9], .big);

        return .{
            .length = length,
            .frame_type = data[3],
            .flags = FrameFlags.init(data[4]),
            .reserved = (stream_id_raw & 0x80000000) != 0,
            .stream_id = stream_id_raw & 0x7FFFFFFF,
        };
    }

    pub fn validate_preface_simd(data: []const u8) bool {
        if (data.len < preface.len) {
            return false;
        }

        if (comptime has_avx2) {
            return validate_preface_avx2(data[0..preface.len]);
        } else {
            return std.mem.eql(u8, data[0..preface.len], preface);
        }
    }

    fn validate_preface_avx2(data: []const u8) bool {
        std.debug.assert(data.len == preface.len);
        std.debug.assert(preface.len == 24);

        const data_head = @as(@Vector(16, u8), data[0..16].*);
        const data_tail = @as(@Vector(8, u8), data[16..24].*);
        const want_head = @as(@Vector(16, u8), preface[0..16].*);
        const want_tail = @as(@Vector(8, u8), preface[16..24].*);

        if (!@reduce(.And, data_head == want_head)) {
            return false;
        }
        return @reduce(.And, data_tail == want_tail);
    }
};

test "lenient frame header parsing accepts known frame type" {
    const data = [_]u8{
        0x00, 0x00, 0x08,
        0x01, 0x04, 0x00,
        0x00, 0x00, 0x01,
    };

    const header = try SIMDFrameParser.parseFrameHeaderLenient(&data);

    try std.testing.expectEqual(@as(u32, 8), header.length);
    try std.testing.expectEqual(@as(u8, 0x01), header.frame_type);
    try std.testing.expect(header.flags.isEndHeaders());
    try std.testing.expectEqual(@as(u32, 1), header.stream_id);
    try std.testing.expect(!header.reserved);
}

test "lenient frame header parsing accepts unknown frame type" {
    const data = [_]u8{
        0x00, 0x00, 0x00,
        0x99, 0x00, 0x80,
        0x00, 0x00, 0x03,
    };

    const header = try SIMDFrameParser.parseFrameHeaderLenient(&data);

    try std.testing.expectEqual(@as(u32, 0), header.length);
    try std.testing.expectEqual(@as(u8, 0x99), header.frame_type);
    try std.testing.expect(header.reserved);
    try std.testing.expectEqual(@as(u32, 3), header.stream_id);
}

test "preface validation" {
    try std.testing.expect(SIMDFrameParser.validate_preface_simd("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    try std.testing.expect(!SIMDFrameParser.validate_preface_simd("GET / HTTP/1.1\r\n\r\n"));
}
