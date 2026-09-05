//! Wire-level HTTP/2 constants shared by parsers, connections, and simulators.
//!
//! Keep RFC-defined values here so limits are named by meaning rather than
//! repeated as unrelated integer literals.

const std = @import("std");
const assert = std.debug.assert;

pub const EndpointRole = enum(u1) {
    client,
    server,
};

pub const frame_header_size: usize = 9;
pub const frame_payload_size_default: u32 = 16_384;
pub const frame_payload_size_max: u32 = (1 << 24) - 1;
pub const stream_identifier_max: u32 = (1 << 31) - 1;
pub const stream_identifier_reserved_bit: u32 = 1 << 31;

pub const hpack_dynamic_table_size_default: u32 = 4_096;
pub const flow_control_window_size_default: u32 = (1 << 16) - 1;
pub const flow_control_window_size_max: u32 = (1 << 31) - 1;

pub const settings_parameter_size: usize = 6;
pub const settings_header_table_size_id: u16 = 0x1;
pub const settings_enable_push_id: u16 = 0x2;
pub const settings_max_concurrent_streams_id: u16 = 0x3;
pub const settings_initial_window_size_id: u16 = 0x4;
pub const settings_max_frame_size_id: u16 = 0x5;
pub const settings_max_header_list_size_id: u16 = 0x6;
pub const settings_no_rfc7540_priorities_id: u16 = 0x9;

comptime {
    assert(frame_header_size == 9);
    assert(frame_payload_size_default == 1 << 14);
    assert(frame_payload_size_max == std.math.maxInt(u24));
    assert(stream_identifier_max == std.math.maxInt(u31));
    assert(stream_identifier_reserved_bit == 1 << 31);
    assert(hpack_dynamic_table_size_default == 1 << 12);
    assert(flow_control_window_size_default == std.math.maxInt(u16));
    assert(flow_control_window_size_max == std.math.maxInt(i32));
    assert(settings_parameter_size == @sizeOf(u16) + @sizeOf(u32));
}

test "RFC 9113 protocol constants retain their wire values" {
    try std.testing.expectEqual(@as(u32, 16_384), frame_payload_size_default);
    try std.testing.expectEqual(@as(u32, 16_777_215), frame_payload_size_max);
    try std.testing.expectEqual(@as(u32, 65_535), flow_control_window_size_default);
    try std.testing.expectEqual(@as(u32, 2_147_483_647), flow_control_window_size_max);
}
