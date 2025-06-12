//! HTTP/2 Protocol Implementation
//!
//! This module provides a complete HTTP/2 implementation following RFC 7540.

const std = @import("std");

// Core HTTP/2 modules
pub const Connection = @import("connection.zig").Connection;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const FrameType = @import("frame.zig").FrameType;
pub const Stream = @import("stream.zig").Stream;
pub const Hpack = @import("hpack.zig").Hpack;
pub const tls = @import("tls.zig");
pub const error_types = @import("error.zig");

// Additional exports for convenience
pub const frame = @import("frame.zig");

pub const max_frame_size_default = 16384;
pub const max_header_list_size_default = 8192;
pub const initial_window_size_default = 65535;

// Error types - descriptive and grouped
pub const Http2Error = error{
    protocol_error,
    frame_size_error,
    compression_error,
    stream_closed,
    flow_control_error,
    settings_timeout,
    connection_error,
};

test {
    std.testing.refAllDecls(@This());
}
