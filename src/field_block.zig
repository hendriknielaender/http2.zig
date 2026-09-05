//! Bounded field-block framing and decompression for discarded streams.

const std = @import("std");
const assert = std.debug.assert;
const Frame = @import("frame.zig").Frame;
const FrameFlags = @import("frame.zig").FrameFlags;
const Hpack = @import("hpack.zig").Hpack;
const capacity = @import("memory_budget.zig").MemBudget.max_header_size_bytes;

/// Padding errors affect the connection; missing frame fields are size errors.
pub fn headersFragment(frame: Frame) error{ ProtocolError, FrameSizeError }![]const u8 {
    assert(frame.header.frame_type == .HEADERS);
    var fragment = frame.payload;
    if (frame.header.flags.has(FrameFlags.PADDED)) {
        if (fragment.len == 0) return error.FrameSizeError;
        const padding: usize = fragment[0];
        if (padding >= fragment.len) return error.ProtocolError;
        fragment = fragment[1 .. fragment.len - padding];
    }
    if (frame.header.flags.has(FrameFlags.PRIORITY)) {
        if (fragment.len < 5) return error.FrameSizeError;
        fragment = fragment[5..];
    }
    return fragment;
}

/// One block can be in flight per connection. A refused stream needs no slot,
/// but its HPACK instructions must still update the shared decoder.
pub const Discarded = struct {
    storage: [capacity]u8 = undefined,
    len: usize = 0,
    stream_id: u32 = 0,
    error_code: u32 = 0,

    pub fn start(self: *Discarded, stream_id: u32, error_code: u32) void {
        assert(self.stream_id == 0);
        assert(stream_id > 0);
        self.stream_id = stream_id;
        self.error_code = error_code;
        self.len = 0;
    }

    pub fn append(self: *Discarded, fragment: []const u8) error{CompressionError}!void {
        assert(self.stream_id > 0);
        assert(self.len <= self.storage.len);
        if (fragment.len > self.storage.len - self.len) return error.CompressionError;
        @memcpy(self.storage[self.len..][0..fragment.len], fragment);
        self.len += fragment.len;
    }

    pub fn decode(self: *const Discarded, table: *Hpack.DynamicTable) !void {
        assert(self.stream_id > 0);
        assert(self.len <= self.storage.len);
        var cursor: usize = 0;
        var saw_field = false;
        while (cursor < self.len) {
            const decoded = try Hpack.decodeHeaderFieldView(self.storage[cursor..self.len], table);
            assert(decoded.bytes_consumed > 0);
            cursor += decoded.bytes_consumed;
            assert(cursor <= self.len);
            switch (decoded.representation) {
                .field => saw_field = true,
                .table_size_update => if (saw_field) return error.CompressionError,
            }
        }
    }

    pub fn reset(self: *Discarded) void {
        self.len = 0;
        self.stream_id = 0;
        self.error_code = 0;
    }
};

comptime {
    const budget = @import("memory_budget.zig").MemBudget;
    assert(@sizeOf(Discarded) <= budget.discarded_field_block_bytes);
}
