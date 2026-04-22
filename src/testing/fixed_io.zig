const std = @import("std");

/// Native std.Io fixed reader/writer pair for unit tests.
/// This keeps test fixtures on native std.Io fixed buffers without adapters.
pub const FixedIo = struct {
    reader: std.Io.Reader,
    writer: std.Io.Writer,

    pub fn init(read_buffer: []const u8, write_buffer: []u8) FixedIo {
        return .{
            .reader = .fixed(read_buffer),
            .writer = .fixed(write_buffer),
        };
    }

    pub fn resetWriter(self: *FixedIo, write_buffer: []u8) void {
        self.writer = .fixed(write_buffer);
    }

    pub fn written(self: *const FixedIo) []const u8 {
        return self.writer.buffered();
    }
};
