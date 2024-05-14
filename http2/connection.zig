const std = @import("std");
const tls = @import("tls.zig");

pub const Connection = struct {
    allocator: *std.mem.Allocator,
    stream: std.io.Stream,
    is_server: bool,
    settings: Settings,
    tls_context: ?tls.TlsContext,

    pub fn init(allocator: *std.mem.Allocator, stream: std.io.Stream, is_server: bool) !Connection {
        const self = Connection{
            .allocator = allocator,
            .stream = stream,
            .is_server = is_server,
            .settings = Settings.default(),
            .tls_context = if (is_server) tls.TlsContext.serverInit() else tls.TlsContext.clientInit(),
        };

        try self.sendPreface();
        try self.sendSettings();
        return self;
    }

    fn sendPreface(self: *Connection) !void {
        if (!self.is_server) {
            const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            try self.stream.writer().writeAll(preface);
        }
    }

    fn sendSettings(self: *Connection) !void {
        var frame = Frame.newSettings(self.settings);
        try frame.encode(self.stream.writer());
    }

    pub fn close(self: *Connection) void {
        _ = self.stream.close();
    }
};

const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: u8 = 1,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,

    pub fn default() Settings {
        return Settings{};
    }
};

const Frame = struct {
    // Frame handling code here
};

test "create and close HTTP/2 connection" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const stream = try std.io.getStream();
    const connection = try Connection.init(arena.allocator(), stream, true);
    defer connection.close();

    // Test that connection preface and settings are sent correctly
    std.testing.expectEqualStrings("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", stream.getWrittenData());
    std.testing.expect(stream.getWrittenData().len > 0); // Check settings frame length is non-zero
}
