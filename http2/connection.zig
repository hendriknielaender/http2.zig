const std = @import("std");

const http2_preface: *const [24:0]u8 = "\x50\x52\x49\x20\x2A\x20\x48\x54\x54\x50\x2F\x32\x2E\x30\x0D\x0A\x0D\x0A\x53\x4D\x0D\x0A\x0D\x0A";

pub fn Connection(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        allocator: *const std.mem.Allocator,
        reader: ReaderType,
        writer: WriterType,
        is_server: bool,
        settings: Settings,

        pub fn init(allocator: *const std.mem.Allocator, reader: ReaderType, writer: WriterType, is_server: bool) !@This() {
            const self = @This(){
                .allocator = allocator,
                .reader = reader,
                .writer = writer,
                .is_server = is_server,
                .settings = Settings.default(),
            };

            // Proper error handling or logging should be considered here
            try self.sendPreface();
            try self.sendSettings();
            return self;
        }

        fn sendPreface(self: @This()) !void {
            if (!self.is_server) {
                try self.writer.writeAll(http2_preface[0..]);
            }
        }

        fn sendSettings(_: @This()) !void {
            // Placeholder for actual implementation
        }

        pub fn close(_: @This()) void {
            // Proper resource cleanup here
        }
    };
}

const Settings = struct {
    header_table_size: u32,
    enable_push: u8,
    max_concurrent_streams: u32,
    initial_window_size: u32,
    max_frame_size: u32,
    max_header_list_size: u32,

    pub fn default() Settings {
        return Settings{
            .header_table_size = 4096,
            .enable_push = 1,
            .max_concurrent_streams = 100,
            .initial_window_size = 65535,
            .max_frame_size = 16384,
            .max_header_list_size = 8192,
        };
    }
};

test "create and close HTTP/2 connection" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);
    const reader = buffer_stream.reader();
    const writer = buffer_stream.writer();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    const connection = try ConnectionType.init(&arena.allocator(), reader, writer, false);
    defer connection.close();

    const writtenData = buffer_stream.getWritten();
    try std.testing.expect(std.mem.eql(u8, http2_preface, writtenData));
    try std.testing.expect(writtenData.len > 0);
}
