const std = @import("std");

/// https://httpwg.org/specs/rfc9113.html#preface
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

            if (!self.is_server) {
                try self.sendPreface();
            }
            try self.sendSettings();
            return self;
        }

        fn sendPreface(self: @This()) !void {
            try self.writer.writeAll(http2_preface[0..]);
        }

        fn sendSettings(self: @This()) !void {
            const settings = [_][2]u32{
                .{ 1, 4096 }, // HEADER_TABLE_SIZE
                .{ 3, 100 }, // MAX_CONCURRENT_STREAMS
            };

            for (settings) |setting| {
                // Serialize and send each setting
                var setting_buffer: [8]u8 = undefined;
                std.mem.writeInt(u32, setting_buffer[0..4], setting[0], std.builtin.Endian.big); // setting ID
                std.mem.writeInt(u32, setting_buffer[4..8], setting[1], std.builtin.Endian.big); // setting Value
                try self.writer.writeAll(setting_buffer[0..6]);
            }
        }

        fn close(_: @This()) void {
            // Send the GOAWAY frame
        }
    };
}

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
    //std.debug.print("Written Data: {any}\n", .{writtenData});
    //std.debug.print("Expected Preface: {any}\n", .{http2_preface});
    try std.testing.expect(std.mem.eql(u8, http2_preface, writtenData[0..http2_preface.len]));
    try std.testing.expect(writtenData.len > 0);
}
