const std = @import("std");
const assert = std.debug.assert;

const http2_preface: []const u8 = "\x50\x52\x49\x20\x2A\x20\x48\x54\x54\x50\x2F\x32\x2E\x30\x0D\x0A\x0D\x0A\x53\x4D\x0D\x0A\x0D\x0A";

pub fn Connection(ReaderType: type, WriterType: type) type {
    return struct {
        allocator: *std.mem.Allocator,
        reader: ReaderType,
        writer: WriterType,
        is_server: bool,
        settings: Settings,

        pub fn init(allocator: *std.mem.Allocator, reader: ReaderType, writer: WriterType, is_server: bool) !@This() {
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
            try self.writer.writeAll(http2_preface);
        }

        fn sendSettings(self: @This()) !void {
            const settings = [_][2]u32{
                .{ 1, self.settings.header_table_size },
                .{ 3, self.settings.max_concurrent_streams },
                .{ 4, self.settings.initial_window_size },
                .{ 5, self.settings.max_frame_size },
                .{ 6, self.settings.max_header_list_size },
            };

            var buffer: [6]u8 = undefined;

            for (settings) |setting| {
                std.mem.writeInt(u16, buffer[0..2], @intCast(setting[0]), .big);
                std.mem.writeInt(u32, buffer[2..6], setting[1], .big);
                try self.writer.writeAll(buffer[0..6]);
            }
        }

        pub fn receiveSettings(self: @This()) !void {
            const settings_frame_header_size = 9;
            var frame_header: [settings_frame_header_size]u8 = undefined;
            try self.reader.readAll(&frame_header);
            const length = std.mem.readInt(u24, frame_header[0..3], .big);
            if (length % 6 != 0) return error.InvalidSettingsFrameSize;

            var settings_payload: []u8 = try self.allocator.alloc(u8, length);
            defer self.allocator.free(settings_payload);
            try self.reader.readAll(settings_payload);

            for (settings_payload.chunks(6)) |setting| {
                const id = std.mem.readInt(u16, setting[0..2], .big);
                const value = std.mem.readInt(u32, setting[2..6], .big);
                switch (id) {
                    1 => self.settings.header_table_size = value,
                    3 => self.settings.max_concurrent_streams = value,
                    4 => self.settings.initial_window_size = value,
                    5 => self.settings.max_frame_size = value,
                    6 => self.settings.max_header_list_size = value,
                    else => {},
                }
            }
        }

        fn close(self: @This()) !void {
            var goaway_frame: [17]u8 = undefined;
            std.mem.writeInt(u24, goaway_frame[0..3], 8, .big);
            goaway_frame[3] = 0x7; // type (GOAWAY)
            goaway_frame[4] = 0; // flags
            std.mem.writeInt(u32, goaway_frame[5..9], 0, .big); // last stream ID
            std.mem.writeInt(u32, goaway_frame[9..13], 0, .big); // error code
            try self.writer.writeAll(&goaway_frame);
        }
    };
}

const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
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
    var allocator = arena.allocator();
    const connection = try ConnectionType.init(&allocator, reader, writer, false);

    defer {
        const close_result = connection.close() catch |err| {
            std.debug.print("Error closing connection: {}\n", .{err});
        };
        _ = close_result;
    }

    const writtenData = buffer_stream.getWritten();
    assert(std.mem.eql(u8, http2_preface, writtenData[0..http2_preface.len]));
    assert(writtenData.len > 0);
}
