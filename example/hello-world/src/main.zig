const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Hpack = http2.Hpack.Hpack;

const ServerConnection = struct {
    connection: http2.Connection(std.io.AnyReader, std.io.AnyWriter),
    dynamic_table: Hpack.DynamicTable,

    pub fn init(reader: std.io.AnyReader, writer: std.io.AnyWriter) !ServerConnection {
        const dynamic_table = try Hpack.DynamicTable.init(@constCast(&std.heap.page_allocator), 4096); // Initialize dynamic table with 4KB size

        return ServerConnection{
            .connection = try Connection.init(@constCast(&std.heap.page_allocator), reader, writer, true),
            .dynamic_table = dynamic_table,
        };
    }

    pub fn deinit(_: *ServerConnection) void {
        //self.dynamic_table.deinit();
    }

    pub fn sendResponse(self: *ServerConnection, stream_id: u31) !void {
        const response_body = "Hello, World!";
        const response_headers = [_]Hpack.HeaderField{
            .{ .name = ":status", .value = "200" },
        };

        // Create buffer to store encoded headers
        var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
        defer buffer.deinit();

        // Encode the headers into the buffer using the dynamic table
        for (response_headers) |header| {
            try Hpack.encodeHeaderField(header, &self.dynamic_table, &buffer);
        }

        const encoded_headers = buffer.items;

        var headers_frame = http2.Frame{
            .header = http2.FrameHeader{
                .length = @intCast(encoded_headers.len),
                .frame_type = .HEADERS,
                .flags = http2.FrameFlags{ .value = http2.FrameFlags.END_HEADERS },
                .reserved = false,
                .stream_id = stream_id,
            },
            .payload = encoded_headers,
        };

        try headers_frame.write(self.connection.writer);

        var data_frame = http2.Frame{
            .header = http2.FrameHeader{
                .length = @intCast(response_body.len),
                .frame_type = .DATA,
                .flags = http2.FrameFlags{ .value = http2.FrameFlags.END_STREAM },
                .reserved = false,
                .stream_id = stream_id,
            },
            .payload = response_body,
        };
        try data_frame.write(self.connection.writer);
    }
};

pub fn main() !void {
    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:9001; press Ctrl-C to exit...\n", .{});

    while (true) {
        var conn = try listener.accept();
        defer conn.stream.close();

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        var server_conn = try ServerConnection.init(conn.stream.reader().any(), conn.stream.writer().any());
        defer server_conn.deinit();

        try server_conn.sendResponse(1);
    }
}
