const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.net.Stream, std.net.Stream);
const Stream = @import("http2").Stream;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:9001; press Ctrl-C to exit...\n", .{});

    while (true) {
        var con = try listener.accept();
        defer con.stream.close();
        std.debug.print("Accepted Connection from: {any}\n", .{con.address});

        var connection = try Connection.init(allocator, con.reader(), con.writer(), true);

        try processConnection(&connection);
    }
}

// Function to handle HTTP/2 frames and respond to requests
fn processConnection(connection: *Connection) !void {
    // Read client preface
    try connection.receiveSettings();

    // Main loop for handling frames
    while (true) {
        const frame = try connection.receiveFrame();
        switch (frame.header.frame_type) {
            .HEADERS => {
                std.debug.print("Received HEADERS frame\n", .{});
                const stream = try connection.getStream(frame.header.stream_id);

                if (stream != null and frame.payload.len > 0) {
                    // Respond to GET request
                    std.debug.print(">>> Sending 200 OK response with Hello, World!\n", .{});

                    const response_data = "Hello, World!";
                    try connection.sendData(stream, response_data);

                    // Send END_STREAM flag to close the stream
                    try connection.sendHeaders(stream, true);
                }
            },
            else => {},
        }
    }
}
