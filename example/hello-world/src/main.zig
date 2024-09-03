const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);
const Stream = http2.Stream;
const FrameFlags = http2.FrameFlags;
const FrameHeader = http2.FrameHeader;
const FrameType = http2.FrameType;
const Frame = http2.Frame;

pub fn main() !void {
    var allocator = std.heap.page_allocator;
    const address = try std.net.Address.resolveIp("0.0.0.0", 9001);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();

    std.debug.print("Listening on 0.0.0.0:9001; press Ctrl-C to exit...\n", .{});

    while (true) {
        var con = try listener.accept();
        defer con.stream.close();
        std.debug.print("Accepted Connection from: {any}\n", .{con.address});

        const reader = con.stream.reader().any();
        const writer = con.stream.writer().any();

        var connection = try Connection.init(&allocator, reader, writer, true);

        try processConnection(&connection);
    }
}

// Function to handle HTTP/2 frames and respond to requests
fn processConnection(connection: *Connection) !void {
    // Send HTTP/2 settings frame
    try connection.sendSettings();

    // Main loop for handling frames
    while (true) {
        const frame = try connection.receiveFrame();

        std.debug.print("Processing frame: {any}\n", .{frame.header.frame_type});

        switch (frame.header.frame_type) {
            .SETTINGS => {
                std.debug.print("Processing SETTINGS frame.\n", .{});
                // Correctly apply settings
                try connection.applySettings(frame);
                try connection.sendSettingsAck();
            },
            .HEADERS => {
                std.debug.print("Processing HEADERS frame.\n", .{});
                // Your existing HEADERS frame logic here
            },
            // Add more frame type handling as necessary
            else => {
                std.debug.print("Ignoring frame of type: {any}\n", .{@tagName(frame.header.frame_type)});
            },
        }
    }
}

// Additional function for sending SETTINGS ACK
pub fn sendSettingsAck(self: @This()) !void {
    const ack_frame = Frame{
        .header = FrameHeader{
            .length = 0,
            .frame_type = FrameType.SETTINGS,
            .flags = FrameFlags.init(FrameFlags.ACK),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{},
    };

    try ack_frame.write(self.writer);
}
