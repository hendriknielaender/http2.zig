const std = @import("std");
const assert = std.debug.assert;

const FrameHeader = @import("frame.zig").FrameHeader;
const FrameFlags = @import("frame.zig").FrameFlags;
const FrameType = @import("frame.zig").FrameType;
const Hpack = @import("hpack.zig").Hpack;
const handler = @import("handler.zig");
const transitionState = @import("stream.zig").transitionState;
const StreamState = @import("stream.zig").StreamState;

const default_response_body =
    \\<!DOCTYPE html>
    \\<html>
    \\<body>
    \\<h1>Hello, World!</h1>
    \\</body>
    \\</html>
;

const log = std.log.scoped(.response);

pub fn connectionResponseWindowAvailable(window_size: i32) usize {
    if (window_size > 0) {
        return @intCast(window_size);
    }
    return 0;
}

pub fn shouldSuppressResponseBody(stream: anytype) bool {
    return stream.request_method == .head;
}

pub fn responseHeadersBlock(stream: anytype) []const u8 {
    return stream.header_block_fragments_buf[0..stream.response_header_block_len];
}

pub fn responseBody(stream: anytype) []const u8 {
    return stream.response.?.body;
}

pub fn shouldEndStreamWithHeaders(stream: anytype) bool {
    if (shouldSuppressResponseBody(stream)) {
        return true;
    }
    return responseBody(stream).len == 0;
}

pub fn streamResponseComplete(stream: anytype) bool {
    if (!stream.response_prepared) {
        return false;
    }
    if (!stream.response_headers_sent) {
        return false;
    }
    if (stream.state == .Closed) {
        return true;
    }
    const response = stream.response orelse return false;
    return stream.response_body_sent >= response.body.len;
}

/// Encode response status and headers into the HPACK wire format using the
/// connection-scoped encoder table.  The encoded block is written into the
/// stream's header-block-fragments buffer so `sendResponseHeaders` can write
/// it to the transport without a copy.
pub fn encodeResponseHeaders(
    stream: anytype,
    response: *const handler.Response,
    encoder_table: *Hpack.DynamicTable,
    allocator: std.mem.Allocator,
) !void {
    var encoded = std.ArrayList(u8).initBuffer(&stream.header_block_fragments_buf);
    var status_storage: [3]u8 = undefined;
    const status_code = try std.fmt.bufPrint(
        &status_storage,
        "{d}",
        .{@intFromEnum(response.status)},
    );

    try Hpack.encodeHeaderField(
        .{ .name = ":status", .value = status_code },
        encoder_table,
        &encoded,
        allocator,
    );
    for (response.headers()) |header_field| {
        try Hpack.encodeHeaderField(
            .{ .name = header_field.name, .value = header_field.value },
            encoder_table,
            &encoded,
            allocator,
        );
    }

    stream.response_header_block_len = encoded.items.len;
}

/// Write the HEADERS frame for a stream whose response has already been
/// encoded.  If the response carries no body (empty body or HEAD method),
/// END_STREAM is set on the frame and the stream transitions to closed.
pub fn sendResponseHeaders(
    stream: anytype,
    conn: anytype,
) !void {
    const headers_block = responseHeadersBlock(stream);
    const end_stream = shouldEndStreamWithHeaders(stream);
    var headers_frame = FrameHeader{
        .length = @intCast(headers_block.len),
        .frame_type = FrameType.HEADERS,
        .flags = .{
            .value = if (end_stream)
                FrameFlags.END_HEADERS | FrameFlags.END_STREAM
            else
                FrameFlags.END_HEADERS,
        },
        .reserved = false,
        .stream_id = stream.id,
    };

    log.debug("Sending HEADERS frame for stream {} ({} bytes)", .{
        stream.id,
        headers_block.len,
    });
    try headers_frame.write(conn.writer);
    try conn.writer.writeAll(headers_block);
    stream.response_headers_sent = true;

    if (end_stream) {
        stream.state = transitionState(stream.state, .SendEndStream);
        if (stream.state == .Closed) {
            try conn.mark_stream_closed(stream.id);
            assert(conn.completed_responses_pending < std.math.maxInt(u32));
            conn.completed_responses_pending += 1;
        }
    }
}

/// Write at most one DATA frame for the stream, bounded by flow-control
/// windows and the connection's max frame size.  Returns immediately when
/// the body is fully sent or the window is blocked.
pub fn sendResponseBody(
    stream: anytype,
    conn: anytype,
) !void {
    if (!stream.response_headers_sent) {
        return;
    }
    if (shouldSuppressResponseBody(stream)) {
        return;
    }

    const body = responseBody(stream);
    if (stream.response_body_sent >= body.len) {
        return;
    }

    const remaining_len = body.len - stream.response_body_sent;
    const frame_limit: usize = @intCast(conn.settings.max_frame_size);
    const conn_window = connectionResponseWindowAvailable(conn.send_window_size);
    const stream_window = connectionResponseWindowAvailable(stream.send_window_size);
    const response_len = @min(remaining_len, @min(frame_limit, @min(conn_window, stream_window)));
    if (response_len == 0) {
        return;
    }

    const response_start = stream.response_body_sent;
    const response_end = response_start + response_len;
    const end_stream = response_end == body.len;

    log.debug("Sending DATA frame for stream {} ({} bytes)", .{ stream.id, response_len });
    try stream.sendData(body[response_start..response_end], end_stream);
    conn.send_window_size -= @intCast(response_len);
    stream.response_body_sent = response_end;

    if (end_stream) {
        assert(stream.state == .Closed);
        assert(conn.completed_responses_pending < std.math.maxInt(u32));
        conn.completed_responses_pending += 1;
    }
}

test "shouldEndStreamWithHeaders true when body is empty" {
    const Stream = struct {
        response: ?handler.Response = null,
        response_body_sent: usize = 0,
        response_prepared: bool = true,
        response_headers_sent: bool = false,
        state: StreamState = .Open,
        request_method: handler.Method = .get,
    };
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "";

    var stream = Stream{
        .response = response,
        .state = .Open,
    };
    try std.testing.expect(shouldEndStreamWithHeaders(&stream));
}

test "shouldEndStreamWithHeaders false when body is not empty" {
    const Stream = struct {
        response: ?handler.Response = null,
        response_body_sent: usize = 0,
        response_prepared: bool = true,
        response_headers_sent: bool = false,
        state: StreamState = .Open,
        request_method: handler.Method = .get,
    };
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "data";

    var stream = Stream{
        .response = response,
        .state = .Open,
    };
    try std.testing.expect(!shouldEndStreamWithHeaders(&stream));
}

test "shouldSuppressResponseBody true for HEAD requests" {
    const Stream = struct {
        request_method: handler.Method = .head,
    };
    var stream = Stream{};
    try std.testing.expect(shouldSuppressResponseBody(&stream));
}

test "shouldSuppressResponseBody false for GET requests" {
    const Stream = struct {
        request_method: handler.Method = .get,
    };
    var stream = Stream{};
    try std.testing.expect(!shouldSuppressResponseBody(&stream));
}

test "connectionResponseWindowAvailable returns uint for positive window" {
    try std.testing.expectEqual(@as(usize, 100), connectionResponseWindowAvailable(100));
}

test "connectionResponseWindowAvailable returns zero for non-positive window" {
    try std.testing.expectEqual(@as(usize, 0), connectionResponseWindowAvailable(0));
    try std.testing.expectEqual(@as(usize, 0), connectionResponseWindowAvailable(-1));
}

test "streamResponseComplete false when response not prepared" {
    const Stream = struct {
        response: ?handler.Response = null,
        response_prepared: bool = false,
        response_headers_sent: bool = false,
        response_body_sent: usize = 0,
        state: StreamState = .Open,
    };
    const stream = Stream{};
    try std.testing.expect(!streamResponseComplete(&stream));
}

test "streamResponseComplete true when stream closed" {
    const Stream = struct {
        response: ?handler.Response = null,
        response_prepared: bool = true,
        response_headers_sent: bool = true,
        response_body_sent: usize = 0,
        state: StreamState = .Closed,
    };
    const stream = Stream{};
    try std.testing.expect(streamResponseComplete(&stream));
}
