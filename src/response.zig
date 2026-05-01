//! HTTP/2 response encoding and frame writing.
//!
//! Encodes response status and headers into HPACK wire format, writes
//! HEADERS and DATA frames to the transport, and manages stream state
//! transitions for response completion.  All functions operate on the
//! stream and connection that own the relevant buffers and I/O handles.

const std = @import("std");
const assert = std.debug.assert;

const FrameHeader = @import("frame.zig").FrameHeader;
const FrameFlags = @import("frame.zig").FrameFlags;
const FrameType = @import("frame.zig").FrameType;
const Hpack = @import("hpack.zig").Hpack;
const handler = @import("handler.zig");
const transitionState = @import("stream.zig").transitionState;
const StreamState = @import("stream.zig").StreamState;
const DefaultStream = @import("stream.zig").DefaultStream;
const Connection = @import("connection.zig").Connection;

const StreamInstanceType = DefaultStream.StreamInstance;

const log = std.log.scoped(.response);

pub fn connectionResponseWindowAvailable(window_size: i32) usize {
    if (window_size > 0) {
        return @intCast(window_size);
    }
    return 0;
}

pub fn shouldSuppressResponseBody(stream: *const StreamInstanceType) bool {
    return stream.request_method == .head;
}

pub fn responseHeadersBlock(stream: *const StreamInstanceType) []const u8 {
    return stream.header_block_fragments_buf[0..stream.response_header_block_len];
}

pub fn responseBody(stream: *const StreamInstanceType) []const u8 {
    return stream.response.?.body;
}

pub fn shouldEndStreamWithHeaders(stream: *const StreamInstanceType) bool {
    if (shouldSuppressResponseBody(stream)) {
        return true;
    }
    return responseBody(stream).len == 0;
}

pub fn streamResponseComplete(stream: *const StreamInstanceType) bool {
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
    stream: *StreamInstanceType,
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
/// encoded.  If the response carries no body, END_STREAM is set and the
/// stream transitions to closed.
pub fn sendResponseHeaders(
    stream: *StreamInstanceType,
    conn: *Connection,
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
/// windows and the connection's max frame size.
pub fn sendResponseBody(
    stream: *StreamInstanceType,
    conn: *Connection,
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

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test "shouldEndStreamWithHeaders true when body is empty" {
    var stream = DefaultStream.StreamInstance{
        .id = 1,
        .state = .Open,
        .conn = undefined,
        .recv_window_size = 65535,
        .send_window_size = 65535,
        .initial_window_size = 65535,
        .header_block_fragments_buf = undefined,
        .headers_bytes_storage = undefined,
        .header_block_fragments_len = 0,
        .headers_bytes_len = 0,
        .expecting_continuation = false,
        .headers_storage = undefined,
        .headers = .empty,
        .content_length = null,
        .request_method_bytes = null,
        .request_method = .get,
        .request_path = null,
        .total_data_received = 0,
        .request_body_storage = undefined,
        .request_body_len = 0,
        .response_body_storage = undefined,
        .request_headers_complete = false,
        .request_complete = false,
        .response = null,
        .response_prepared = true,
        .response_header_block_len = 0,
        .response_headers_sent = false,
        .response_body_sent = 0,
        .cleaned_up = false,
        .priority = .{},
        .priority_update_received = false,
        .schedule_epoch_last = 0,
        .schedule_count = 0,
        .stream_dependency = 0,
        .exclusive = false,
        .weight = 16,
    };
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "";
    stream.response = response;
    try std.testing.expect(shouldEndStreamWithHeaders(&stream));
}

test "shouldEndStreamWithHeaders false when body is not empty" {
    var stream = DefaultStream.StreamInstance{
        .id = 1,
        .state = .Open,
        .conn = undefined,
        .recv_window_size = 65535,
        .send_window_size = 65535,
        .initial_window_size = 65535,
        .header_block_fragments_buf = undefined,
        .headers_bytes_storage = undefined,
        .header_block_fragments_len = 0,
        .headers_bytes_len = 0,
        .expecting_continuation = false,
        .headers_storage = undefined,
        .headers = .empty,
        .content_length = null,
        .request_method_bytes = null,
        .request_method = .get,
        .request_path = null,
        .total_data_received = 0,
        .request_body_storage = undefined,
        .request_body_len = 0,
        .response_body_storage = undefined,
        .request_headers_complete = false,
        .request_complete = false,
        .response = null,
        .response_prepared = true,
        .response_header_block_len = 0,
        .response_headers_sent = false,
        .response_body_sent = 0,
        .cleaned_up = false,
        .priority = .{},
        .priority_update_received = false,
        .schedule_epoch_last = 0,
        .schedule_count = 0,
        .stream_dependency = 0,
        .exclusive = false,
        .weight = 16,
    };
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "data";
    stream.response = response;
    try std.testing.expect(!shouldEndStreamWithHeaders(&stream));
}

test "shouldSuppressResponseBody true for HEAD requests" {
    var stream = DefaultStream.StreamInstance{
        .id = 0,
        .state = .Idle,
        .conn = undefined,
        .recv_window_size = 0,
        .send_window_size = 0,
        .initial_window_size = 0,
        .header_block_fragments_buf = undefined,
        .headers_bytes_storage = undefined,
        .header_block_fragments_len = 0,
        .headers_bytes_len = 0,
        .expecting_continuation = false,
        .headers_storage = undefined,
        .headers = .empty,
        .content_length = null,
        .request_method_bytes = null,
        .request_method = .head,
        .request_path = null,
        .total_data_received = 0,
        .request_body_storage = undefined,
        .request_body_len = 0,
        .response_body_storage = undefined,
        .request_headers_complete = false,
        .request_complete = false,
        .response = null,
        .response_prepared = false,
        .response_header_block_len = 0,
        .response_headers_sent = false,
        .response_body_sent = 0,
        .cleaned_up = false,
        .priority = .{},
        .priority_update_received = false,
        .schedule_epoch_last = 0,
        .schedule_count = 0,
        .stream_dependency = 0,
        .exclusive = false,
        .weight = 16,
    };
    try std.testing.expect(shouldSuppressResponseBody(&stream));
}

test "shouldSuppressResponseBody false for GET requests" {
    var stream = DefaultStream.StreamInstance{
        .id = 0,
        .state = .Idle,
        .conn = undefined,
        .recv_window_size = 0,
        .send_window_size = 0,
        .initial_window_size = 0,
        .header_block_fragments_buf = undefined,
        .headers_bytes_storage = undefined,
        .header_block_fragments_len = 0,
        .headers_bytes_len = 0,
        .expecting_continuation = false,
        .headers_storage = undefined,
        .headers = .empty,
        .content_length = null,
        .request_method_bytes = null,
        .request_method = .get,
        .request_path = null,
        .total_data_received = 0,
        .request_body_storage = undefined,
        .request_body_len = 0,
        .response_body_storage = undefined,
        .request_headers_complete = false,
        .request_complete = false,
        .response = null,
        .response_prepared = false,
        .response_header_block_len = 0,
        .response_headers_sent = false,
        .response_body_sent = 0,
        .cleaned_up = false,
        .priority = .{},
        .priority_update_received = false,
        .schedule_epoch_last = 0,
        .schedule_count = 0,
        .stream_dependency = 0,
        .exclusive = false,
        .weight = 16,
    };
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
    var stream = DefaultStream.StreamInstance{
        .id = 0,
        .state = .Open,
        .conn = undefined,
        .recv_window_size = 0,
        .send_window_size = 0,
        .initial_window_size = 0,
        .header_block_fragments_buf = undefined,
        .headers_bytes_storage = undefined,
        .header_block_fragments_len = 0,
        .headers_bytes_len = 0,
        .expecting_continuation = false,
        .headers_storage = undefined,
        .headers = .empty,
        .content_length = null,
        .request_method_bytes = null,
        .request_method = .get,
        .request_path = null,
        .total_data_received = 0,
        .request_body_storage = undefined,
        .request_body_len = 0,
        .response_body_storage = undefined,
        .request_headers_complete = false,
        .request_complete = false,
        .response = null,
        .response_prepared = false,
        .response_header_block_len = 0,
        .response_headers_sent = false,
        .response_body_sent = 0,
        .cleaned_up = false,
        .priority = .{},
        .priority_update_received = false,
        .schedule_epoch_last = 0,
        .schedule_count = 0,
        .stream_dependency = 0,
        .exclusive = false,
        .weight = 16,
    };
    try std.testing.expect(!streamResponseComplete(&stream));
}

test "streamResponseComplete true when stream closed" {
    var stream = DefaultStream.StreamInstance{
        .id = 0,
        .state = .Closed,
        .conn = undefined,
        .recv_window_size = 0,
        .send_window_size = 0,
        .initial_window_size = 0,
        .header_block_fragments_buf = undefined,
        .headers_bytes_storage = undefined,
        .header_block_fragments_len = 0,
        .headers_bytes_len = 0,
        .expecting_continuation = false,
        .headers_storage = undefined,
        .headers = .empty,
        .content_length = null,
        .request_method_bytes = null,
        .request_method = .get,
        .request_path = null,
        .total_data_received = 0,
        .request_body_storage = undefined,
        .request_body_len = 0,
        .response_body_storage = undefined,
        .request_headers_complete = false,
        .request_complete = false,
        .response = null,
        .response_prepared = true,
        .response_header_block_len = 0,
        .response_headers_sent = true,
        .response_body_sent = 0,
        .cleaned_up = false,
        .priority = .{},
        .priority_update_received = false,
        .schedule_epoch_last = 0,
        .schedule_count = 0,
        .stream_dependency = 0,
        .exclusive = false,
        .weight = 16,
    };
    try std.testing.expect(streamResponseComplete(&stream));
}
