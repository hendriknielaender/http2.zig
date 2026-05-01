//! HTTP/2 response encoding and frame writing.
//!
//! Encodes response status and headers into HPACK wire format, writes
//! HEADERS and DATA frames to the transport, and manages stream state
//! transitions for response completion.  The `ResponseWriter` struct
//! consolidates the response lifecycle state that was previously scattered
//! across five separate fields on `StreamInstance`, giving it a single
//! interface for encode / writeHeaders / writeBody progression.

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

/// Owns the response lifecycle state for a single HTTP/2 stream.
/// Encapsulates prepare → encode → writeHeaders → writeBody governance
/// that was previously implicit across five bool / optional / integer fields
/// on `StreamInstance`.
pub const ResponseWriter = struct {
    response: ?handler.Response,
    response_prepared: bool,
    response_header_block_len: usize,
    response_headers_sent: bool,
    response_body_sent: usize,

    /// Points into the stream's `header_block_fragments_buf` so that the
    /// HPACK encoder reuses the same storage that receives request fragments.
    /// The two phases (receive / encode) are mutually exclusive, so no
    /// additional allocation is needed.
    header_fragments_buffer: []u8,

    pub fn init(header_fragments_buffer: []u8) ResponseWriter {
        assert(header_fragments_buffer.len > 0);
        return .{
            .response = null,
            .response_prepared = false,
            .response_header_block_len = 0,
            .response_headers_sent = false,
            .response_body_sent = 0,
            .header_fragments_buffer = header_fragments_buffer,
        };
    }

    pub fn deinit(self: *ResponseWriter) void {
        if (self.response) |*response| {
            response.deinit();
        }
        self.* = undefined;
    }

    pub fn isPrepared(self: *const ResponseWriter) bool {
        return self.response_prepared;
    }

    pub fn isComplete(self: *const ResponseWriter) bool {
        if (!self.response_prepared) return false;
        if (!self.response_headers_sent) return false;
        const response = self.response orelse return false;
        return self.response_body_sent >= response.body.len;
    }

    pub fn shouldEndStreamWithHeaders(
        self: *const ResponseWriter,
        request_method: ?handler.Method,
    ) bool {
        if (request_method) |method| {
            if (method == .head) return true;
        }
        if (!self.response_prepared) return false;
        return self.response.?.body.len == 0;
    }

    pub fn headersBlock(self: *const ResponseWriter) []const u8 {
        assert(self.response_prepared);
        return self.header_fragments_buffer[0..self.response_header_block_len];
    }

    pub fn body(self: *const ResponseWriter) []const u8 {
        assert(self.response_prepared);
        return self.response.?.body;
    }

    /// Encode response status and headers into the HPACK wire format using
    /// the connection-scoped encoder table.  The encoded block lands in
    /// `header_fragments_buffer` so that `sendResponseHeaders` can write it
    /// directly to the transport without a copy.
    pub fn encode(
        self: *ResponseWriter,
        response: *const handler.Response,
        encoder_table: *Hpack.DynamicTable,
        allocator: std.mem.Allocator,
    ) !void {
        assert(!self.response_prepared);
        assert(response.body.len <= 1024 * 1024);

        var encoded = std.ArrayList(u8).initBuffer(self.header_fragments_buffer);
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

        self.response_header_block_len = encoded.items.len;
        self.response = response.*;
        self.response_prepared = true;
    }
};

pub fn streamResponseComplete(stream: *const StreamInstanceType) bool {
    if (stream.state == .Closed) return true;
    return stream.response_writer.isComplete();
}

/// Write the HEADERS frame for a stream whose response has already been
/// encoded.  If the response carries no body, END_STREAM is set and the
/// stream transitions to closed.
pub fn sendResponseHeaders(
    stream: *StreamInstanceType,
    conn: *Connection,
) !void {
    const writer = &stream.response_writer;
    const headers_block = writer.headersBlock();
    const end_stream = writer.shouldEndStreamWithHeaders(stream.request_method);

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
    writer.response_headers_sent = true;

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
    const writer = &stream.response_writer;
    if (!writer.response_headers_sent) return;
    if (stream.request_method == .head) return;

    const body_slice = writer.body();
    if (writer.response_body_sent >= body_slice.len) return;

    const remaining_len = body_slice.len - writer.response_body_sent;
    const frame_limit: usize = @intCast(conn.settings.max_frame_size);
    const conn_window = connectionResponseWindowAvailable(conn.send_window_size);
    const stream_window = connectionResponseWindowAvailable(stream.send_window_size);
    const response_len = @min(remaining_len, @min(frame_limit, @min(conn_window, stream_window)));
    if (response_len == 0) return;

    const response_start = writer.response_body_sent;
    const response_end = response_start + response_len;
    const end_stream = response_end == body_slice.len;

    log.debug("Sending DATA frame for stream {} ({} bytes)", .{ stream.id, response_len });
    try stream.sendData(body_slice[response_start..response_end], end_stream);
    conn.send_window_size -= @intCast(response_len);
    writer.response_body_sent = response_end;

    if (end_stream) {
        assert(stream.state == .Closed);
        assert(conn.completed_responses_pending < std.math.maxInt(u32));
        conn.completed_responses_pending += 1;
    }
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test "ResponseWriter shouldEndStreamWithHeaders when body is empty" {
    var scratch: [256]u8 = undefined;
    var writer = ResponseWriter.init(&scratch);
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "";
    writer.response = response;
    writer.response_prepared = true;
    try std.testing.expect(writer.shouldEndStreamWithHeaders(.get));
}

test "ResponseWriter shouldEndStreamWithHeaders false when body is not empty" {
    var scratch: [256]u8 = undefined;
    var writer = ResponseWriter.init(&scratch);
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "data";
    writer.response = response;
    writer.response_prepared = true;
    try std.testing.expect(!writer.shouldEndStreamWithHeaders(.get));
}

test "ResponseWriter shouldEndStreamWithHeaders for HEAD request without prepared response" {
    var scratch: [256]u8 = undefined;
    var writer = ResponseWriter.init(&scratch);
    try std.testing.expect(writer.shouldEndStreamWithHeaders(.head));
}

test "ResponseWriter shouldEndStreamWithHeaders false for GET with body" {
    var scratch: [256]u8 = undefined;
    var writer = ResponseWriter.init(&scratch);
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "body";
    writer.response = response;
    writer.response_prepared = true;
    try std.testing.expect(!writer.shouldEndStreamWithHeaders(.get));
}

test "connectionResponseWindowAvailable returns uint for positive window" {
    try std.testing.expectEqual(@as(usize, 100), connectionResponseWindowAvailable(100));
}

test "connectionResponseWindowAvailable returns zero for non-positive window" {
    try std.testing.expectEqual(@as(usize, 0), connectionResponseWindowAvailable(0));
    try std.testing.expectEqual(@as(usize, 0), connectionResponseWindowAvailable(-1));
}

test "ResponseWriter isComplete false when not prepared" {
    var scratch: [256]u8 = undefined;
    var writer = ResponseWriter.init(&scratch);
    try std.testing.expect(!writer.isComplete());
}

test "ResponseWriter isComplete true after headers sent and body fully sent" {
    var scratch: [256]u8 = undefined;
    var writer = ResponseWriter.init(&scratch);
    var response = handler.Response.init(.ok);
    defer response.deinit();
    response.body = "";
    writer.response = response;
    writer.response_prepared = true;
    writer.response_headers_sent = true;
    try std.testing.expect(writer.isComplete());
}
