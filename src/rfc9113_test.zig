//! Raw-frame regressions for RFC 9113 requirements missed by legacy h2spec.

const std = @import("std");
const Connection = @import("connection.zig").Connection;
const TestIo = @import("testing/fixed_io.zig").FixedIo;
const Frame = @import("frame.zig").Frame;
const FrameType = @import("frame.zig").FrameType;
const FrameFlags = @import("frame.zig").FrameFlags;
const http2_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
fn makeFrame(kind: FrameType, flags: u8, id: u32, payload: []const u8) Frame {
    return .{ .header = .{
        .length = @intCast(payload.len),
        .frame_type = kind,
        .flags = FrameFlags.init(flags),
        .reserved = false,
        .stream_id = id,
    }, .payload = payload };
}

fn firstPayload(bytes: []const u8, kind: FrameType) ?[]const u8 {
    var offset: usize = 0;
    while (offset + 9 <= bytes.len) {
        const size = (@as(usize, bytes[offset]) << 16) |
            (@as(usize, bytes[offset + 1]) << 8) | bytes[offset + 2];
        if (offset + 9 + size > bytes.len) return null;
        if (bytes[offset + 3] == @intFromEnum(kind)) return bytes[offset + 9 .. offset + 9 + size];
        offset += 9 + size;
    }
    return null;
}

const request_block = [_]u8{ 0x82, 0x87, 0x84 }; // GET, https, /

test "RFC 9113 encoder emits dynamic table size update after SETTINGS reduction" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &request_block));
    try std.testing.expect(connection.hpack_encoder_table.current_size > 0);
    const output_start = test_io.written().len;
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{ 0, 1, 0, 0, 0, 0 }));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 3, &request_block));
    const block = firstPayload(test_io.written()[output_start..], .HEADERS).?;
    try std.testing.expectEqual(@as(u8, 0x20), block[0]);
}

test "RFC 9113 malformed trailer still decompresses its HPACK entries" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 4, 1, &request_block));
    // Incrementally indexed x-a: b; trailer is malformed because END_STREAM is absent.
    try connection.handleFrameEventDriven(
        makeFrame(.HEADERS, 4, 1, &.{ 0x40, 3, 'x', '-', 'a', 1, 'b' }),
    );
    try std.testing.expect(!connection.goaway_sent);
    try std.testing.expectEqual(@as(usize, 1), connection.hpack_decoder_table.count);
}

test "RFC 9113 stream refusal still decompresses its HPACK entries" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    connection.settings.max_concurrent_streams = 0;
    const block = request_block ++ [_]u8{ 0x40, 3, 'x', '-', 'a', 1, 'b' };
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &block));
    try std.testing.expect(!connection.goaway_sent);
    try std.testing.expectEqual(@as(usize, 1), connection.hpack_decoder_table.count);
}

test "RFC 9113 undefined WINDOW_UPDATE flag does not close stream" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 4, 1, &request_block));
    try connection.handleFrameEventDriven(makeFrame(.WINDOW_UPDATE, 1, 1, &.{ 0, 0, 0, 1 }));
    try std.testing.expectEqual(
        @import("stream.zig").StreamState.Open,
        connection.stream_storage.find(1).?.state,
    );
}

test "RFC 9113 empty field name before pseudo headers is rejected" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    const block = [_]u8{ 0, 0, 1, '\r' } ++ request_block;
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &block));
    const response_block = firstPayload(test_io.written(), .HEADERS).?;
    try std.testing.expectEqual(@as(u8, 0x8c), response_block[0]); // :status 400
}

test "RFC 9113 zero length padded HEADERS fragment is accepted" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 9, 1, &.{0}));
    try std.testing.expect(!connection.goaway_sent);
    try connection.handleFrameEventDriven(makeFrame(.CONTINUATION, 4, 1, &request_block));
    const response_block = firstPayload(test_io.written(), .HEADERS).?;
    try std.testing.expectEqual(@as(u8, 0x88), response_block[0]);
}

test "RFC 9113 invalid HEADERS padding produces PROTOCOL_ERROR" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 12, 1, &.{1}));
    const goaway = firstPayload(test_io.written(), .GOAWAY).?;
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, goaway[4..8], .big));
}

test "RFC 9113 resize sequences emit the minimum and final limit once" {
    const Hpack = @import("hpack.zig").Hpack;
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &request_block));
    const start = test_io.written().len;
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{
        0, 1, 0, 0, 0, 64, 0, 1, 0, 0, 1, 0,
    }));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 3, &request_block));
    const block = firstPayload(test_io.written()[start..], .HEADERS).?;
    var decoder = Hpack.DynamicTable.init(4096);
    const minimum = try Hpack.decodeHeaderFieldView(block, &decoder);
    try std.testing.expectEqual(@as(usize, 64), minimum.representation.table_size_update);
    const final = try Hpack.decodeHeaderFieldView(block[minimum.bytes_consumed..], &decoder);
    try std.testing.expectEqual(@as(usize, 256), final.representation.table_size_update);
    const next_start = test_io.written().len;
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 5, &request_block));
    try std.testing.expectEqual(
        @as(u8, 0x88),
        firstPayload(test_io.written()[next_start..], .HEADERS).?[0],
    );
}

test "RFC 9113 malformed request response emits pending HPACK resize" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{ 0, 1, 0, 0, 0, 0 }));
    const malformed = request_block ++ [_]u8{ 0, 0, 1, '\r' };
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &malformed));
    try std.testing.expectEqualSlices(u8, &.{ 0x20, 0x8c }, firstPayload(
        test_io.written(),
        .HEADERS,
    ).?);
    try std.testing.expect(!connection.goaway_sent);
}

const indexed_entry = [_]u8{ 0x40, 3, 'x', '-', 'a', 1, 'b' };

test "RFC 9113 refused split field block preserves the next stream's HPACK index" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    connection.settings.max_concurrent_streams = 1;
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 4, 1, &request_block));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 1, 3, indexed_entry[0..3]));
    try std.testing.expectEqual(@as(?u32, 3), connection.expecting_continuation_stream_id);
    try std.testing.expectEqual(@as(u32, 3), connection.last_stream_id);
    try connection.handleFrameEventDriven(makeFrame(.CONTINUATION, 4, 3, indexed_entry[3..]));
    try std.testing.expectEqual(@as(?u32, null), connection.expecting_continuation_stream_id);
    try std.testing.expectEqual(@as(usize, 1), connection.hpack_decoder_table.count);
    try connection.handleFrameEventDriven(makeFrame(.RST_STREAM, 0, 1, &.{ 0, 0, 0, 0 }));
    const start = test_io.written().len;
    const referencing = request_block ++ [_]u8{0xbe};
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 5, &referencing));
    try std.testing.expectEqual(@as(u8, 0x88), firstPayload(
        test_io.written()[start..],
        .HEADERS,
    ).?[0]);
    try std.testing.expect(!connection.goaway_sent);
    try std.testing.expectEqual(@as(u8, 0), connection.stream_storage.activeCount());
}

test "RFC 9113 malformed split trailer is decoded before releasing its slot" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 4, 1, &request_block));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 0, 1, indexed_entry[0..3]));
    try std.testing.expect(connection.stream_storage.find(1) != null);
    try connection.handleFrameEventDriven(makeFrame(.CONTINUATION, 4, 1, indexed_entry[3..]));
    try std.testing.expect(connection.stream_storage.find(1) == null);
    try std.testing.expectEqual(@as(usize, 1), connection.hpack_decoder_table.count);
    const referencing = request_block ++ [_]u8{0xbe};
    const start = test_io.written().len;
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 3, &referencing));
    try std.testing.expectEqual(@as(u8, 0x88), firstPayload(
        test_io.written()[start..],
        .HEADERS,
    ).?[0]);
    try std.testing.expect(!connection.goaway_sent);
}

test "RFC 9113 discard buffer exhaustion closes with COMPRESSION_ERROR" {
    const capacity = @import("memory_budget.zig").MemBudget.max_header_size_bytes;
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    connection.settings.max_concurrent_streams = 0;
    const block = [_]u8{0x82} ** capacity;
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 1, 1, &block));
    try connection.handleFrameEventDriven(makeFrame(.CONTINUATION, 4, 1, &.{0x82}));
    const goaway = firstPayload(test_io.written(), .GOAWAY).?;
    try std.testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, goaway[4..8], .big));
}

test "RFC 9113 empty names after fields and in trailers remain stream errors" {
    for ([_]bool{ false, true }) |trailer| {
        var output: [8192]u8 = undefined;
        var test_io = TestIo.init(http2_preface, &output);
        var connection = try Connection.initOwnedForTesting(
            std.testing.allocator,
            &test_io.reader,
            &test_io.writer,
            .server,
        );
        defer connection.deinit();
        try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
        if (trailer) {
            try connection.handleFrameEventDriven(makeFrame(.HEADERS, 4, 1, &request_block));
            try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &.{ 0, 0, 1, 'x' }));
        } else {
            const block = request_block ++ [_]u8{ 0, 0, 1, 'x' };
            try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &block));
        }
        const reset = firstPayload(test_io.written(), .RST_STREAM).?;
        try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, reset[0..4], .big));
        try std.testing.expect(!connection.goaway_sent);
    }
}

test "RFC 9113 undefined PRIORITY and CONTINUATION flags do not end a request" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 0, 1, request_block[0..1]));
    try connection.handleFrameEventDriven(makeFrame(.CONTINUATION, 5, 1, request_block[1..]));
    try connection.handleFrameEventDriven(makeFrame(.PRIORITY, 0xff, 1, &.{ 0, 0, 0, 1, 0 }));
    const stream = connection.stream_storage.find(1).?;
    try std.testing.expectEqual(@import("stream.zig").StreamState.Open, stream.state);
    try std.testing.expect(!stream.request_complete);
    try connection.handleFrameEventDriven(makeFrame(.DATA, 1, 1, &.{}));
    try std.testing.expect(!connection.goaway_sent);
    try std.testing.expect(firstPayload(test_io.written(), .HEADERS) != null);
}

test "RFC 9113 all representable HEADERS padding lengths permit an empty fragment" {
    for ([_]u8{ 0, 1, 255 }) |padding| {
        var output: [8192]u8 = undefined;
        var test_io = TestIo.init(http2_preface, &output);
        var connection = try Connection.initOwnedForTesting(
            std.testing.allocator,
            &test_io.reader,
            &test_io.writer,
            .server,
        );
        defer connection.deinit();
        try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
        var payload = [_]u8{0} ** 256;
        payload[0] = padding;
        const size = @as(usize, padding) + 1;
        try connection.handleFrameEventDriven(makeFrame(.HEADERS, 9, 1, payload[0..size]));
        try connection.handleFrameEventDriven(makeFrame(.CONTINUATION, 4, 1, &request_block));
        try std.testing.expect(!connection.goaway_sent);
        try std.testing.expectEqual(@as(u8, 0x88), firstPayload(test_io.written(), .HEADERS).?[0]);
    }
}

test "RFC 9113 discarded blocks still enforce HPACK syntax and instruction order" {
    const invalid_blocks = [_][]const u8{ &.{ 0x82, 0x20 }, &.{0x80} };
    for (invalid_blocks) |block| {
        var output: [8192]u8 = undefined;
        var test_io = TestIo.init(http2_preface, &output);
        var connection = try Connection.initOwnedForTesting(
            std.testing.allocator,
            &test_io.reader,
            &test_io.writer,
            .server,
        );
        defer connection.deinit();
        try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
        connection.settings.max_concurrent_streams = 0;
        try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, block));
        const goaway = firstPayload(test_io.written(), .GOAWAY).?;
        try std.testing.expectEqual(@as(u32, 9), std.mem.readInt(u32, goaway[4..8], .big));
        try std.testing.expect(firstPayload(test_io.written(), .RST_STREAM) == null);
    }
}

test "RFC 9113 refused stream identifiers cannot be reused" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    connection.settings.max_concurrent_streams = 0;
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &request_block));
    try std.testing.expect(!connection.goaway_sent);
    try connection.handleFrameEventDriven(makeFrame(.HEADERS, 5, 1, &request_block));
    try std.testing.expect(connection.goaway_sent);
}

test "RFC 9113 invalid SETTINGS length is not acknowledged" {
    var output: [8192]u8 = undefined;
    var test_io = TestIo.init(http2_preface, &output);
    var connection = try Connection.initOwnedForTesting(
        std.testing.allocator,
        &test_io.reader,
        &test_io.writer,
        .server,
    );
    defer connection.deinit();
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{}));
    const start = test_io.written().len;
    try connection.handleFrameEventDriven(makeFrame(.SETTINGS, 0, 0, &.{0}));
    const frames = test_io.written()[start..];
    try std.testing.expect(firstPayload(frames, .SETTINGS) == null);
    const goaway = firstPayload(frames, .GOAWAY).?;
    try std.testing.expectEqual(@as(u32, 6), std.mem.readInt(u32, goaway[4..8], .big));
}
