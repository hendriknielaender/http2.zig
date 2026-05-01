//! Per-frame-type dispatch for HTTP/2 connections.
//!
//! Extracted from `Connection` to concentrate frame-type routing and the
//! per-handler protocol logic.  A `DispatchContext` carries pointers into
//! the connection state — no hidden `self.*` references.  Stream management,
//! request dispatch, and I/O coalescing stay in `connection.zig`.

const std = @import("std");
const assert = std.debug.assert;

const FrameType = @import("frame.zig").FrameType;
const FrameFlags = @import("frame.zig").FrameFlags;
const FrameHeader = @import("frame.zig").FrameHeader;
const Frame = @import("frame.zig").Frame;
const Hpack = @import("hpack.zig").Hpack;
const resp = @import("response.zig");
const HttpPriority = @import("http_priority.zig").Priority;
const memory_budget = @import("memory_budget.zig");

const stream_storage_module = @import("stream_storage.zig");
const StreamStorage = stream_storage_module.StreamStorage;
const StreamInstance = @import("stream.zig").DefaultStream.StreamInstance;

const max_streams_per_connection = memory_budget.MemBudget.max_streams_per_connection;

const log = std.log.scoped(.frame_handler);

const priority_frame_payload_size: usize = 5;
const priority_update_payload_id_size: usize = 4;
const settings_no_rfc7540_priorities_id: u16 = 0x9;

comptime {
    assert(priority_frame_payload_size == 5);
    assert(priority_update_payload_id_size == 4);
    assert(settings_no_rfc7540_priorities_id == 0x9);
}

const FrameHandler = enum(u8) {
    data = @intFromEnum(FrameType.DATA),
    headers = @intFromEnum(FrameType.HEADERS),
    priority = @intFromEnum(FrameType.PRIORITY),
    rst_stream = @intFromEnum(FrameType.RST_STREAM),
    settings = @intFromEnum(FrameType.SETTINGS),
    push_promise = @intFromEnum(FrameType.PUSH_PROMISE),
    ping = @intFromEnum(FrameType.PING),
    goaway = @intFromEnum(FrameType.GOAWAY),
    window_update = @intFromEnum(FrameType.WINDOW_UPDATE),
    continuation = @intFromEnum(FrameType.CONTINUATION),
    priority_update = @intFromEnum(FrameType.PRIORITY_UPDATE),

    pub fn fromFrameType(frame_type: u8) ?FrameHandler {
        return switch (frame_type) {
            @intFromEnum(FrameType.DATA) => .data,
            @intFromEnum(FrameType.HEADERS) => .headers,
            @intFromEnum(FrameType.PRIORITY) => .priority,
            @intFromEnum(FrameType.RST_STREAM) => .rst_stream,
            @intFromEnum(FrameType.SETTINGS) => .settings,
            @intFromEnum(FrameType.PUSH_PROMISE) => .push_promise,
            @intFromEnum(FrameType.PING) => .ping,
            @intFromEnum(FrameType.GOAWAY) => .goaway,
            @intFromEnum(FrameType.WINDOW_UPDATE) => .window_update,
            @intFromEnum(FrameType.CONTINUATION) => .continuation,
            @intFromEnum(FrameType.PRIORITY_UPDATE) => .priority_update,
            else => null,
        };
    }
};

pub const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = max_streams_per_connection,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
    no_rfc7540_priorities: bool = true,

    pub fn default() Settings {
        return Settings{};
    }
};

pub const ConnectionPendingPriorityUpdate = struct {
    stream_id: u32 = 0,
    priority: HttpPriority = .{},
    in_use: bool = false,
};

pub const DispatchContext = struct {
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    stream_storage: *StreamStorage,
    settings: *Settings,
    hpack_decoder_table: *Hpack.DynamicTable,
    hpack_encoder_table: *Hpack.DynamicTable,
    recv_window_size: *i32,
    send_window_size: *i32,
    goaway_sent: *bool,
    goaway_received: *bool,
    last_stream_id: *u32,
    expecting_continuation_stream_id: *?u32,
    client_settings_received: *bool,
    peer_first_settings_received: *bool,
    peer_no_rfc7540_priorities: *bool,
    peer_no_rfc7540_priorities_setting_received: *bool,
    pending_stream_slots: *[max_streams_per_connection]u8,
    pending_stream_queued: *[max_streams_per_connection]bool,
    pending_stream_count: *u8,
    pending_priority_updates: *[max_streams_per_connection]ConnectionPendingPriorityUpdate,
    schedule_epoch_next: *u64,
    completed_responses_pending: *u32,
    connection_closed: *bool,
    conn_ptr: *anyopaque,
};

pub fn dispatchFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.length == 0 and
        frame.header.frame_type == .DATA and
        frame.header.stream_id == 0 and
        frame.payload.len == 0)
    {
        return;
    }

    const frame_type_u8 = @intFromEnum(frame.header.frame_type);
    const frame_handler = FrameHandler.fromFrameType(frame_type_u8) orelse {
        log.debug("Ignoring unknown frame type {d} on stream {d}", .{
            frame_type_u8,
            frame.header.stream_id,
        });
        return;
    };

    switch (frame_handler) {
        .data => try handleDataFrameOptimized(ctx, frame),
        .headers => try handleHeadersFrameOptimized(ctx, frame),
        .priority => try handlePriorityFrameOptimized(ctx, frame),
        .rst_stream => try handleRstStreamFrameOptimized(ctx, frame),
        .settings => try handleSettingsFrameOptimized(ctx, frame),
        .push_promise => try handlePushPromiseFrameOptimized(ctx, frame),
        .ping => try handlePingFrameOptimized(ctx, frame),
        .goaway => try handleGoawayFrameOptimized(ctx, frame),
        .window_update => try handleWindowUpdateFrameOptimized(ctx, frame),
        .continuation => try handleContinuationFrameOptimized(ctx, frame),
        .priority_update => try handlePriorityUpdateFrameOptimized(ctx, frame),
    }
}

// -----------------------------------------------------------------------
//  Per-frame-type handlers
// -----------------------------------------------------------------------

fn handleDataFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id == 0) {
        return sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x1, "DATA frame on stream 0");
    }

    if (ctx.stream_storage.find(frame.header.stream_id)) |stream| {
        switch (stream.state) {
            .Idle => {
                log.err("DATA frame on idle stream {}: PROTOCOL_ERROR", .{frame.header.stream_id});
                try sendGoawayAndClose(ctx, 0, 0x1, "DATA frame on idle stream: PROTOCOL_ERROR");
                return error.ProtocolError;
            },
            .HalfClosedRemote => {
                log.err("DATA on HalfClosedRemote stream {}: STREAM_CLOSED", .{frame.header.stream_id});
                return sendRstStream(ctx, frame.header.stream_id, 0x5);
            },
            .Closed => {
                log.debug("DATA frame on closed stream {}: sending RST_STREAM", .{frame.header.stream_id});
                return sendRstStream(ctx, frame.header.stream_id, 0x5);
            },
            else => {},
        }

        if (frame.header.length > 0) {
            try sendWindowUpdate(ctx, 0, @intCast(frame.header.length));
        }

        try handleOptimizedStreamFrame(ctx, stream, frame);
    } else {
        if (frame.header.stream_id <= ctx.last_stream_id.*) {
            log.debug("DATA frame on closed stream {}: sending RST_STREAM", .{frame.header.stream_id});
            return sendRstStream(ctx, frame.header.stream_id, 0x5);
        }
        log.err("DATA frame on idle stream {}: PROTOCOL_ERROR", .{frame.header.stream_id});
        try sendGoawayAndClose(ctx, 0, 0x1, "DATA frame on idle stream: PROTOCOL_ERROR");
        return error.ProtocolError;
    }
}

fn handleHeadersFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id == 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "HEADERS frame on stream 0");
    }

    if (ctx.stream_storage.find(frame.header.stream_id)) |stream| {
        switch (stream.state) {
            .HalfClosedRemote => {
                log.err("HEADERS on HalfClosedRemote stream {}: STREAM_CLOSED", .{frame.header.stream_id});
                return sendRstStream(ctx, frame.header.stream_id, 0x5);
            },
            .Closed => {
                log.debug("HEADERS frame on closed stream {}: sending RST_STREAM", .{frame.header.stream_id});
                return sendRstStream(ctx, frame.header.stream_id, 0x5);
            },
            else => {},
        }
    } else if (frame.header.stream_id < ctx.last_stream_id.*) {
        log.err("HEADERS with stream ID {} < last_stream_id {}: PROTOCOL_ERROR", .{
            frame.header.stream_id,
            ctx.last_stream_id.*,
        });
        try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x1, "Stream ID decreased: PROTOCOL_ERROR");
        return error.ProtocolError;
    } else if (frame.header.stream_id == ctx.last_stream_id.*) {
        log.debug("HEADERS on released stream {}: STREAM_CLOSED", .{frame.header.stream_id});
        try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x5, "HEADERS on closed stream: STREAM_CLOSED");
        return error.StreamClosed;
    }

    const stream = getStream(ctx, frame.header.stream_id) catch |err| {
        if (err == error.MaxConcurrentStreamsExceeded) {
            return sendRstStream(ctx, frame.header.stream_id, 0x7);
        }
        return err;
    };
    try handleOptimizedStreamFrame(ctx, stream, frame);
}

fn handlePriorityFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id == 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "PRIORITY frame on stream 0");
    }

    if (!priorityFramePayloadValidSize(frame)) {
        try sendPriorityFrameSizeError(ctx);
        return;
    }

    if (ctx.stream_storage.find(frame.header.stream_id)) |stream| {
        try handleOptimizedStreamFrame(ctx, stream, frame);
    } else if (frame.header.stream_id > ctx.last_stream_id.*) {
        const dep = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFFFFFF;
        if (dep == frame.header.stream_id) {
            log.err("PRIORITY on idle stream {} depends on itself: PROTOCOL_ERROR", .{frame.header.stream_id});
            try sendGoawayAndClose(ctx, 0, 0x1, "PRIORITY depends on itself: PROTOCOL_ERROR");
            return error.ProtocolError;
        }
        log.debug("Ignoring PRIORITY on idle stream {d}", .{frame.header.stream_id});
    } else {
        log.debug("Ignoring PRIORITY on closed stream {d}", .{frame.header.stream_id});
    }
}

fn handleRstStreamFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id == 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "RST_STREAM frame on stream 0");
    }
    if (frame.payload.len != 4) {
        try sendGoawayAndClose(ctx, 0, 0x6, "RST_STREAM invalid payload: FRAME_SIZE_ERROR");
        return error.FrameSizeError;
    }
    if (ctx.stream_storage.find(frame.header.stream_id)) |stream| {
        try handleOptimizedStreamFrame(ctx, stream, frame);
    } else {
        if (frame.header.stream_id > ctx.last_stream_id.*) {
            try sendGoawayAndClose(ctx, 0, 0x1, "RST_STREAM on idle stream: PROTOCOL_ERROR");
            return error.ProtocolError;
        }
        log.debug("RST_STREAM on closed stream {}: ignoring", .{frame.header.stream_id});
    }
}

fn handleSettingsFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id != 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "SETTINGS on non-zero stream");
    }
    try applyFrameSettings(ctx, frame);
    if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
        try sendSettingsAck(ctx);
    }
}

fn handlePushPromiseFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    _ = frame;
    return sendGoawayAndClose(ctx, 0, 0x1, "Client sent PUSH_PROMISE");
}

fn handlePingFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id != 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "PING on non-zero stream");
    }
    if (frame.payload.len != 8) {
        return sendGoawayAndClose(ctx, 0, 0x6, "Invalid PING payload size");
    }
    if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
        try sendPing(ctx, frame.payload, true);
    }
}

fn handleGoawayFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id != 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "GOAWAY on non-zero stream");
    }
    try handleGoawayFrame(ctx, frame);
}

fn handleWindowUpdateFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id == 0) {
        try handleWindowUpdate(ctx, frame);
        return;
    }

    if (ctx.stream_storage.find(frame.header.stream_id)) |stream| {
        try handleOptimizedStreamFrame(ctx, stream, frame);
    } else {
        if (frame.header.stream_id > ctx.last_stream_id.*) {
            log.err("WINDOW_UPDATE on idle stream {}: PROTOCOL_ERROR", .{frame.header.stream_id});
            try sendGoawayAndClose(ctx, 0, 0x1, "WINDOW_UPDATE on idle stream: PROTOCOL_ERROR");
            return;
        }
        log.debug("WINDOW_UPDATE on closed stream {}: ignoring", .{frame.header.stream_id});
    }
}

fn handleContinuationFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id == 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "CONTINUATION on stream 0");
    }
    const expected = ctx.expecting_continuation_stream_id.* orelse {
        log.err("Received CONTINUATION without preceding HEADERS: PROTOCOL_ERROR", .{});
        try sendGoawayAndClose(ctx, 0, 0x1, "Unexpected CONTINUATION: PROTOCOL_ERROR");
        return error.ProtocolError;
    };
    if (frame.header.stream_id != expected) {
        log.err("CONTINUATION on stream {} while expecting {}: PROTOCOL_ERROR", .{
            frame.header.stream_id,
            expected,
        });
        try sendGoawayAndClose(ctx, 0, 0x1, "CONTINUATION on wrong stream: PROTOCOL_ERROR");
        return error.ProtocolError;
    }
    const stream = ctx.stream_storage.find(frame.header.stream_id) orelse {
        log.err("CONTINUATION on idle stream {}: PROTOCOL_ERROR", .{frame.header.stream_id});
        try sendGoawayAndClose(ctx, 0, 0x1, "CONTINUATION on idle stream: PROTOCOL_ERROR");
        return error.ProtocolError;
    };
    try handleOptimizedStreamFrame(ctx, stream, frame);
}

fn handlePriorityUpdateFrameOptimized(ctx: *DispatchContext, frame: Frame) !void {
    try handlePriorityUpdateFrame(ctx, frame);
}

// -----------------------------------------------------------------------
//  Internal helpers
// -----------------------------------------------------------------------

fn handleOptimizedStreamFrame(
    ctx: *DispatchContext,
    stream: *StreamInstance,
    frame: Frame,
) !void {
    try handleStreamLevelFrameProcess(ctx, stream, frame);
    handleStreamLevelFrameUpdateContinuationState(ctx, frame);
}

fn handleStreamLevelFrameProcess(
    ctx: *DispatchContext,
    stream: *StreamInstance,
    frame: Frame,
) !void {
    stream.handleFrame(frame) catch |err| {
        log.err("Error handling frame in stream {d}: {s}", .{
            frame.header.stream_id,
            @errorName(err),
        });
        if (ctx.goaway_sent.*) return;
        try handleStreamLevelFrameProcessError(ctx, frame.header.stream_id, err);
    };

    if (stream.state == .Closed) {
        const stream_index = ctx.stream_storage.findIndex(stream.id) orelse unreachable;
        ctx.stream_storage.releaseSlot(stream_index);
        return;
    }

    try queueStreamIfReady(ctx, stream);
}

fn handleStreamLevelFrameProcessError(ctx: *DispatchContext, stream_id: u32, err: anyerror) !void {
    switch (err) {
        error.FrameSizeError => {
            try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x6, "Frame size error: FRAME_SIZE_ERROR");
        },
        error.CompressionError => {
            try sendGoawayAndClose(ctx, 0, 0x9, "Compression error: COMPRESSION_ERROR");
        },
        error.StreamClosed => {
            if (!ctx.goaway_sent.*) {
                try sendRstStream(ctx, stream_id, 0x5);
            }
        },
        error.FlowControlError => {
            try sendRstStream(ctx, stream_id, 0x3);
        },
        error.ProtocolError => {
            try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x1, "Protocol error: PROTOCOL_ERROR");
            return err;
        },
        error.InvalidStreamState, error.IdleStreamError => {
            try sendGoawayAndClose(ctx, 0, 0x1, "Invalid stream state: PROTOCOL_ERROR");
        },
        else => {},
    }
}

fn handleStreamLevelFrameUpdateContinuationState(ctx: *DispatchContext, frame: Frame) void {
    const is_headers = frame.header.frame_type == FrameType.HEADERS;
    const is_push = frame.header.frame_type == FrameType.PUSH_PROMISE;
    const is_cont = frame.header.frame_type == FrameType.CONTINUATION;
    const has_end = (frame.header.flags.value & FrameFlags.END_HEADERS) != 0;

    if ((is_headers or is_push) and !has_end) {
        ctx.expecting_continuation_stream_id.* = frame.header.stream_id;
    }
    if (is_cont and has_end) {
        ctx.expecting_continuation_stream_id.* = null;
    }
}

fn handleGoawayFrame(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.payload.len < 8) {
        try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x1, "Invalid GOAWAY: PROTOCOL_ERROR");
        return error.ProtocolError;
    }

    const last_stream_id = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFFFFFF;
    const error_code = std.mem.readInt(u32, frame.payload[4..8], .big);
    log.debug("Received GOAWAY with last_stream_id={d}, error_code={d}", .{ last_stream_id, error_code });

    ctx.goaway_received.* = true;
    ctx.last_stream_id.* = last_stream_id;
}

fn handleWindowUpdate(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.payload.len != 4) {
        try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x6, "WINDOW_UPDATE with invalid payload: FRAME_SIZE_ERROR");
        return;
    }
    const increment = std.mem.readInt(u32, frame.payload[0..4], .big);
    if (increment == 0) {
        try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x1, "WINDOW_UPDATE increment 0: PROTOCOL_ERROR");
        return;
    }
    if (increment > 0x7FFFFFFF) {
        try sendGoawayAndClose(ctx, ctx.last_stream_id.*, 0x3, "WINDOW_UPDATE increment too large: FLOW_CONTROL_ERROR");
        return;
    }

    if (frame.header.stream_id == 0) {
        updateSendWindow(ctx, ctx.send_window_size, increment) catch |err| {
            if (err == error.FlowControlError) {
                try finishAfterGoaway(ctx);
                return;
            }
            return err;
        };
    } else {
        const stream = ctx.stream_storage.find(frame.header.stream_id) orelse {
            if (frame.header.stream_id > ctx.last_stream_id.*) {
                try sendGoawayAndClose(ctx, 0, 0x1, "WINDOW_UPDATE on idle: PROTOCOL_ERROR");
                return error.ProtocolError;
            }
            return;
        };
        stream.updateSendWindow(@intCast(increment)) catch |err| {
            if (err == error.FlowControlError) return;
            return err;
        };
    }
}

pub fn handlePriorityUpdateFrame(ctx: *DispatchContext, frame: Frame) !void {
    if (frame.header.stream_id != 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "PRIORITY_UPDATE on non-zero stream");
    }
    if (frame.payload.len < priority_update_payload_id_size + 1) {
        return sendGoawayAndClose(ctx, 0, 0x1, "Invalid PRIORITY_UPDATE payload: PROTOCOL_ERROR");
    }

    const raw_id = std.mem.readInt(u32, frame.payload[0..priority_update_payload_id_size], .big);
    const prioritized_id = raw_id & 0x7FFFFFFF;
    if (prioritized_id == 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "PRIORITY_UPDATE stream ID 0: PROTOCOL_ERROR");
    }
    if ((prioritized_id & 1) == 0) {
        return sendGoawayAndClose(ctx, 0, 0x1, "PRIORITY_UPDATE for push stream: PROTOCOL_ERROR");
    }

    const priority = HttpPriority.parse(
        frame.payload[priority_update_payload_id_size..],
    ) catch {
        return sendGoawayAndClose(ctx, 0, 0x1, "Invalid PRIORITY_UPDATE field value: PROTOCOL_ERROR");
    };

    if (ctx.stream_storage.find(prioritized_id)) |stream| {
        switch (stream.state) {
            .HalfClosedLocal, .Closed => return,
            else => {},
        }
        stream.applyPriority(priority);
        return;
    }

    if (prioritized_id > ctx.last_stream_id.*) {
        try pendingPriorityUpdateStore(ctx, prioritized_id, priority);
    }
}

// -----------------------------------------------------------------------
//  I/O helpers
// -----------------------------------------------------------------------

pub fn sendGoawayAndClose(ctx: *DispatchContext, last_stream_id: u32, error_code: u32, debug_msg: []const u8) !void {
    if (!ctx.goaway_sent.*) {
        try sendGoaway(ctx, last_stream_id, error_code, debug_msg);
        ctx.goaway_sent.* = true;
        try flushOutput(ctx);
    }
}

fn sendRstStream(ctx: *DispatchContext, stream_id: u32, error_code: u32) !void {
    var h = FrameHeader{
        .length = 4,
        .frame_type = FrameType.RST_STREAM,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = stream_id,
    };
    try h.write(ctx.writer);
    var ec: [4]u8 = undefined;
    std.mem.writeInt(u32, ec[0..4], error_code, .big);
    try ctx.writer.writeAll(&ec);
    log.debug("Sent RST_STREAM with error code {d} for stream {d}", .{ error_code, stream_id });
}

fn sendGoaway(ctx: *DispatchContext, last_stream_id: u32, error_code: u32, debug_data: []const u8) !void {
    const debug_max = 96;
    const debug_len = @min(debug_data.len, debug_max);
    const payload_size = 8 + debug_len;
    assert(payload_size > 0);

    var payload: [8 + 96]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], last_stream_id & 0x7FFFFFFF, .big);
    std.mem.writeInt(u32, payload[4..8], error_code, .big);
    if (debug_len > 0) {
        std.mem.copyForwards(u8, payload[8 .. 8 + debug_len], debug_data[0..debug_len]);
    }

    var gf = Frame{
        .header = FrameHeader{
            .length = @intCast(payload_size),
            .frame_type = FrameType.GOAWAY,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = payload[0..payload_size],
    };
    try gf.write(ctx.writer);
    ctx.goaway_sent.* = true;
}

fn sendSettingsAck(ctx: *DispatchContext) !void {
    if (ctx.goaway_sent.*) return;
    var h = FrameHeader{
        .length = 0,
        .frame_type = FrameType.SETTINGS,
        .flags = FrameFlags{ .value = FrameFlags.ACK },
        .reserved = false,
        .stream_id = 0,
    };
    h.write(ctx.writer) catch |err| {
        if (err == error.BrokenPipe) return err;
        return err;
    };
}

fn sendPing(ctx: *DispatchContext, opaque_data: []const u8, ack: bool) !void {
    if (opaque_data.len != 8) return error.InvalidPingPayloadSize;
    var h = FrameHeader{
        .length = 8,
        .frame_type = FrameType.PING,
        .flags = if (ack) FrameFlags{ .value = FrameFlags.ACK } else FrameFlags{ .value = 0 },
        .reserved = false,
        .stream_id = 0,
    };
    try h.write(ctx.writer);
    try ctx.writer.writeAll(opaque_data);
}

fn sendWindowUpdate(ctx: *DispatchContext, stream_id: u32, increment: u32) !void {
    var h = FrameHeader{
        .length = 4,
        .frame_type = FrameType.WINDOW_UPDATE,
        .flags = FrameFlags.init(0),
        .reserved = false,
        .stream_id = stream_id,
    };
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, increment, .big);
    try h.write(ctx.writer);
    try ctx.writer.writeAll(&buf);
}

fn flushOutput(ctx: *DispatchContext) !void {
    if (ctx.writer.buffered().len == 0) return;
    try ctx.writer.flush();
}

fn finishAfterGoaway(ctx: *DispatchContext) !void {
    try flushOutput(ctx);
    var drain_buf: [1024]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 100) : (attempts += 1) {
        const n = ctx.reader.readSliceShort(&drain_buf) catch |err| {
            log.debug("Connection drain completed: {s}", .{@errorName(err)});
            return;
        };
        if (n == 0) return;
    }
}

// -----------------------------------------------------------------------
//  Flow control
// -----------------------------------------------------------------------

fn updateSendWindow(ctx: *DispatchContext, window: *i32, increment: u32) !void {
    const ov = @addWithOverflow(window.*, @as(i32, @intCast(increment)));
    if (ov[0] > 2147483647 or ov[0] < 0) {
        if (!ctx.goaway_sent.*) {
            sendGoaway(ctx, ctx.last_stream_id.*, 0x3, "Flow control window exceeded limits: FLOW_CONTROL_ERROR") catch {};
            ctx.goaway_sent.* = true;
        }
        return error.FlowControlError;
    }
    window.* = ov[0];
}

// -----------------------------------------------------------------------
//  Stream helpers
// -----------------------------------------------------------------------

fn getStream(ctx: *DispatchContext, stream_id: u32) !*StreamInstance {
    if (stream_id % 2 == 0) {
        try sendGoawayAndClose(ctx, 0, 0x1, "Invalid stream ID: PROTOCOL_ERROR");
        return error.ProtocolError;
    }
    if (ctx.stream_storage.find(stream_id)) |stream| return stream;
    if (ctx.stream_storage.activeCount() >= ctx.settings.max_concurrent_streams) {
        return error.MaxConcurrentStreamsExceeded;
    }
    if (stream_id <= ctx.last_stream_id.*) {
        try sendGoawayAndClose(ctx, 0, 0x1, "Stream ID decreased: PROTOCOL_ERROR");
        return error.ProtocolError;
    }
    ctx.last_stream_id.* = stream_id;
    const slot_index = try ctx.stream_storage.allocateSlot(stream_id);
    const stream_slot = ctx.stream_storage.findBySlotIndex(slot_index);
    stream_slot.init(@ptrCast(@alignCast(ctx.conn_ptr)), stream_id);
    if (pendingPriorityUpdateTake(ctx, stream_id)) |priority| {
        stream_slot.applyPriority(priority);
    }
    stream_slot.send_window_size = @intCast(ctx.settings.initial_window_size);
    stream_slot.initial_window_size = ctx.settings.initial_window_size;
    return stream_slot;
}

fn queueStreamIfReady(ctx: *DispatchContext, stream: *StreamInstance) !void {
    if (stream.state != .HalfClosedRemote) return;
    if (!stream.request_complete) return;
    if (!stream.request_headers_complete) return;
    if (stream.expecting_continuation) return;
    if (resp.streamResponseComplete(stream)) return;

    const stream_index = ctx.stream_storage.findIndex(stream.id) orelse unreachable;
    try pendingStreamPush(ctx, stream_index);
}

fn pendingStreamPush(ctx: *DispatchContext, stream_index: u8) !void {
    assert(stream_index < max_streams_per_connection);
    if (ctx.pending_stream_queued[stream_index]) return;
    if (ctx.pending_stream_count.* >= max_streams_per_connection) {
        return error.PendingStreamQueueFull;
    }
    ctx.pending_stream_slots[ctx.pending_stream_count.*] = stream_index;
    ctx.pending_stream_queued[stream_index] = true;
    ctx.pending_stream_count.* += 1;
}

// -----------------------------------------------------------------------
//  Pending priority updates
// -----------------------------------------------------------------------

fn pendingPriorityUpdateStore(ctx: *DispatchContext, stream_id: u32, priority: HttpPriority) !void {
    assert(stream_id > 0);
    var pi: u8 = 0;
    while (pi < max_streams_per_connection) : (pi += 1) {
        if (ctx.pending_priority_updates[pi].in_use) {
            if (ctx.pending_priority_updates[pi].stream_id == stream_id) {
                ctx.pending_priority_updates[pi].priority = priority;
                return;
            }
            continue;
        }
        ctx.pending_priority_updates[pi] = .{
            .stream_id = stream_id,
            .priority = priority,
            .in_use = true,
        };
        return;
    }
    return error.PendingPriorityUpdateBufferFull;
}

fn pendingPriorityUpdateTake(ctx: *DispatchContext, stream_id: u32) ?HttpPriority {
    assert(stream_id > 0);
    var pi: u8 = 0;
    while (pi < max_streams_per_connection) : (pi += 1) {
        if (!ctx.pending_priority_updates[pi].in_use) continue;
        if (ctx.pending_priority_updates[pi].stream_id != stream_id) continue;
        const priority = ctx.pending_priority_updates[pi].priority;
        ctx.pending_priority_updates[pi] = .{};
        return priority;
    }
    return null;
}

// -----------------------------------------------------------------------
//  Priority frame helpers
// -----------------------------------------------------------------------

fn priorityFramePayloadValidSize(frame: Frame) bool {
    assert(frame.header.frame_type == FrameType.PRIORITY);
    assert(frame.header.length == frame.payload.len);
    return frame.payload.len == priority_frame_payload_size;
}

fn sendPriorityFrameSizeError(ctx: *DispatchContext) !void {
    try sendGoawayAndClose(ctx, 0, 0x6, "Frame size error: FRAME_SIZE_ERROR");
}

// -----------------------------------------------------------------------
//  SETTINGS frame handling
// -----------------------------------------------------------------------

fn applyFrameSettings(ctx: *DispatchContext, frame: Frame) !void {
    assert(frame.header.frame_type == FrameType.SETTINGS);
    assert(frame.header.stream_id == 0);
    if (frame.header.stream_id != 0) {
        if (!ctx.goaway_sent.*) {
            try sendGoawayAndClose(ctx, 0, 0x1, "SETTINGS on non-zero stream: PROTOCOL_ERROR");
        }
        return;
    }
    if ((frame.header.flags.value & FrameFlags.ACK) != 0) {
        if (frame.payload.len != 0) {
            if (!ctx.goaway_sent.*) {
                try sendGoawayAndClose(ctx, 0, 0x6, "SETTINGS ACK with payload: FRAME_SIZE_ERROR");
            }
        }
        return;
    }
    if (frame.payload.len % 6 != 0) {
        if (!ctx.goaway_sent.*) {
            try sendGoawayAndClose(ctx, 0, 0x6, "Invalid SETTINGS frame size: FRAME_SIZE_ERROR");
        }
        return;
    }

    const buffer = frame.payload;
    const buffer_len: u32 = @intCast(buffer.len);
    var index: u32 = 0;
    var no_rfc7540: ?bool = null;

    while (index + 6 <= buffer_len) {
        const setting_id = std.mem.readInt(u16, buffer[index..][0..2], .big);
        const setting_value = std.mem.readInt(u32, buffer[index + 2 ..][0..4], .big);

        if (setting_id == settings_no_rfc7540_priorities_id) {
            if (setting_value == 0) {
                no_rfc7540 = false;
            } else if (setting_value == 1) {
                no_rfc7540 = true;
            } else {
                if (!ctx.goaway_sent.*) {
                    try sendGoawayAndClose(ctx, 0, 0x1, "Invalid SETTINGS_NO_RFC7540_PRIORITIES value: PROTOCOL_ERROR");
                }
                return error.ProtocolError;
            }
        } else {
            applySetting(ctx, setting_id, setting_value) catch |err| {
                if (err == error.ProtocolError) return err;
            };
        }
        index += 6;
    }

    if (!ctx.peer_first_settings_received.*) {
        if (no_rfc7540) |val| {
            ctx.peer_no_rfc7540_priorities.* = val;
            ctx.peer_no_rfc7540_priorities_setting_received.* = true;
        }
    }
    ctx.peer_first_settings_received.* = true;
}

fn applySetting(ctx: *DispatchContext, id: u16, value: u32) !void {
    switch (id) {
        1 => {
            ctx.settings.header_table_size = value;
            ctx.hpack_encoder_table.setMaxAllowedSize(value);
        },
        2 => {
            if (value != 0 and value != 1) {
                if (!ctx.goaway_sent.*) {
                    try sendGoawayAndClose(ctx, 0, 0x1, "Invalid SETTINGS_ENABLE_PUSH: PROTOCOL_ERROR");
                }
                return;
            }
            ctx.settings.enable_push = value == 1;
        },
        3 => ctx.settings.max_concurrent_streams = value,
        4 => {
            if (value > 2147483647) {
                if (!ctx.goaway_sent.*) {
                    try sendGoawayAndClose(ctx, 0, 0x3, "SETTINGS_INITIAL_WINDOW_SIZE too large: FLOW_CONTROL_ERROR");
                }
                return;
            }
            const old = ctx.settings.initial_window_size;
            ctx.settings.initial_window_size = value;
            const delta: i32 = @as(i32, @intCast(value)) - @as(i32, @intCast(old));
            try updateStreamWindows(ctx, delta);
        },
        5 => {
            if (value < 16384 or value > 16777215) {
                if (!ctx.goaway_sent.*) {
                    try sendGoawayAndClose(ctx, 0, 0x1, "Invalid SETTINGS_MAX_FRAME_SIZE: PROTOCOL_ERROR");
                }
                return;
            }
            ctx.settings.max_frame_size = value;
        },
        6 => ctx.settings.max_header_list_size = value,
        else => {},
    }
}

fn updateStreamWindows(ctx: *DispatchContext, delta: i32) !void {
    var index: u8 = 0;
    while (index < max_streams_per_connection) : (index += 1) {
        if (!ctx.stream_storage.isInUse(index)) continue;
        const stream = ctx.stream_storage.findBySlotIndex(index);
        const new_window: i64 = @as(i64, stream.send_window_size) + @as(i64, delta);
        if (new_window < std.math.minInt(i32) or new_window > std.math.maxInt(i32)) {
            if (!ctx.goaway_sent.*) {
                try sendGoawayAndClose(ctx, 0, 0x3, "Stream window overflow: FLOW_CONTROL_ERROR");
            }
            return;
        }
        stream.send_window_size = @intCast(new_window);
        stream.initial_window_size = ctx.settings.initial_window_size;
    }
}
