const std = @import("std");
pub const Stream = @import("stream.zig").Stream;
pub const DefaultStream = @import("stream.zig").DefaultStream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const FrameType = @import("frame.zig").FrameType;
const SIMDFrameParser = @import("simd_frame_parser.zig").SIMDFrameParser;
pub const Hpack = @import("hpack.zig").Hpack;
const handler = @import("handler.zig");
const resp = @import("response.zig");
pub const http2 = @import("http2.zig");
const HttpPriority = @import("http_priority.zig").Priority;
const memory_budget = @import("memory_budget.zig");
const TestIo = @import("testing/fixed_io.zig").FixedIo;
const path = @import("path.zig");
const stream_storage_module = @import("stream_storage.zig");
const fh = @import("frame_handler.zig");
const Settings = fh.Settings;
const DispatchContext = fh.DispatchContext;
const max_streams_per_connection = memory_budget.MemBudget.max_streams_per_connection;
const max_frame_size_default = http2.max_frame_size_default;
const log = std.log.scoped(.connection);

const assert = std.debug.assert;
const http2_preface: []const u8 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const priority_frame_payload_size: usize = 5;
const priority_update_frame_type: u8 = 0x10;
const priority_update_payload_id_size: usize = 4;
const settings_no_rfc7540_priorities_id: u16 = 0x9;
const http2_frame_size_min: usize = 16 * 1024;
const default_response_body =
    \\<!DOCTYPE html>
    \\<html>
    \\<body>
    \\<h1>Hello, World!</h1>
    \\</body>
    \\</html>
;
const default_response_content_type = "text/html; charset=utf-8";
comptime {
    assert(max_streams_per_connection == 100);
    assert(max_streams_per_connection <= std.math.maxInt(u8));
    assert(priority_frame_payload_size == 5);
    assert(priority_update_frame_type == @intFromEnum(FrameType.PRIORITY_UPDATE));
    assert(priority_update_payload_id_size == 4);
    assert(settings_no_rfc7540_priorities_id == 0x9);
    assert(default_response_body.len == 68);
    assert(default_response_body.len <= http2_frame_size_min);
    assert(default_response_content_type.len == 24);
}

const RequestTarget = @import("path.zig").RequestTarget;
pub const Connection = struct {
    pub const StreamStorage = @import("stream_storage.zig").StreamStorage;
    pub const PendingPriorityUpdate = fh.ConnectionPendingPriorityUpdate;

    allocator: std.mem.Allocator,
    request_dispatcher: ?handler.RequestDispatcher,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    settings: Settings,
    recv_window_size: i32 = 65535,
    send_window_size: i32 = 65535,
    stream_storage: *StreamStorage,
    owned_stream_storage: ?*StreamStorage = null,
    pending_stream_slots: [max_streams_per_connection]u8,
    pending_stream_queued: [max_streams_per_connection]bool,
    pending_stream_count: u8 = 0,
    pending_priority_updates: [max_streams_per_connection]PendingPriorityUpdate,
    completed_responses_pending: u32 = 0,
    // HPACK keeps independent dynamic tables per direction.
    hpack_decoder_table: Hpack.DynamicTable,
    hpack_encoder_table: Hpack.DynamicTable,
    goaway_sent: bool = false,
    goaway_received: bool = false,
    expecting_continuation_stream_id: ?u32 = null,
    last_stream_id: u32 = 0,
    client_settings_received: bool = false,
    peer_first_settings_received: bool = false,
    peer_no_rfc7540_priorities: bool = false,
    peer_no_rfc7540_priorities_setting_received: bool = false,
    schedule_epoch_next: u64 = 1,
    connection_closed: bool = false,

    fn initBase(
        target: *@This(),
        stream_storage_ptr: *StreamStorage,
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    ) void {
        stream_storage_ptr.init();

        target.* = .{
            .allocator = allocator,
            .request_dispatcher = null,
            .reader = reader,
            .writer = writer,
            .settings = Settings.default(),
            .recv_window_size = 65535,
            .send_window_size = 65535,
            .stream_storage = stream_storage_ptr,
            .owned_stream_storage = null,
            .pending_stream_slots = undefined,
            .pending_stream_queued = [_]bool{false} ** max_streams_per_connection,
            .pending_stream_count = 0,
            .pending_priority_updates = [_]PendingPriorityUpdate{.{}} ** max_streams_per_connection,
            .completed_responses_pending = 0,
            .hpack_decoder_table = Hpack.DynamicTable.init(allocator, 4096),
            .hpack_encoder_table = Hpack.DynamicTable.init(allocator, 4096),
            .peer_first_settings_received = false,
            .peer_no_rfc7540_priorities = false,
            .peer_no_rfc7540_priorities_setting_received = false,
            .schedule_epoch_next = 1,
        };

        assert(target.stream_storage.slots.len == max_streams_per_connection);
        assert(target.stream_storage.ids.len == max_streams_per_connection);
        assert(target.stream_storage.in_use.len == max_streams_per_connection);
        assert(target.stream_storage.lookup_ids.len == 256);
        assert(target.stream_storage.lookup_indices.len == 256);
    }

    fn initDispatchContext(target: *@This()) DispatchContext {
        return .{
            .allocator = target.allocator,
            .reader = target.reader,
            .writer = target.writer,
            .stream_storage = target.stream_storage,
            .settings = &target.settings,
            .hpack_decoder_table = &target.hpack_decoder_table,
            .hpack_encoder_table = &target.hpack_encoder_table,
            .recv_window_size = &target.recv_window_size,
            .send_window_size = &target.send_window_size,
            .goaway_sent = &target.goaway_sent,
            .goaway_received = &target.goaway_received,
            .last_stream_id = &target.last_stream_id,
            .expecting_continuation_stream_id = &target.expecting_continuation_stream_id,
            .client_settings_received = &target.client_settings_received,
            .peer_first_settings_received = &target.peer_first_settings_received,
            .peer_no_rfc7540_priorities = &target.peer_no_rfc7540_priorities,
            .peer_no_rfc7540_priorities_setting_received = &target.peer_no_rfc7540_priorities_setting_received,
            .pending_stream_slots = &target.pending_stream_slots,
            .pending_stream_queued = &target.pending_stream_queued,
            .pending_stream_count = &target.pending_stream_count,
            .pending_priority_updates = &target.pending_priority_updates,
            .schedule_epoch_next = &target.schedule_epoch_next,
            .completed_responses_pending = &target.completed_responses_pending,
            .connection_closed = &target.connection_closed,
            .conn_ptr = target,
        };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        comptime is_server: bool,
    ) !@This() {
        var self: @This() = undefined;
        const stream_storage = try allocator.create(StreamStorage);
        errdefer allocator.destroy(stream_storage);

        initBase(&self, stream_storage, allocator, reader, writer);
        self.owned_stream_storage = stream_storage;
        if (is_server) {
            try self.check_server_preface();
        } else {
            try self.send_preface();
        }
        try self.send_settings();
        try self.flush_output();
        return self;
    }

    pub fn initServerEventDrivenInPlace(
        target: *@This(),
        stream_storage: *StreamStorage,
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    ) !void {
        initBase(target, stream_storage, allocator, reader, writer);
        try target.send_settings();
        try target.flush_output();
    }

    pub fn initServerInPlace(
        target: *@This(),
        stream_storage: *StreamStorage,
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    ) !void {
        initBase(target, stream_storage, allocator, reader, writer);
        errdefer target.flush_output() catch {};
        try target.check_server_preface();
        try target.send_settings();
        try target.flush_output();
    }

    pub fn bindRequestDispatcher(
        self: *@This(),
        request_dispatcher: handler.RequestDispatcher,
    ) void {
        self.request_dispatcher = request_dispatcher;
    }

    fn flush_output(self: *@This()) !void {
        if (self.writer.buffered().len == 0) {
            return;
        }

        try self.writer.flush();
    }

    fn check_server_preface(self: *@This()) !void {
        const preface_len = http2_preface.len;
        var preface_buf: [preface_len]u8 = undefined;
        var bytes_read: usize = 0;
        while (bytes_read < preface_len) {
            const read_result = try self.reader.readSliceShort(preface_buf[bytes_read..]);
            if (read_result == 0) {
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                } else {
                    // Partial preface - might be protocol mismatch or slow client
                    log.err("Partial HTTP/2 preface received ({} of {} bytes). Expected: {any}, Got: {any}", .{ bytes_read, preface_len, http2_preface, preface_buf[0..bytes_read] });
                    try self.send_goaway(0, 0x1, "Incomplete preface: PROTOCOL_ERROR");
                    return error.InvalidPreface;
                }
            }
            bytes_read += read_result;
        }
        if (!SIMDFrameParser.validate_preface_simd(&preface_buf)) {
            log.err("Invalid preface received. Expected: {any}, Got: {any}", .{ http2_preface, preface_buf });
            try self.send_goaway(0, 0x1, "Invalid preface: PROTOCOL_ERROR");
            return error.InvalidPreface;
        }
        log.debug("Valid HTTP/2 preface received", .{});
    }
    pub fn deinit(self: *@This()) void {
        self.connection_closed = true;

        for (&self.stream_storage.slots, 0..) |*stream_slot, stream_index| {
            if (!self.stream_storage.in_use[stream_index]) continue;
            stream_slot.deinit();
            self.stream_storage.ids[stream_index] = 0;
            self.stream_storage.in_use[stream_index] = false;
        }
        self.stream_storage.in_use_count = 0;
        self.stream_storage.reset();
        self.pending_stream_count = 0;
        self.pending_stream_queued = [_]bool{false} ** max_streams_per_connection;
        self.completed_responses_pending = 0;
        self.hpack_decoder_table.deinit();
        self.hpack_encoder_table.deinit();
        if (self.owned_stream_storage) |owned| {
            self.allocator.destroy(owned);
            self.owned_stream_storage = null;
        }
        log.debug("Resources deinitialized for connection\n", .{});
    }

    /// Mark a stream as closed.
    /// The stream slot is released by the connection hot path after the frame or response completes.
    pub fn mark_stream_closed(self: *@This(), stream_id: u32) !void {
        assert(stream_id > 0);
        _ = self;
        log.debug("Marked stream {d} as closed\n", .{stream_id});
    }

    fn active_stream_count(self: *@This()) u32 {
        return self.stream_storage.activeCount();
    }

    fn send_preface(self: *const @This()) !void {
        try self.writer.writeAll(http2_preface);
    }

    pub fn highest_stream_id(self: *const @This()) u32 {
        return self.last_stream_id;
    }

    // O(1) average lookup via the open-addressed hash table in StreamStorage.
    fn streamFindIndex(self: *const @This(), stream_id: u32) ?u8 {
        return self.stream_storage.findIndex(stream_id);
    }

    fn streamFind(self: *@This(), stream_id: u32) ?*DefaultStream.StreamInstance {
        return self.stream_storage.find(stream_id);
    }

    pub fn rfc7540_priority_signals_ignored(self: *const @This()) bool {
        if (self.settings.no_rfc7540_priorities) {
            return true;
        }
        if (self.peer_no_rfc7540_priorities) {
            return true;
        }
        return false;
    }

    fn pending_priority_update_count(self: *const @This()) u32 {
        var update_count: u32 = 0;

        for (self.pending_priority_updates) |pending_update| {
            if (!pending_update.in_use) {
                continue;
            }
            update_count += 1;
        }

        return update_count;
    }

    fn pending_priority_update_find_index(self: *const @This(), stream_id: u32) ?u8 {
        assert(stream_id > 0);

        for (self.pending_priority_updates, 0..) |pending_update, pending_index| {
            if (!pending_update.in_use) {
                continue;
            }
            if (pending_update.stream_id != stream_id) {
                continue;
            }
            return @intCast(pending_index);
        }

        return null;
    }

    fn pending_priority_update_take(self: *@This(), stream_id: u32) ?HttpPriority {
        const pending_index = self.pending_priority_update_find_index(stream_id) orelse return null;
        const pending_priority = self.pending_priority_updates[pending_index].priority;

        self.pending_priority_updates[pending_index] = .{};
        return pending_priority;
    }

    fn pending_priority_update_store(
        self: *@This(),
        stream_id: u32,
        priority: HttpPriority,
    ) !void {
        assert(stream_id > 0);

        if (self.pending_priority_update_find_index(stream_id)) |pending_index| {
            self.pending_priority_updates[pending_index].priority = priority;
            return;
        }

        const prioritized_streams = self.active_stream_count() + self.pending_priority_update_count();
        if (prioritized_streams >= self.settings.max_concurrent_streams) {
            try self.sendGoawayAndClose(
                0x1,
                "Too many prioritized idle streams: PROTOCOL_ERROR",
            );
            return error.ProtocolError;
        }

        for (&self.pending_priority_updates) |*pending_update| {
            if (pending_update.in_use) {
                continue;
            }

            pending_update.* = .{
                .stream_id = stream_id,
                .priority = priority,
                .in_use = true,
            };
            return;
        }

        return error.PendingPriorityUpdateBufferFull;
    }

    fn stream_has_higher_precedence(
        self: *const @This(),
        candidate_index: u8,
        current_index: u8,
    ) bool {
        const candidate_stream = &self.stream_storage.slots[candidate_index];
        const current_stream = &self.stream_storage.slots[current_index];

        if (candidate_stream.priority.urgency < current_stream.priority.urgency) {
            return true;
        }
        if (candidate_stream.priority.urgency > current_stream.priority.urgency) {
            return false;
        }

        const candidate_round_robin = stream_in_round_robin_phase(candidate_stream);
        const current_round_robin = stream_in_round_robin_phase(current_stream);
        if (candidate_round_robin != current_round_robin) {
            return !candidate_round_robin;
        }

        if (!candidate_round_robin) {
            return candidate_stream.id < current_stream.id;
        }

        if (candidate_stream.schedule_epoch_last < current_stream.schedule_epoch_last) {
            return true;
        }
        if (candidate_stream.schedule_epoch_last > current_stream.schedule_epoch_last) {
            return false;
        }

        return candidate_stream.id < current_stream.id;
    }

    fn stream_in_round_robin_phase(
        stream: *const DefaultStream.StreamInstance,
    ) bool {
        if (!stream.priority.incremental) {
            return false;
        }
        return stream.schedule_count > 0;
    }

    fn pendingStreamPush(self: *@This(), stream_index: u8) !void {
        assert(stream_index < max_streams_per_connection);

        if (self.pending_stream_queued[stream_index]) {
            return;
        }

        if (self.pending_stream_count >= max_streams_per_connection) {
            return error.PendingStreamQueueFull;
        }

        const pending_index: usize = self.pending_stream_count;
        self.pending_stream_slots[pending_index] = stream_index;
        self.pending_stream_queued[stream_index] = true;
        self.pending_stream_count += 1;
    }

    fn pendingStreamPop(self: *@This()) ?u8 {
        if (self.pending_stream_count == 0) {
            return null;
        }

        var pending_index_best: u8 = 0;
        var pending_index: u8 = 1;
        while (pending_index < self.pending_stream_count) : (pending_index += 1) {
            const candidate_index = self.pending_stream_slots[pending_index];
            const current_index = self.pending_stream_slots[pending_index_best];
            if (self.stream_has_higher_precedence(candidate_index, current_index)) {
                pending_index_best = pending_index;
            }
        }

        const stream_index = self.pending_stream_slots[pending_index_best];
        self.pending_stream_queued[stream_index] = false;

        pending_index = pending_index_best + 1;
        while (pending_index < self.pending_stream_count) : (pending_index += 1) {
            self.pending_stream_slots[pending_index - 1] = self.pending_stream_slots[pending_index];
        }
        self.pending_stream_count -= 1;
        assert(self.stream_storage.slots[stream_index].schedule_count < std.math.maxInt(u32));
        self.stream_storage.slots[stream_index].schedule_count += 1;
        self.stream_storage.slots[stream_index].schedule_epoch_last = self.schedule_epoch_next;
        self.schedule_epoch_next += 1;
        return stream_index;
    }

    fn pendingStreamRemove(self: *@This(), stream_index: u8) void {
        assert(stream_index < max_streams_per_connection);

        if (!self.pending_stream_queued[stream_index]) {
            return;
        }

        var pending_index: u8 = 0;
        while (pending_index < self.pending_stream_count) : (pending_index += 1) {
            if (self.pending_stream_slots[pending_index] != stream_index) continue;

            var shift_index = pending_index + 1;
            while (shift_index < self.pending_stream_count) : (shift_index += 1) {
                self.pending_stream_slots[shift_index - 1] = self.pending_stream_slots[shift_index];
            }

            self.pending_stream_count -= 1;
            self.pending_stream_queued[stream_index] = false;
            return;
        }

        unreachable;
    }

    fn releaseClosedStream(self: *@This(), stream_index: u8) void {
        const stream = self.stream_storage.findBySlotIndex(stream_index);
        const stream_id = stream.id;

        self.pendingStreamRemove(stream_index);
        stream.deinit();
        self.stream_storage.releaseSlot(stream_index);
        log.debug("Released closed stream {d}\n", .{stream_id});
    }

    fn queueStreamIfReady(self: *@This(), stream: *DefaultStream.StreamInstance) !void {
        if (stream.state != .HalfClosedRemote) {
            return;
        }
        if (!stream.request_complete) {
            return;
        }
        if (!stream.request_headers_complete) {
            return;
        }
        if (stream.expecting_continuation) {
            return;
        }
        if (resp.streamResponseComplete(stream)) {
            return;
        }

        const stream_index = self.streamFindIndex(stream.id) orelse unreachable;
        try self.pendingStreamPush(stream_index);
    }

    pub fn takeCompletedResponses(self: *@This()) u32 {
        const completed_responses = self.completed_responses_pending;
        self.completed_responses_pending = 0;
        return completed_responses;
    }

    fn streamAllocate(self: *@This(), stream_id: u32) !*DefaultStream.StreamInstance {
        const slot_index = try self.stream_storage.allocateSlot(stream_id);
        const stream_slot = self.stream_storage.findBySlotIndex(slot_index);
        stream_slot.init(self, stream_id);
        if (self.pending_priority_update_take(stream_id)) |priority| {
            stream_slot.applyPriority(priority);
        }
        return stream_slot;
    }
    /// Sends a RST_STREAM frame for a given stream ID with the specified error code.
    pub fn send_rst_stream(self: *@This(), stream_id: u32, error_code: u32) !void {
        var frame_header = FrameHeader{
            .length = 4,
            .frame_type = FrameType.RST_STREAM, // 3 for RST_STREAM
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = stream_id, // The stream ID for which to send RST_STREAM
        };
        // Write the frame header
        try frame_header.write(self.writer);
        // Write the error code as a 4-byte big-endian integer
        var error_code_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, error_code_bytes[0..4], error_code, .big);
        try self.writer.writeAll(&error_code_bytes);
        log.debug("Sent RST_STREAM frame with error code {d} for stream ID {d}\n", .{ error_code, stream_id });
    }

    pub fn receiveFrameStatic(self: *@This(), buffer: []u8) !Frame {
        if (buffer.len < 9) return error.BufferTooSmall;

        const header_bytes = self.reader.peek(9) catch |err| switch (err) {
            error.EndOfStream => return error.UnexpectedEOF,
            error.ReadFailed => return error.ReadFailed,
        };

        const parsed = SIMDFrameParser.parseFrameHeaderLenient(header_bytes) catch |err| {
            switch (err) {
                error.InvalidFrameLength => {
                    log.err("Invalid frame length detected, sending GOAWAY", .{});
                    try self.send_goaway(0, 0x6, "Frame size error: FRAME_SIZE_ERROR");
                    try self.flush_output();
                    return error.FrameSizeError;
                },
                error.InsufficientData => return error.BufferTooSmall,
            }
        };

        if (parsed.length > self.settings.max_frame_size) {
            log.err("Received frame size {} exceeds SETTINGS_MAX_FRAME_SIZE {}, sending GOAWAY", .{ parsed.length, self.settings.max_frame_size });
            try self.send_goaway(self.last_stream_id, 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
            self.goaway_sent = true;
            try self.finishAfterGoaway();
            return error.FrameSizeError;
        }

        const frame_size = parsed.length + 9;
        if (frame_size > buffer.len) return error.BufferTooSmall;

        // Take the entire frame from the per-connection reader buffer. The
        // first `peek(9)` fills that buffer with as much data as the transport
        // has ready, so pipelined frames are parsed from memory until the
        // buffer drains instead of issuing one read for every 9-byte header and
        // again for every payload.
        const payload = if (frame_size <= self.reader.buffer.len) payload: {
            const frame_bytes = self.reader.take(frame_size) catch |err| switch (err) {
                error.EndOfStream => return error.UnexpectedEOF,
                error.ReadFailed => return error.ReadFailed,
            };
            break :payload if (parsed.length > 0) frame_bytes[9..frame_size] else &[_]u8{};
        } else payload: {
            self.reader.toss(9);
            const payload_buffer = buffer[9..frame_size];
            self.reader.readSliceAll(payload_buffer) catch |err| switch (err) {
                error.EndOfStream => return error.UnexpectedEOF,
                error.ReadFailed => return error.ReadFailed,
            };
            break :payload payload_buffer;
        };

        const frame_type = FrameType.fromU8(parsed.frame_type) orelse {
            log.debug("Received unknown frame type {} on stream {}, ignoring per RFC 9113", .{ parsed.frame_type, parsed.stream_id });
            // Unknown frame types must be ignored per RFC 9113
            // Return without processing - we've already consumed the frame payload
            return Frame{
                .header = FrameHeader{
                    .length = 0,
                    .frame_type = FrameType.DATA, // Use a valid frame type but we'll ignore it
                    .flags = FrameFlags.init(0),
                    .reserved = false,
                    .stream_id = 0, // Connection-level frame that will be ignored
                },
                .payload = &[_]u8{},
            };
        };

        return Frame{
            .header = FrameHeader{
                .length = parsed.length,
                .frame_type = frame_type,
                .flags = parsed.flags,
                .reserved = parsed.reserved,
                .stream_id = parsed.stream_id,
            },
            .payload = payload,
        };
    }

    pub fn dispatchFrameOptimized(self: *@This(), frame: Frame) !void {
        var ctx = initDispatchContext(self);
        return fh.dispatchFrameOptimized(&ctx, frame);
    }

    fn sendGoawayAndClose(self: *@This(), error_code: u32, debug_msg: []const u8) !void {
        var ctx = initDispatchContext(self);
        return fh.sendGoawayAndClose(&ctx, self.last_stream_id, error_code, debug_msg);
    }

    fn handle_priority_update_frame(self: *@This(), frame: Frame) !void {
        var ctx = initDispatchContext(self);
        return fh.handlePriorityUpdateFrame(&ctx, frame);
    }

    pub fn handle_connection_optimized(self: *@This()) !void {
        var frame_buffer: [64 * 1024]u8 = undefined;

        while (!self.client_settings_received) {
            const frame = self.receiveFrameStatic(&frame_buffer) catch |err| {
                self.handle_receive_frame_error(err) catch |handle_err| {
                    try self.flush_output();
                    return handle_err;
                };
                try self.flush_output();
                return;
            };

            self.dispatchFrameOptimized(frame) catch |err| {
                if (self.goaway_sent) {
                    try self.finishAfterGoaway();
                    return;
                }
                try self.flush_output();
                return err;
            };
            try self.flush_ready_streams();
            try self.flush_output_if_idle_or_full();
            if (frame.header.frame_type == FrameType.SETTINGS) {
                if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                    self.client_settings_received = true;
                }
            }
        }

        while (!self.goaway_sent) {
            if (self.connection_closed) {
                break;
            }
            const frame = self.receiveFrameStatic(&frame_buffer) catch |err| switch (err) {
                error.BufferTooSmall => {
                    log.err("Frame too large for static buffer, connection corrupted", .{});
                    try self.send_goaway(0, 0x2, "Frame size exceeds buffer: INTERNAL_ERROR");
                    try self.flush_output();
                    break;
                },
                error.UnexpectedEOF => {
                    log.debug("Connection read error: UnexpectedEOF", .{});
                    break;
                },
                error.FrameSizeError => {
                    try self.flush_output();
                    break;
                },
                else => {
                    log.debug("Connection read error: {s}", .{@errorName(err)});
                    break;
                },
            };

            if (self.expecting_continuation_stream_id) |stream_id| {
                if (frame.header.stream_id != stream_id or frame.header.frame_type != FrameType.CONTINUATION) {
                    log.err("Received frame type {d} on stream {d} while expecting CONTINUATION frame on stream {d}: PROTOCOL_ERROR", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id, stream_id });
                    try self.send_goaway(self.highest_stream_id(), 0x1, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                    self.goaway_sent = true;
                    try self.finishAfterGoaway();
                    return error.ProtocolError;
                }
            }

            self.dispatchFrameOptimized(frame) catch |err| {
                if (self.goaway_sent) {
                    try self.finishAfterGoaway();
                    return;
                }
                try self.flush_output();
                return err;
            };
            try self.flush_ready_streams();

            // Coalesce TLS writes across pipelined requests. With h2load
            // -m 100 the read buffer typically holds several complete frames
            // when we get here; flushing per-frame turns each response into
            // a separate SSL_write/TLS record (~22 bytes overhead each).
            // Hold the flush until the read side drains *or* the writer is
            // ~half full, then a single flush emits one TLS record covering
            // multiple HEADERS+DATA frames.
            try self.flush_output_if_idle_or_full();

            if (self.goaway_sent) {
                if (self.goaway_received) {
                    log.debug("Both GOAWAY sent and received, gracefully closing connection.", .{});
                    break;
                }
            }
        }
        try self.flush_output();
        log.debug("SIMD-optimized connection handler terminated gracefully.", .{});
    }

    /// Flush only when there is no point holding the bytes back any longer:
    /// either the inbound side has nothing buffered (so the next read will
    /// block on the network and the peer is waiting for our reply), or the
    /// writer has accumulated enough output that further coalescing wouldn't
    /// fit in a single TLS record anyway.
    const flush_coalesce_threshold: usize = 8 * 1024;

    fn flush_output_if_idle_or_full(self: *@This()) !void {
        const buffered_out = self.writer.buffered().len;
        if (buffered_out == 0) return;
        if (self.reader.bufferedLen() == 0 or buffered_out >= flush_coalesce_threshold) {
            try self.flush_output();
        }
    }

    fn finishAfterGoaway(self: *@This()) !void {
        try self.flush_output();
        try self.drain_connection();
    }

    fn drain_connection(self: *@This()) !void {
        var drain_buffer: [1024]u8 = undefined;
        var drain_attempts: u32 = 0;
        const max_drain_attempts = 100;

        while (drain_attempts < max_drain_attempts) : (drain_attempts += 1) {
            const bytes_read = self.reader.readSliceShort(&drain_buffer) catch |err| {
                log.debug("Connection drain completed: {s}", .{@errorName(err)});
                return;
            };
            if (bytes_read == 0) {
                return;
            }
        }
        log.debug("Connection drain completed after {} attempts", .{drain_attempts});
    }

    /// Adjust frame handling and validation per RFC 9113.
    pub fn handle_connection(self: *@This()) !void {
        // Use optimized connection handler with SIMD frame parsing
        return self.handle_connection_optimized();
    }

    /// Handle a single parsed frame from an event loop without pulling from `reader`.
    /// Mirrors the per-frame logic in `handle_connection_optimized` so simulators and
    /// the production path exercise the same dispatch code.
    pub fn handleFrameEventDriven(self: *@This(), frame: Frame) !void {
        // Validate CONTINUATION expectations before dispatch, matching the
        // per-frame guard in `handle_connection_optimized`.
        if (self.expecting_continuation_stream_id) |stream_id| {
            if (frame.header.stream_id != stream_id or
                frame.header.frame_type != FrameType.CONTINUATION)
            {
                log.err("Received frame type {d} on stream {d} while expecting CONTINUATION frame on stream {d}: PROTOCOL_ERROR", .{
                    @intFromEnum(frame.header.frame_type),
                    frame.header.stream_id,
                    stream_id,
                });
                try self.send_goaway(
                    self.highest_stream_id(),
                    0x1,
                    "Expected CONTINUATION frame: PROTOCOL_ERROR",
                );
                self.goaway_sent = true;
                try self.finishAfterGoaway();
                return error.ProtocolError;
            }
        }

        self.dispatchFrameOptimized(frame) catch |err| {
            if (self.goaway_sent) {
                try self.finishAfterGoaway();
                return;
            }
            try self.flush_output();
            return err;
        };
        try self.flush_ready_streams();
        try self.flush_output_if_idle_or_full();

        if (frame.header.frame_type == FrameType.SETTINGS) {
            if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                self.client_settings_received = true;
            }
        }

        if (self.goaway_sent and self.goaway_received) {
            self.connection_closed = true;
        }
    }
    pub fn flush_ready_streams(self: *@This()) !void {
        if (self.goaway_sent) {
            return;
        }

        // One flush pass gives every queued stream a turn. The canned response
        // fits within a single DATA frame, so a later WINDOW_UPDATE is the only
        // thing that can make a blocked stream advance further.
        const pending_stream_count = self.pending_stream_count;
        var requeue_streams: [max_streams_per_connection]u8 = undefined;
        var requeue_stream_count: u8 = 0;
        var pending_index: u32 = 0;

        while (pending_index < pending_stream_count) : (pending_index += 1) {
            const stream_index = self.pendingStreamPop() orelse break;
            if (try self.flush_ready_stream(stream_index)) {
                assert(requeue_stream_count < max_streams_per_connection);
                requeue_streams[requeue_stream_count] = stream_index;
                requeue_stream_count += 1;
            }
        }

        var requeue_index: u8 = 0;
        while (requeue_index < requeue_stream_count) : (requeue_index += 1) {
            try self.pendingStreamPush(requeue_streams[requeue_index]);
        }
    }

    fn flush_ready_stream(self: *@This(), stream_index: u8) !bool {
        if (!self.stream_storage.in_use[stream_index]) {
            return false;
        }

        const stream = &self.stream_storage.slots[stream_index];
        try self.process_request(stream);

        if (stream.state == .Closed) {
            self.releaseClosedStream(stream_index);
            return false;
        }

        if (!resp.streamResponseComplete(stream)) {
            return true;
        }

        return false;
    }

    fn handle_goaway_frame(self: *@This(), frame: Frame) !void {
        if (frame.payload.len < 8) {
            log.debug("Invalid GOAWAY frame size, expected at least 8 bytes.\n", .{});
            try self.send_goaway(self.last_stream_id, 0x1, "Invalid GOAWAY frame: PROTOCOL_ERROR");
            return error.ProtocolError;
        }
        // Extract the last_stream_id and error_code
        const last_stream_id = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFFFFFF;
        const error_code = std.mem.readInt(u32, frame.payload[4..8], .big);
        log.debug("Received GOAWAY with last_stream_id={d}, error_code={d}\n", .{ last_stream_id, error_code });
        // Optionally handle debug data if present
        if (frame.payload.len > 8) {
            const debug_data = frame.payload[8..];
            log.debug("GOAWAY debug data: {any}\n", .{debug_data});
        }
        // Set the goaway_received flag
        self.goaway_received = true;
        // Update the highest stream ID we can process
        self.last_stream_id = last_stream_id;

        // Don't immediately close the connection - allow draining of pending frames
        // The connection will close when goaway_sent is also true (graceful shutdown)
        // or when all streams are processed
    }
    /// Process frame within the stream and handle errors
    fn handle_stream_level_frame_process(
        self: *@This(),
        stream: *DefaultStream.StreamInstance,
        frame: Frame,
    ) !void {
        stream.handleFrame(frame) catch |err| {
            log.err("Error handling frame in stream {d}: {s}\n", .{ frame.header.stream_id, @errorName(err) });

            if (self.goaway_sent) {
                return;
            }

            try self.handle_stream_level_frame_process_error(frame.header.stream_id, err);
        };

        if (stream.state == .Closed) {
            const stream_index = self.streamFindIndex(stream.id) orelse unreachable;
            self.releaseClosedStream(stream_index);
            return;
        }

        try self.queueStreamIfReady(stream);
    }

    fn handleOptimizedStreamFrame(
        self: *@This(),
        stream: *DefaultStream.StreamInstance,
        frame: Frame,
    ) !void {
        try self.handle_stream_level_frame_process(stream, frame);
        self.handle_stream_level_frame_update_continuation_state(frame);
    }

    /// Handle specific stream processing errors
    fn handle_stream_level_frame_process_error(self: *@This(), stream_id: u32, err: anyerror) !void {
        switch (err) {
            error.FrameSizeError => {
                log.err("Frame size error on stream {d}: FRAME_SIZE_ERROR\n", .{stream_id});
                try self.send_goaway(self.last_stream_id, 0x6, "Frame size error: FRAME_SIZE_ERROR");
                return;
            },
            error.CompressionError => {
                try self.send_goaway(0, 0x9, "Compression error: COMPRESSION_ERROR");
                return;
            },
            error.StreamClosed => {
                if (!self.goaway_sent) {
                    log.debug("Stream {d}: Detected StreamClosed error, sending RST_STREAM with STREAM_CLOSED (0x5)\n", .{stream_id});
                    try self.send_rst_stream(stream_id, 0x5);
                }
                return;
            },
            error.FlowControlError => {
                try self.send_rst_stream(stream_id, 0x3);
                return;
            },
            error.ProtocolError => {
                try self.send_goaway(self.last_stream_id, 0x1, "Protocol error: PROTOCOL_ERROR");
                return err;
            },
            error.InvalidStreamState, error.IdleStreamError => {
                try self.send_goaway(0, 0x1, "Invalid stream state: PROTOCOL_ERROR");
                return;
            },
            else => {},
        }
    }

    /// Update CONTINUATION frame expectations based on frame type and flags
    fn handle_stream_level_frame_update_continuation_state(self: *@This(), frame: Frame) void {
        const is_headers_frame = (frame.header.frame_type == FrameType.HEADERS);
        const is_push_promise_frame = (frame.header.frame_type == FrameType.PUSH_PROMISE);
        const is_continuation_frame = (frame.header.frame_type == FrameType.CONTINUATION);
        const has_end_headers_flag = ((frame.header.flags.value & FrameFlags.END_HEADERS) != 0);

        if (is_headers_frame or is_push_promise_frame) {
            if (!has_end_headers_flag) {
                self.expecting_continuation_stream_id = frame.header.stream_id;
            }
        }

        if (is_continuation_frame) {
            if (has_end_headers_flag) {
                self.expecting_continuation_stream_id = null;
            }
        }
    }
    fn handle_receive_frame_error(self: *@This(), err: anytype) !void {
        switch (err) {
            error.FrameSizeError => {
                log.err("Frame size exceeded, sending GOAWAY: FRAME_SIZE_ERROR.\n", .{});
                try self.send_goaway(self.highest_stream_id(), 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
                return error.FrameSizeError;
            },
            error.UnexpectedEOF => {
                log.debug("Client closed the connection (UnexpectedEOF)\n", .{});
                return error.UnexpectedEOF;
            },
            else => {
                log.err("Error receiving frame: {s}\n", .{@errorName(err)});
                return err;
            },
        }
    }
    pub fn process_request(self: *@This(), stream: *DefaultStream.StreamInstance) !void {
        assert(stream.request_complete);
        assert(stream.request_headers_complete);
        assert(!stream.expecting_continuation);
        log.debug("Processing request for stream ID: {d}, state: {s}", .{ stream.id, @tagName(stream.state) });
        try self.process_request_prepare_response(stream);
        try resp.sendResponseHeaders(stream, self);
        try resp.sendResponseBody(stream, self);
    }

    fn process_request_prepare_response(self: *@This(), stream: *DefaultStream.StreamInstance) !void {
        if (stream.response_writer.isPrepared()) {
            return;
        }

        var response = try self.build_response(stream);
        errdefer response.deinit();
        try self.encode_response(stream, &response);
    }

    fn build_response(self: *@This(), stream: *DefaultStream.StreamInstance) !handler.Response {
        if (self.request_dispatcher) |request_dispatcher| {
            return self.dispatch_request(request_dispatcher, stream) catch |err| switch (err) {
                error.InvalidRequestTarget,
                error.MissingMethod,
                error.MissingPath,
                error.RequestTargetTooLarge,
                => self.simpleResponse(.bad_request, "Bad Request"),
                error.UnsupportedMethod => self.simpleResponse(.not_implemented, "Not Implemented"),
                else => return err,
            };
        }
        return self.build_default_response();
    }

    fn build_default_response(self: *@This()) !handler.Response {
        const builder = handler.ResponseBuilder.init(self.allocator);
        return builder.html(.ok, default_response_body);
    }

    fn dispatch_request(
        self: *@This(),
        request_dispatcher: handler.RequestDispatcher,
        stream: *DefaultStream.StreamInstance,
    ) !handler.Response {
        const method = try self.requestMethod(stream);
        const raw_target = stream.request_path orelse return error.MissingPath;
        if (path.normalizedRequestTarget(raw_target)) |target| {
            return self.dispatch_request_target(request_dispatcher, stream, method, target);
        }
        return self.dispatch_request_slow(request_dispatcher, stream, method, raw_target);
    }

    fn dispatch_request_slow(
        self: *@This(),
        request_dispatcher: handler.RequestDispatcher,
        stream: *DefaultStream.StreamInstance,
        method: handler.Method,
        raw_target: []const u8,
    ) !handler.Response {
        var path_storage: [memory_budget.MemBudget.max_header_size_bytes]u8 = undefined;
        const target = try path.normalizeRequestTarget(raw_target, &path_storage);
        return self.dispatch_request_target(request_dispatcher, stream, method, target);
    }

    fn dispatch_request_target(
        self: *@This(),
        request_dispatcher: handler.RequestDispatcher,
        stream: *DefaultStream.StreamInstance,
        method: handler.Method,
        target: RequestTarget,
    ) !handler.Response {
        var context = handler.Context.init(
            self.allocator,
            method,
            target.normalized_path,
            target.query,
            stream.headers.items,
            stream.request_body_storage[0..stream.request_body_len],
            stream.response_body_storage[0..],
        );

        return request_dispatcher.call(&context) catch |err| {
            log.err("Request dispatcher failed on stream {d}: {s}\n", .{
                stream.id,
                @errorName(err),
            });
            return self.simpleResponse(.internal_server_error, "Internal Server Error");
        };
    }

    fn requestMethod(self: *@This(), stream: *DefaultStream.StreamInstance) !handler.Method {
        _ = self;
        if (stream.request_method) |method| {
            return method;
        }
        if (stream.request_method_bytes == null) {
            return error.MissingMethod;
        }
        return error.UnsupportedMethod;
    }

    fn requestPseudoHeader(
        self: *@This(),
        stream: *const DefaultStream.StreamInstance,
        name: []const u8,
    ) ?[]const u8 {
        _ = self;
        for (stream.headers.items) |header_field| {
            if (std.mem.eql(u8, header_field.name, name)) {
                return header_field.value;
            }
        }
        return null;
    }

    fn simpleResponse(self: *@This(), status: handler.Status, body: []const u8) !handler.Response {
        const builder = handler.ResponseBuilder.init(self.allocator);
        return builder.text(status, body);
    }

    fn encode_response(
        self: *@This(),
        stream: *DefaultStream.StreamInstance,
        response_msg: *const handler.Response,
    ) !void {
        try stream.response_writer.encode(
            response_msg,
            &self.hpack_encoder_table,
            self.allocator,
        );
    }

    pub fn send_settings(self: *@This()) !void {
        const settings = [_][2]u32{
            .{ 1, self.settings.header_table_size }, // HEADER_TABLE_SIZE
            .{ 3, self.settings.max_concurrent_streams }, // MAX_CONCURRENT_STREAMS
            .{ 4, self.settings.initial_window_size }, // INITIAL_WINDOW_SIZE
            .{ 5, self.settings.max_frame_size }, // MAX_FRAME_SIZE
            .{ 6, self.settings.max_header_list_size }, // MAX_HEADER_LIST_SIZE
            .{ settings_no_rfc7540_priorities_id, @intFromBool(self.settings.no_rfc7540_priorities) },
        };
        // Define the settings frame header
        var frame_header = FrameHeader{
            .length = @intCast(6 * settings.len), // 6 bytes per setting
            .frame_type = FrameType.SETTINGS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0, // 0 indicates a connection-level frame
        };
        // Write the frame header first
        try frame_header.write(self.writer);
        var buffer: [6]u8 = undefined;
        for (settings) |setting| {
            // Serialize Setting ID as u16 (big-endian)
            std.mem.writeInt(u16, buffer[0..2], @intCast(setting[0]), .big);
            // Serialize Setting Value as u32 (big-endian)
            std.mem.writeInt(u32, buffer[2..6], setting[1], .big);
            try self.writer.writeAll(buffer[0..6]);
        }
    }

    pub fn apply_frame_settings(self: *@This(), frame: Frame) !void {
        std.debug.assert(frame.header.frame_type == FrameType.SETTINGS);
        std.debug.assert(frame.header.stream_id == 0);

        try self.apply_frame_settings_validate(frame);

        if (self.apply_frame_settings_is_ack(frame)) {
            try self.apply_frame_settings_handle_ack(frame);
            return;
        }

        try self.apply_frame_settings_validate_payload(frame);
        try self.apply_frame_settings_process_parameters(frame);
    }

    /// Validate SETTINGS frame basic properties
    fn apply_frame_settings_validate(self: *@This(), frame: Frame) !void {
        if (frame.header.frame_type != FrameType.SETTINGS) {
            log.err("Received frame with invalid frame type: {any}\n", .{frame.header.frame_type});
            return error.InvalidFrameType;
        }

        if (frame.header.stream_id != 0) {
            log.err("SETTINGS frame received on a non-zero stream ID: {any}\n", .{frame.header.stream_id});
            if (!self.goaway_sent) {
                try self.send_goaway(0, 0x1, "SETTINGS frame with non-zero stream ID: PROTOCOL_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
    }

    /// Check if SETTINGS frame has ACK flag
    fn apply_frame_settings_is_ack(self: *@This(), frame: Frame) bool {
        _ = self;
        return (frame.header.flags.value & FrameFlags.ACK) != 0;
    }

    /// Handle SETTINGS ACK frame
    fn apply_frame_settings_handle_ack(self: *@This(), frame: Frame) !void {
        if (frame.payload.len != 0) {
            log.err("SETTINGS frame with ACK flag and non-zero payload length\n", .{});
            if (!self.goaway_sent) {
                try self.send_goaway(0, 0x6, "SETTINGS ACK with payload: FRAME_SIZE_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
    }

    /// Validate SETTINGS frame payload format
    fn apply_frame_settings_validate_payload(self: *@This(), frame: Frame) !void {
        if (frame.payload.len % 6 != 0) {
            log.err("Invalid SETTINGS frame size: {any}\n", .{frame.payload.len});
            if (!self.goaway_sent) {
                try self.send_goaway(0, 0x6, "Invalid SETTINGS frame size: FRAME_SIZE_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
    }

    /// Process all SETTINGS parameters in frame payload
    fn apply_frame_settings_process_parameters(self: *@This(), frame: Frame) !void {
        const buffer = frame.payload;
        const buffer_size_u32: u32 = @intCast(buffer.len);
        var index: u32 = 0;
        var no_rfc7540_priorities: ?bool = null;

        while (index + 6 <= buffer_size_u32) {
            const setting_id_ptr: *const [2]u8 = @ptrCast(&buffer[index]);
            const setting_id = std.mem.readInt(u16, setting_id_ptr, .big);

            const setting_value_ptr: *const [4]u8 = @ptrCast(&buffer[index + 2]);
            const setting_value = std.mem.readInt(u32, setting_value_ptr, .big);

            if (setting_id == settings_no_rfc7540_priorities_id) {
                no_rfc7540_priorities = try self.apply_frame_settings_parse_no_rfc7540_priorities(
                    setting_value,
                );
            } else {
                try self.apply_frame_settings_process_single_parameter(setting_id, setting_value);
            }
            index += 6;
        }

        try self.apply_frame_settings_finalize_no_rfc7540_priorities(
            no_rfc7540_priorities,
        );
        self.peer_first_settings_received = true;
    }

    /// Process a single SETTINGS parameter
    fn apply_frame_settings_process_single_parameter(self: *@This(), setting_id: u16, setting_value: u32) !void {
        switch (setting_id) {
            1 => try self.apply_frame_settings_header_table_size(setting_value),
            2 => try self.apply_frame_settings_enable_push(setting_value),
            3 => self.apply_frame_settings_max_concurrent_streams(setting_value),
            4 => try self.apply_frame_settings_initial_window_size(setting_value),
            5 => try self.apply_frame_settings_max_frame_size(setting_value),
            6 => self.apply_frame_settings_max_header_list_size(setting_value),
            else => {},
        }
    }

    fn apply_frame_settings_parse_no_rfc7540_priorities(
        self: *@This(),
        value: u32,
    ) !bool {
        if (value == 0) {
            return false;
        }
        if (value == 1) {
            return true;
        }

        if (!self.goaway_sent) {
            try self.send_goaway(
                0,
                0x1,
                "Invalid SETTINGS_NO_RFC7540_PRIORITIES value: PROTOCOL_ERROR",
            );
            self.goaway_sent = true;
        }
        return error.ProtocolError;
    }

    fn apply_frame_settings_finalize_no_rfc7540_priorities(
        self: *@This(),
        value: ?bool,
    ) !void {
        if (!self.peer_first_settings_received) {
            if (value) |setting_value| {
                self.peer_no_rfc7540_priorities = setting_value;
                self.peer_no_rfc7540_priorities_setting_received = true;
            }
            return;
        }

        if (value == null) {
            return;
        }
        if (!self.peer_no_rfc7540_priorities_setting_received) {
            try self.sendGoawayAndClose(
                0x1,
                "SETTINGS_NO_RFC7540_PRIORITIES changed: PROTOCOL_ERROR",
            );
            return error.ProtocolError;
        }

        const setting_value = value.?;
        if (self.peer_no_rfc7540_priorities != setting_value) {
            try self.sendGoawayAndClose(
                0x1,
                "SETTINGS_NO_RFC7540_PRIORITIES changed: PROTOCOL_ERROR",
            );
            return error.ProtocolError;
        }
    }

    /// Handle SETTINGS_HEADER_TABLE_SIZE
    fn apply_frame_settings_header_table_size(self: *@This(), value: u32) !void {
        self.settings.header_table_size = value;
        // The peer is advertising the largest dynamic table size it is willing to decode.
        // We keep our encoder bounded by local static storage, while accepting larger peer limits.
        self.hpack_encoder_table.setMaxAllowedSize(value);
    }

    /// Handle SETTINGS_ENABLE_PUSH
    fn apply_frame_settings_enable_push(self: *@This(), value: u32) !void {
        if (value != 0 and value != 1) {
            log.err("Invalid SETTINGS_ENABLE_PUSH value {d}: PROTOCOL_ERROR\n", .{value});
            if (!self.goaway_sent) {
                try self.send_goaway(0, 0x1, "Invalid SETTINGS_ENABLE_PUSH value: PROTOCOL_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
        self.settings.enable_push = (value == 1);
    }

    /// Handle SETTINGS_MAX_CONCURRENT_STREAMS
    fn apply_frame_settings_max_concurrent_streams(self: *@This(), value: u32) void {
        self.settings.max_concurrent_streams = value;
    }

    /// Handle SETTINGS_INITIAL_WINDOW_SIZE
    fn apply_frame_settings_initial_window_size(self: *@This(), value: u32) !void {
        // Per RFC 9113 Section 6.9.2: Values above 2^31-1 MUST be treated as FLOW_CONTROL_ERROR
        const max_window_size: u32 = 2147483647;
        if (value > max_window_size) {
            log.debug("SETTINGS_INITIAL_WINDOW_SIZE too large {d}: FLOW_CONTROL_ERROR\n", .{value});
            if (!self.goaway_sent) {
                try self.send_goaway(0, 0x3, "SETTINGS_INITIAL_WINDOW_SIZE too large: FLOW_CONTROL_ERROR");
                self.goaway_sent = true;
                try self.flush_output();
            }
            return;
        }

        const old_window_size = self.settings.initial_window_size;
        self.settings.initial_window_size = value;

        const new_size_i32: i32 = @intCast(value);
        const old_size_i32: i32 = @intCast(old_window_size);
        const window_delta: i32 = new_size_i32 - old_size_i32;

        try self.apply_frame_settings_update_stream_windows(window_delta);
    }

    /// Update all stream window sizes when initial window size changes
    fn apply_frame_settings_update_stream_windows(self: *@This(), window_delta: i32) !void {
        for (&self.stream_storage.slots, self.stream_storage.in_use) |*stream, in_use| {
            if (!in_use) continue;
            const new_window_size: i64 = @as(i64, stream.send_window_size) + @as(i64, window_delta);
            if (new_window_size < std.math.minInt(i32)) {
                log.err("Stream window size underflow on stream {d}: FLOW_CONTROL_ERROR\n", .{stream.id});
                if (!self.goaway_sent) {
                    try self.send_goaway(0, 0x3, "Stream window size underflow: FLOW_CONTROL_ERROR");
                    self.goaway_sent = true;
                }
                return;
            }
            if (new_window_size > std.math.maxInt(i32)) {
                log.err("Stream window size overflow on stream {d}: FLOW_CONTROL_ERROR\n", .{stream.id});
                if (!self.goaway_sent) {
                    try self.send_goaway(0, 0x3, "Stream window size overflow: FLOW_CONTROL_ERROR");
                    self.goaway_sent = true;
                }
                return;
            }

            stream.send_window_size = @intCast(new_window_size);
            stream.initial_window_size = self.settings.initial_window_size;
        }
    }

    /// Handle SETTINGS_MAX_FRAME_SIZE
    fn apply_frame_settings_max_frame_size(self: *@This(), value: u32) !void {
        const min_frame_size: u32 = 16384;
        const max_frame_size: u32 = 16777215;

        if (value < min_frame_size or value > max_frame_size) {
            log.err("Invalid SETTINGS_MAX_FRAME_SIZE value {d}: PROTOCOL_ERROR\n", .{value});
            if (!self.goaway_sent) {
                try self.send_goaway(0, 0x1, "Invalid SETTINGS_MAX_FRAME_SIZE value: PROTOCOL_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
        self.settings.max_frame_size = value;
    }

    /// Handle SETTINGS_MAX_HEADER_LIST_SIZE
    fn apply_frame_settings_max_header_list_size(self: *@This(), value: u32) void {
        self.settings.max_header_list_size = value;
    }
    /// Sends a GOAWAY frame with the given parameters.
    pub fn send_goaway(self: *@This(), last_stream_id: u32, error_code: u32, debug_data: []const u8) !void {
        const debug_data_max = 96;
        const debug_data_len = @min(debug_data.len, debug_data_max);
        const payload_size = 8 + debug_data_len;
        assert(payload_size > 0);

        var payload: [8 + debug_data_max]u8 = undefined;
        std.mem.writeInt(u32, payload[0..4], last_stream_id & 0x7FFFFFFF, .big);
        std.mem.writeInt(u32, payload[4..8], error_code, .big);
        if (debug_data_len > 0) {
            std.mem.copyForwards(u8, payload[8 .. 8 + debug_data_len], debug_data[0..debug_data_len]);
        }

        var goaway_frame = Frame{
            .header = FrameHeader{
                .length = @intCast(payload_size),
                .frame_type = FrameType.GOAWAY,
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = 0,
            },
            .payload = payload[0..payload_size],
        };
        try goaway_frame.write(self.writer);
        self.goaway_sent = true;
    }
    pub fn get_stream(self: *@This(), stream_id: u32) !*DefaultStream.StreamInstance {
        // Ensure the stream ID is valid (odd numbers for client-initiated streams)
        if (stream_id % 2 == 0) {
            log.err("Received invalid stream ID {d} from client: PROTOCOL_ERROR\n", .{stream_id});
            try self.send_goaway(0, 0x1, "Invalid stream ID: PROTOCOL_ERROR");
            return error.ProtocolError;
        }
        // Check if the stream already exists
        if (self.streamFind(stream_id)) |stream| {
            return stream;
        } else {
            // Enforce the max concurrent streams limit
            if (self.active_stream_count() >= self.settings.max_concurrent_streams) {
                log.err("Exceeded max concurrent streams limit: {d}\n", .{self.settings.max_concurrent_streams});
                return error.MaxConcurrentStreamsExceeded;
            }
            // Ensure the new stream ID is greater than the last processed stream ID
            if (stream_id <= self.last_stream_id) {
                log.err("Received new stream ID {d} <= last_stream_id {d}: PROTOCOL_ERROR\n", .{ stream_id, self.last_stream_id });
                try self.send_goaway(0, 0x1, "Stream ID decreased: PROTOCOL_ERROR");
                return error.ProtocolError;
            }
            // Update the last processed stream ID
            self.last_stream_id = stream_id;
            // Initialize a new stream in-place
            const new_stream = self.streamAllocate(stream_id) catch |err| {
                log.err("Failed to initialize stream {d}: {s}\n", .{ stream_id, @errorName(err) });
                return err;
            };
            new_stream.send_window_size = @intCast(self.settings.initial_window_size);
            new_stream.initial_window_size = self.settings.initial_window_size;
            return new_stream;
        }
    }
    fn update_send_window(self: *@This(), increment: i32) !void {
        const ov = @addWithOverflow(self.send_window_size, increment);
        if (ov[0] > 2147483647 or ov[0] < 0) {
            log.err("Flow control window overflow detected. Sending GOAWAY with FLOW_CONTROL_ERROR.\n", .{});
            if (!self.goaway_sent) {
                try self.send_goaway(self.highest_stream_id(), 0x3, "Flow control window exceeded limits: FLOW_CONTROL_ERROR");
                self.goaway_sent = true;
            }
            return error.FlowControlError; // Still return error since this is a helper function
        }
        self.send_window_size = ov[0];
    }
    fn update_recv_window(self: *@This(), delta: i32) !void {
        const ov = @addWithOverflow(self.recv_window_size, delta);
        if (ov[0] > 2147483647 or ov[0] < 0) {
            log.err("Receive window overflow detected. Sending GOAWAY with FLOW_CONTROL_ERROR.\n", .{});
            if (!self.goaway_sent) {
                try self.send_goaway(self.highest_stream_id(), 0x3, "Receive window exceeded limits: FLOW_CONTROL_ERROR");
                self.goaway_sent = true;
            }
            return error.FlowControlError; // Still return error since this is a helper function
        }
        self.recv_window_size = ov[0];
    }
    pub fn send_window_update(self: *@This(), stream_id: u32, increment: i32) !void {
        var frame_header = FrameHeader{
            .length = 4,
            .frame_type = FrameType.WINDOW_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = stream_id,
        };
        var buffer: [4]u8 = undefined;
        std.mem.writeInt(u32, &buffer, @intCast(increment), .big);
        try frame_header.write(self.writer);
        try self.writer.writeAll(&buffer);
    }
    pub fn handle_window_update(self: *@This(), frame: Frame) !void {
        if (frame.payload.len != 4) {
            log.err("WINDOW_UPDATE frame with invalid payload length {d} (expected 4): FRAME_SIZE_ERROR\n", .{frame.payload.len});
            if (!self.goaway_sent) {
                try self.send_goaway(self.highest_stream_id(), 0x6, "WINDOW_UPDATE frame with invalid payload length: FRAME_SIZE_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
        const increment = std.mem.readInt(u32, frame.payload[0..4], .big);

        if (increment == 0) {
            log.err("Received WINDOW_UPDATE with increment 0, sending GOAWAY: PROTOCOL_ERROR.\n", .{});
            if (!self.goaway_sent) {
                try self.send_goaway(self.highest_stream_id(), 0x1, "WINDOW_UPDATE with increment 0: PROTOCOL_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
        if (increment > 0x7FFFFFFF) {
            log.err("Received WINDOW_UPDATE with increment exceeding maximum value, sending GOAWAY: FLOW_CONTROL_ERROR.\n", .{});
            if (!self.goaway_sent) {
                try self.send_goaway(self.highest_stream_id(), 0x3, "WINDOW_UPDATE increment too large: FLOW_CONTROL_ERROR");
                self.goaway_sent = true;
            }
            return;
        }
        if (frame.header.stream_id == 0) {
            self.update_send_window(@intCast(increment)) catch |err| {
                if (err == error.FlowControlError) {
                    // GOAWAY was already sent by update_send_window, ensure it's flushed
                    try self.finishAfterGoaway();
                    return;
                }
                return err;
            };
        } else {
            if (self.streamFind(frame.header.stream_id)) |stream| {
                stream.updateSendWindow(@intCast(increment)) catch |err| {
                    if (err == error.FlowControlError) {
                        // RST_STREAM was already sent by updateSendWindow
                        return;
                    }
                    return err;
                };
            } else {
                if (frame.header.stream_id > self.last_stream_id) {
                    log.err("WINDOW_UPDATE frame on idle stream {}: PROTOCOL_ERROR\n", .{frame.header.stream_id});
                    try self.send_goaway(0, 0x1, "WINDOW_UPDATE frame on idle stream: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }
                log.debug("WINDOW_UPDATE frame on closed stream {}: ignoring\n", .{frame.header.stream_id});
            }
        }
    }
    pub fn send_data(self: *@This(), stream: *DefaultStream.StreamInstance, data: []const u8, end_stream: bool) !void {
        const max_frame_size = self.settings.max_frame_size;
        var remaining_data = data;
        while (remaining_data.len > 0) {
            const chunk_size = if (remaining_data.len > max_frame_size) max_frame_size else remaining_data.len;
            const data_chunk = remaining_data[0..chunk_size];
            remaining_data = remaining_data[chunk_size..];
            var data_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(chunk_size),
                    .frame_type = FrameType.DATA,
                    .flags = FrameFlags{
                        .value = if (remaining_data.len == 0 and end_stream) FrameFlags.END_STREAM else 0,
                    },
                    .reserved = false,
                    .stream_id = stream.id,
                },
                .payload = data_chunk,
            };
            try data_frame.write(self.writer);
        }
    }
};

fn encodeTestRequestHeaders(
    allocator: std.mem.Allocator,
    connection: *Connection,
) ![]u8 {
    const request_headers = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var encoded_headers: std.ArrayList(u8) = .empty;
    defer encoded_headers.deinit(allocator);

    for (request_headers) |header| {
        try Hpack.encodeHeaderField(
            header,
            &connection.hpack_encoder_table,
            &encoded_headers,
            allocator,
        );
    }

    return encoded_headers.toOwnedSlice(allocator);
}

test "HTTP/2 connection initialization and flow control" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [8192]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();
    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    var stream = try DefaultStream.init(allocator, &connection, 1);
    const preface_written_data = test_io.written();
    const headers_payload = try encodeTestRequestHeaders(allocator, &connection);
    defer allocator.free(headers_payload);
    const headers_payload_len: u32 = @intCast(headers_payload.len);
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = headers_payload_len,
            .frame_type = FrameType.HEADERS,
            .flags = FrameFlags.init(FrameFlags.END_HEADERS | FrameFlags.END_STREAM),
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = headers_payload,
    };
    try stream.handleFrame(headers_frame);
    var response = try connection.build_default_response();
    defer response.deinit();
    try connection.encode_response(stream, &response);
    try resp.sendResponseHeaders(stream, &connection);
    const headers_written_data = test_io.written();
    assert(headers_written_data.len > preface_written_data.len);
    const data = "Hello, world!";
    try connection.send_data(stream, data, false);
    const written_data = test_io.written();
    const preface_length = 24;
    const settings_frame_length = 39;
    const min_expected_length = preface_length + settings_frame_length + 40;
    assert(written_data.len >= min_expected_length);
    test_io.resetWriter(&buffer);
    const data_after_reset = "Hello again!";
    try connection.send_data(stream, data_after_reset, false);
    const sent_data = test_io.written();
    assert(sent_data.len > 0);
    const window_update_frame = Frame{
        .header = FrameHeader{
            .length = 4,
            .frame_type = FrameType.WINDOW_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{ 0x00, 0x00, 0x01, 0x00 },
    };
    try connection.handle_window_update(window_update_frame);
    try connection.send_data(stream, data_after_reset, false);
    const sent_data_after_window_update = test_io.written();
    assert(sent_data_after_window_update.len > sent_data.len);
}
test "apply_frame_settings test" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const alloc = arena.allocator();
    var connection = try Connection.init(alloc, &test_io.reader, &test_io.writer, false);
    const frame = Frame{
        .header = FrameHeader{
            .length = 18,
            .frame_type = FrameType.SETTINGS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{
            // Example settings: ID 1, value 4096; ID 3, value 100; ID 4, value 65535
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // header_table_size: 4096
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // max_concurrent_streams: 100
            0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF, // initial_window_size: 65535
        },
    };
    // Call the function to apply the frame settings via connection
    try connection.apply_frame_settings(frame);
    // Assert that the settings were applied correctly in the connection
    try std.testing.expect(connection.settings.header_table_size == 4096);
    try std.testing.expect(connection.settings.max_concurrent_streams == 100);
    try std.testing.expect(connection.settings.initial_window_size == 65535);
}

test "apply_frame_settings rejects oversized initial window with GOAWAY" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    test_io.resetWriter(&buffer);

    const frame = Frame{
        .header = .{
            .length = 6,
            .frame_type = .SETTINGS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{
            0x00, 0x04,
            0x80, 0x00,
            0x00, 0x00,
        },
    };

    try connection.apply_frame_settings(frame);

    try std.testing.expect(connection.goaway_sent);
    try std.testing.expectEqual(@as(u32, 65535), connection.settings.initial_window_size);

    const written = test_io.written();
    try std.testing.expect(written.len >= 17);
    try std.testing.expectEqual(@intFromEnum(FrameType.GOAWAY), written[3]);

    const goaway_error_code = std.mem.readInt(u32, written[13..17], .big);
    try std.testing.expectEqual(@as(u32, 0x3), goaway_error_code);
}

test "apply_frame_settings allows stream window to become negative" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    var stream = try connection.get_stream(1);
    stream.state = .HalfClosedRemote;
    stream.request_headers_complete = true;
    stream.request_complete = true;
    stream.send_window_size = 1;

    test_io.resetWriter(&buffer);

    const frame = Frame{
        .header = .{
            .length = 6,
            .frame_type = .SETTINGS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{
            0x00, 0x04,
            0x00, 0x00,
            0x00, 0x00,
        },
    };

    try connection.apply_frame_settings(frame);

    try std.testing.expect(!connection.goaway_sent);
    try std.testing.expectEqual(@as(u32, 0), connection.settings.initial_window_size);
    try std.testing.expectEqual(@as(i32, -65534), stream.send_window_size);
    try std.testing.expectEqual(@as(usize, 0), test_io.written().len);
}

test "default settings stream" {
    const settings = Settings.default();

    try std.testing.expectEqual(@as(u32, 100), settings.max_concurrent_streams);
    try std.testing.expectEqual(max_streams_per_connection, settings.max_concurrent_streams);
    try std.testing.expect(settings.no_rfc7540_priorities);
}

test "stream allocation matches fixed concurrent stream capacity" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const alloc = arena.allocator();
    var connection = try Connection.init(
        alloc,
        &test_io.reader,
        &test_io.writer,
        false,
    );

    var stream_index: u32 = 0;
    while (stream_index < max_streams_per_connection) : (stream_index += 1) {
        const stream_id = stream_index * 2 + 1;
        _ = try connection.streamAllocate(stream_id);
    }

    const overflow_stream_id = max_streams_per_connection * 2 + 1;
    try std.testing.expectError(
        error.MaxConcurrentStreamsExceeded,
        connection.streamAllocate(overflow_stream_id),
    );
}

test "send HEADERS and DATA frames with proper flow" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [8192]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();
    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    var stream = try DefaultStream.init(allocator, &connection, 1);
    const headers_payload = [_]u8{ 0x82, 0x86, 0x84, 0x81 }; // :method GET, :scheme http, :path /, :authority
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = headers_payload.len,
            .frame_type = FrameType.HEADERS,
            .flags = FrameFlags{
                .value = FrameFlags.END_HEADERS, // Mark end of headers
            },
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = &headers_payload,
    };
    try stream.handleFrame(headers_frame);
    const headers_written_data = test_io.written();
    assert(headers_written_data.len > 0);
    const data = "Hello, world!";
    try connection.send_data(stream, data, false);
    const written_data = test_io.written();
    assert(written_data.len > headers_written_data.len);
}
test "send RST_STREAM frame with correct frame_type" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();
    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    var stream = try DefaultStream.init(allocator, &connection, 1);
    const initial_pos = test_io.written().len;
    try stream.sendRstStream(0x1);
    const written_data = test_io.written();
    try std.testing.expectEqual(written_data[initial_pos + 3], 3);
}

test "default response header encoding uses dynamic table after first response" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    const stream = try connection.get_stream(1);

    var response = try connection.build_default_response();
    defer response.deinit();
    try connection.encode_response(stream, &response);
    const first_header_block_len = stream.response_writer.response_header_block_len;

    var dynamic_table = Hpack.DynamicTable.init(allocator, 4096);
    defer dynamic_table.deinit();

    const expected_content_length = std.fmt.comptimePrint(
        "{d}",
        .{default_response_body.len},
    );
    const expected_headers = [_]Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = default_response_content_type },
        .{ .name = "content-length", .value = expected_content_length },
    };

    var offset: usize = 0;
    for (expected_headers) |expected_header| {
        const headers_block = stream.response_writer.headersBlock();
        var decoded = try Hpack.decodeHeaderField(
            headers_block[offset..],
            &dynamic_table,
            allocator,
        );
        defer decoded.deinit();

        try std.testing.expectEqualStrings(expected_header.name, decoded.header.name);
        try std.testing.expectEqualStrings(expected_header.value, decoded.header.value);
        offset += decoded.bytes_consumed;
    }

    try std.testing.expectEqual(stream.response_writer.response_header_block_len, offset);
    try std.testing.expect(dynamic_table.count > 0);

    const second_stream = try connection.get_stream(3);
    var second_response = try connection.build_default_response();
    defer second_response.deinit();
    try connection.encode_response(second_stream, &second_response);

    try std.testing.expect(second_stream.response_writer.response_header_block_len < first_header_block_len);
}

test "flush_ready_streams reports completed responses once" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );

    const stream = try connection.get_stream(1);
    stream.state = .HalfClosedRemote;
    stream.request_headers_complete = true;
    stream.request_complete = true;

    try connection.queueStreamIfReady(stream);
    try connection.flush_ready_streams();

    try std.testing.expectEqual(@as(u32, 1), connection.takeCompletedResponses());
    try std.testing.expectEqual(@as(u32, 0), connection.takeCompletedResponses());
}

test "flush_ready_streams does not respond before END_HEADERS" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    const initial_written_len = test_io.written().len;

    const fragmented_headers = Frame{
        .header = .{
            .length = 1,
            .frame_type = .HEADERS,
            .flags = FrameFlags.init(FrameFlags.END_STREAM),
            .reserved = false,
            .stream_id = 1,
        },
        .payload = &[_]u8{0x82},
    };

    try connection.handleFrameEventDriven(fragmented_headers);

    const stream = try connection.get_stream(1);
    try std.testing.expectEqual(@as(?u32, 1), connection.expecting_continuation_stream_id);
    try std.testing.expect(stream.state == .HalfClosedRemote);
    try std.testing.expect(!stream.request_headers_complete);
    try std.testing.expect(!stream.request_complete);
    try std.testing.expect(!stream.response_writer.response_headers_sent);

    try connection.flush_ready_streams();

    try std.testing.expectEqual(initial_written_len, test_io.written().len);
    try std.testing.expect(!stream.response_writer.response_headers_sent);
    try std.testing.expectEqual(@as(u32, 0), connection.takeCompletedResponses());
}

test "dispatchFrameOptimized queues completed requests for flush" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    const headers_payload = try encodeTestRequestHeaders(allocator, &connection);
    defer allocator.free(headers_payload);

    const headers_frame = Frame{
        .header = .{
            .length = @intCast(headers_payload.len),
            .frame_type = .HEADERS,
            .flags = FrameFlags.init(FrameFlags.END_HEADERS | FrameFlags.END_STREAM),
            .reserved = false,
            .stream_id = 1,
        },
        .payload = headers_payload,
    };

    try connection.dispatchFrameOptimized(headers_frame);
    try std.testing.expectEqual(@as(u8, 1), connection.pending_stream_count);

    try connection.flush_ready_streams();

    try std.testing.expectEqual(@as(u32, 1), connection.takeCompletedResponses());
    try std.testing.expectEqual(@as(u8, 0), connection.pending_stream_count);
}

test "handleFrameEventDriven flushes completed requests" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);
    const headers_payload = try encodeTestRequestHeaders(allocator, &connection);
    defer allocator.free(headers_payload);

    const initial_written_len = test_io.written().len;
    const headers_frame = Frame{
        .header = .{
            .length = @intCast(headers_payload.len),
            .frame_type = .HEADERS,
            .flags = FrameFlags.init(FrameFlags.END_HEADERS | FrameFlags.END_STREAM),
            .reserved = false,
            .stream_id = 1,
        },
        .payload = headers_payload,
    };

    try connection.handleFrameEventDriven(headers_frame);

    try std.testing.expect(test_io.written().len > initial_written_len);
    try std.testing.expectEqual(@as(u32, 1), connection.takeCompletedResponses());
    try std.testing.expectEqual(@as(u8, 0), connection.pending_stream_count);
}

test "send_settings advertises SETTINGS_NO_RFC7540_PRIORITIES in first SETTINGS frame" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    _ = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );

    const written = test_io.written();
    const settings_offset = http2_preface.len;
    try std.testing.expectEqual(
        @as(u8, @intFromEnum(FrameType.SETTINGS)),
        written[settings_offset + 3],
    );

    const payload_length = (@as(u32, written[settings_offset + 0]) << 16) |
        (@as(u32, written[settings_offset + 1]) << 8) |
        @as(u32, written[settings_offset + 2]);
    try std.testing.expectEqual(@as(u32, 36), payload_length);

    var setting_offset: usize = settings_offset + 9;
    const settings_end = setting_offset + payload_length;
    var saw_setting = false;
    while (setting_offset < settings_end) : (setting_offset += 6) {
        const setting_id = std.mem.readInt(u16, written[setting_offset..][0..2], .big);
        const setting_value = std.mem.readInt(u32, written[setting_offset + 2 ..][0..4], .big);
        if (setting_id != settings_no_rfc7540_priorities_id) {
            continue;
        }

        saw_setting = true;
        try std.testing.expectEqual(@as(u32, 1), setting_value);
    }

    try std.testing.expect(saw_setting);
}

test "PRIORITY_UPDATE buffers idle stream priority until stream opens" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );

    const priority_update_payload = "\x00\x00\x00\x01u=0, i";
    const priority_update_frame = Frame{
        .header = .{
            .length = priority_update_payload.len,
            .frame_type = .PRIORITY_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = priority_update_payload,
    };

    try connection.handle_priority_update_frame(priority_update_frame);
    const stream = try connection.get_stream(1);

    try std.testing.expectEqual(@as(u8, 0), stream.priority.urgency);
    try std.testing.expect(stream.priority.incremental);
    try std.testing.expect(stream.priority_update_received);
}

test "PRIORITY_UPDATE with prioritized stream ID zero sends PROTOCOL_ERROR" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );
    const write_offset_before = test_io.written().len;

    const invalid_payload = "\x00\x00\x00\x00u=0";
    const invalid_frame = Frame{
        .header = .{
            .length = invalid_payload.len,
            .frame_type = .PRIORITY_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = invalid_payload,
    };

    try connection.handle_priority_update_frame(invalid_frame);
    try std.testing.expect(connection.goaway_sent);

    const written = test_io.written();
    try std.testing.expect(written.len > write_offset_before + 16);
    try std.testing.expectEqual(
        @intFromEnum(FrameType.GOAWAY),
        written[write_offset_before + 3],
    );
}

test "scheduler prefers lower urgency before higher urgency" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );

    const low_urgency_stream = try connection.get_stream(1);
    low_urgency_stream.state = .HalfClosedRemote;
    low_urgency_stream.request_headers_complete = true;
    low_urgency_stream.request_complete = true;
    low_urgency_stream.priority.urgency = 5;

    const high_urgency_stream = try connection.get_stream(3);
    high_urgency_stream.state = .HalfClosedRemote;
    high_urgency_stream.request_headers_complete = true;
    high_urgency_stream.request_complete = true;
    high_urgency_stream.priority.urgency = 0;

    try connection.queueStreamIfReady(low_urgency_stream);
    try connection.queueStreamIfReady(high_urgency_stream);

    const selected_index = connection.pendingStreamPop() orelse unreachable;
    const selected_stream = connection.stream_storage.findBySlotIndex(selected_index);
    try std.testing.expectEqual(@as(u32, 3), selected_stream.id);
}

test "scheduler gives same-urgency incremental streams a first turn" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );

    const incremental_stream = try connection.get_stream(1);
    incremental_stream.state = .HalfClosedRemote;
    incremental_stream.request_headers_complete = true;
    incremental_stream.request_complete = true;
    incremental_stream.priority.urgency = 2;
    incremental_stream.priority.incremental = true;

    const blocking_stream = try connection.get_stream(3);
    blocking_stream.state = .HalfClosedRemote;
    blocking_stream.request_headers_complete = true;
    blocking_stream.request_complete = true;
    blocking_stream.priority.urgency = 2;
    blocking_stream.priority.incremental = false;

    try connection.queueStreamIfReady(blocking_stream);
    try connection.queueStreamIfReady(incremental_stream);

    const first_index = connection.pendingStreamPop() orelse unreachable;
    try std.testing.expectEqual(@as(u32, 1), connection.stream_storage.slots[first_index].id);

    try connection.pendingStreamPush(first_index);

    const second_index = connection.pendingStreamPop() orelse unreachable;
    try std.testing.expectEqual(@as(u32, 3), connection.stream_storage.slots[second_index].id);
}

test "flush_ready_streams does not let a blocked stream stall other responses" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(allocator, &test_io.reader, &test_io.writer, false);

    const blocked_stream = try connection.get_stream(1);
    blocked_stream.state = .HalfClosedRemote;
    blocked_stream.request_headers_complete = true;
    blocked_stream.request_complete = true;
    blocked_stream.priority.urgency = 0;
    blocked_stream.send_window_size = 0;

    const ready_stream = try connection.get_stream(3);
    ready_stream.state = .HalfClosedRemote;
    ready_stream.request_headers_complete = true;
    ready_stream.request_complete = true;
    ready_stream.priority.urgency = 5;

    try connection.queueStreamIfReady(blocked_stream);
    try connection.queueStreamIfReady(ready_stream);
    try connection.flush_ready_streams();

    try std.testing.expect(blocked_stream.response_writer.response_headers_sent);
    try std.testing.expect(ready_stream.state == .Closed);
    try std.testing.expectEqual(@as(u32, 1), connection.takeCompletedResponses());
    try std.testing.expectEqual(@as(u8, 1), connection.pending_stream_count);
}

test "event-driven PRIORITY frame rejects payload lengths other than five octets" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );
    const write_offset_before = test_io.written().len;

    const invalid_priority_frame = Frame{
        .header = .{
            .length = 4,
            .frame_type = .PRIORITY,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 1,
        },
        .payload = &[_]u8{ 0x00, 0x00, 0x00, 0x00 },
    };

    // The optimized dispatch path handles invalid PRIORITY payload sizes by
    // sending GOAWAY but does not propagate a FrameSizeError to the caller.
    try connection.handleFrameEventDriven(invalid_priority_frame);
    try std.testing.expect(connection.goaway_sent);

    const written = test_io.written();
    try std.testing.expect(written.len > write_offset_before + 16);
    try std.testing.expectEqual(
        @intFromEnum(FrameType.GOAWAY),
        written[write_offset_before + 3],
    );
    const goaway_error_code = (@as(u32, written[write_offset_before + 13]) << 24) |
        (@as(u32, written[write_offset_before + 14]) << 16) |
        (@as(u32, written[write_offset_before + 15]) << 8) |
        @as(u32, written[write_offset_before + 16]);
    try std.testing.expectEqual(
        @as(u32, 0x6),
        goaway_error_code,
    );
}

test "optimized PRIORITY dispatch validates payload size before ignoring idle streams" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);
    const allocator = arena.allocator();

    var connection = try Connection.init(
        allocator,
        &test_io.reader,
        &test_io.writer,
        false,
    );
    const write_offset_before = test_io.written().len;

    const invalid_priority_frame = Frame{
        .header = .{
            .length = 4,
            .frame_type = .PRIORITY,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 3,
        },
        .payload = &[_]u8{ 0x00, 0x00, 0x00, 0x00 },
    };

    try connection.dispatchFrameOptimized(invalid_priority_frame);
    try std.testing.expect(connection.goaway_sent);

    const written = test_io.written();
    try std.testing.expect(written.len > write_offset_before + 16);
    try std.testing.expectEqual(
        @intFromEnum(FrameType.GOAWAY),
        written[write_offset_before + 3],
    );
    const goaway_error_code = (@as(u32, written[write_offset_before + 13]) << 24) |
        (@as(u32, written[write_offset_before + 14]) << 16) |
        (@as(u32, written[write_offset_before + 15]) << 8) |
        @as(u32, written[write_offset_before + 16]);
    try std.testing.expectEqual(
        @as(u32, 0x6),
        goaway_error_code,
    );
}
