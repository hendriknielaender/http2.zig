const std = @import("std");
const assert = std.debug.assert;
const Frame = @import("frame.zig").Frame;
const FrameHeader = @import("frame.zig").FrameHeader;
const FrameType = @import("frame.zig").FrameType;
const FrameFlags = @import("frame.zig").FrameFlags;
const Connection = @import("connection.zig").Connection;
const Hpack = @import("hpack.zig").Hpack;
const Priority = @import("http_priority.zig").Priority;
const handler = @import("handler.zig");
const field = @import("field.zig");
const field_block = @import("field_block.zig");
const memory_budget = @import("memory_budget.zig");
const protocol = @import("protocol.zig");
const TestIo = @import("testing/fixed_io.zig").FixedIo;
const ResponseWriter = @import("response.zig").ResponseWriter;

const log = std.log.scoped(.stream);

/// Why a message is malformed (RFC 9113 § 8.1.1), or null. A static string, so
/// carrying one costs no storage and keeps validation reportable, not fatal.
const MalformedReason = ?[]const u8;

/// Room for the canned 400's field block. ":status: 400" is HPACK static entry
/// 12, so one byte usually suffices; the margin covers a literal fallback.
const bad_request_block_bytes: usize = 64;

// Compile-time stream state enumeration with explicit ordering for table generation
pub const StreamState = enum(u3) {
    Idle = 0,
    ReservedLocal = 1,
    ReservedRemote = 2,
    Open = 3,
    HalfClosedLocal = 4,
    HalfClosedRemote = 5,
    Closed = 6,
};

// Compile-time stream event enumeration for state machine
const StreamEvent = enum(u4) {
    RecvHeaders = 0,
    RecvData = 1,
    RecvEndStream = 2,
    SendHeaders = 3,
    SendData = 4,
    SendEndStream = 5,
    RecvRstStream = 6,
    SendRstStream = 7,
    RecvPriority = 8,
    RecvWindowUpdate = 9,
    RecvContinuation = 10,
};

// Generate state transition table at compile time
const TRANSITION_TABLE = blk: {
    const num_states = @typeInfo(StreamState).@"enum".fields.len;
    const num_events = @typeInfo(StreamEvent).@"enum".fields.len;

    var table: [num_states][num_events]StreamState = undefined;

    // Initialize all transitions as invalid (same state)
    for (0..num_states) |s| {
        for (0..num_events) |e| {
            table[s][e] = @enumFromInt(s);
        }
    }

    // Define valid HTTP/2 state transitions explicitly
    // From Idle
    table[@intFromEnum(StreamState.Idle)][@intFromEnum(StreamEvent.RecvHeaders)] = StreamState.Open;
    table[@intFromEnum(StreamState.Idle)][@intFromEnum(StreamEvent.SendHeaders)] = StreamState.Open;

    // From Open
    table[
        @intFromEnum(
            StreamState.Open,
        )
    ][@intFromEnum(StreamEvent.RecvEndStream)] = StreamState.HalfClosedRemote;
    table[
        @intFromEnum(
            StreamState.Open,
        )
    ][@intFromEnum(StreamEvent.SendEndStream)] = StreamState.HalfClosedLocal;
    table[
        @intFromEnum(
            StreamState.Open,
        )
    ][@intFromEnum(StreamEvent.RecvRstStream)] = StreamState.Closed;
    table[
        @intFromEnum(
            StreamState.Open,
        )
    ][@intFromEnum(StreamEvent.SendRstStream)] = StreamState.Closed;

    // From HalfClosedLocal
    table[
        @intFromEnum(
            StreamState.HalfClosedLocal,
        )
    ][@intFromEnum(StreamEvent.RecvEndStream)] = StreamState.Closed;
    table[
        @intFromEnum(
            StreamState.HalfClosedLocal,
        )
    ][@intFromEnum(StreamEvent.RecvRstStream)] = StreamState.Closed;
    table[
        @intFromEnum(
            StreamState.HalfClosedLocal,
        )
    ][@intFromEnum(StreamEvent.SendRstStream)] = StreamState.Closed;

    // From HalfClosedRemote
    table[
        @intFromEnum(
            StreamState.HalfClosedRemote,
        )
    ][@intFromEnum(StreamEvent.SendEndStream)] = StreamState.Closed;
    table[
        @intFromEnum(
            StreamState.HalfClosedRemote,
        )
    ][@intFromEnum(StreamEvent.RecvRstStream)] = StreamState.Closed;
    table[
        @intFromEnum(
            StreamState.HalfClosedRemote,
        )
    ][@intFromEnum(StreamEvent.SendRstStream)] = StreamState.Closed;

    break :blk table;
};

// Compile-time state machine transition function
pub fn transitionState(current: StreamState, event: StreamEvent) StreamState {
    return TRANSITION_TABLE[@intFromEnum(current)][@intFromEnum(event)];
}

// Compile-time stream configuration with assertions
pub fn Stream(comptime WindowBits: u5, comptime MaxStreams: u31) type {
    comptime {
        assert(WindowBits >= 16); // Minimum window size of 64KB
        assert(WindowBits <= 31); // Maximum window size of 2GB
        assert(MaxStreams > 0);
        assert(MaxStreams <= (1 << 30)); // Reasonable upper bound
    }

    return struct {
        // Compile-time constants for performance
        const Self = @This();
        const WindowBufferSize: u32 = 1 << WindowBits;
        const WindowDefault: u32 = WindowBufferSize - 1;
        const MaxStreamCount: u32 = MaxStreams;
        const HeaderBufferSize = memory_budget.MemBudget.max_header_size_bytes;
        const HeaderCountMax = 64;

        // Stream instance with static buffer allocation
        pub const StreamInstance = struct {
            // Core stream identification and state
            id: u32,
            state: StreamState,
            conn: *Connection,

            // Flow control with compile-time optimized window sizes
            recv_window_size: i32,
            send_window_size: i32,
            initial_window_size: u32,

            // Static buffer allocation for maximum performance
            header_block_fragments_buf: [HeaderBufferSize]u8,
            headers_bytes_storage: [HeaderBufferSize]u8,

            // Buffer length tracking for static arrays
            header_block_fragments_len: usize,
            headers_bytes_len: usize,

            // Header processing state
            expecting_continuation: bool,
            headers_storage: [HeaderCountMax]Hpack.HeaderField,
            headers: std.ArrayList(Hpack.HeaderField),
            content_length: ?u64,
            request_method_bytes: ?[]const u8,
            request_method: ?handler.Method,
            request_path: ?[]const u8,
            total_data_received: usize,
            request_body_storage: [memory_budget.MemBudget.max_data_buffer_bytes]u8,
            request_body_len: usize,
            // Scratch for a buffered body or in-place streaming source state.
            // The two uses are mutually exclusive for a response.
            response_body_storage: handler.StreamStateStorage,
            request_headers_complete: bool,
            trailer_missing_end_stream: bool,
            request_complete: bool,
            response_writer: ResponseWriter,
            cleaned_up: bool,

            // RFC 9218 extensible priority state.
            priority: Priority,
            priority_update_received: bool,
            schedule_epoch_last: u64,
            schedule_count: u32,

            // Compile-time optimized initialization
            /// Prepares a slot for a new stream.
            ///
            /// Fields are written individually rather than through a whole
            /// struct literal. The literal form stores every field including
            /// the four scratch buffers, and the backend folds the
            /// `undefined` ones into an adjacent zero-fill — measured at 8 KiB
            /// of `bzero` per stream, which is pure waste on the hot path.
            /// The buffers below carry no meaning until their paired length
            /// says otherwise, so they are deliberately left as-is.
            pub fn init(self: *Self.StreamInstance, conn: *Connection, id: u32) void {
                self.id = id;
                self.state = .Idle;
                self.conn = conn;
                self.recv_window_size = @intCast(WindowDefault);
                self.send_window_size = @intCast(WindowDefault);
                self.initial_window_size = WindowDefault;

                // header_block_fragments_buf, headers_bytes_storage,
                // headers_storage, and request_body_storage stay untouched;
                // the lengths below define what is readable.
                self.header_block_fragments_len = 0;
                self.headers_bytes_len = 0;
                self.request_body_len = 0;

                self.expecting_continuation = false;
                self.headers = std.ArrayList(Hpack.HeaderField).initBuffer(&self.headers_storage);
                self.content_length = null;
                self.request_method_bytes = null;
                self.request_method = null;
                self.request_path = null;
                self.total_data_received = 0;
                self.response_body_storage.initInPlace(id);
                self.request_headers_complete = false;
                self.trailer_missing_end_stream = false;
                self.request_complete = false;
                self.response_writer = ResponseWriter.init(&self.header_block_fragments_buf);
                self.cleaned_up = false;
                self.priority = .{};
                self.priority_update_received = false;
                self.schedule_epoch_last = 0;
                self.schedule_count = 0;
            }

            // Optimized cleanup with static memory management
            pub fn deinit(self: *Self.StreamInstance) void {
                // Prevent double-cleanup with compile-time guarantee
                if (self.cleaned_up) {
                    return;
                }

                if (self.expecting_continuation) {
                    self.conn.expecting_continuation_stream_id = null;
                }

                // Static buffers don't need deinitialization, just reset lengths
                self.header_block_fragments_len = 0;
                self.headers_bytes_len = 0;
                self.request_body_len = 0;

                self.response_writer.deinit();
                self.headers.clearRetainingCapacity();
                self.request_method_bytes = null;
                self.request_method = null;
                self.request_path = null;
                self.request_headers_complete = false;
                self.trailer_missing_end_stream = false;
                self.cleaned_up = true;
            }

            // High-performance frame handling with exhaustive switching
            pub fn handleFrame(self: *Self.StreamInstance, frame: Frame) !void {

                // Exhaustive state validation before processing
                const current_state = self.state;

                // Exhaustive frame type validation against current state
                const is_valid_frame = frameAllowed(current_state, frame.header.frame_type);

                if (!is_valid_frame) {
                    log.err(
                        "Invalid frame type {s} for state {s} on stream {d}\n",
                        .{ @tagName(frame.header.frame_type), @tagName(current_state), self.id },
                    );
                    try self.sendRstStream(0x1); // PROTOCOL_ERROR
                    return error.ProtocolError;
                }

                // Exhaustive validation for CONTINUATION expectation
                if (self.expecting_continuation and frame.header.frame_type != .CONTINUATION) {
                    log.err(
                        "Received frame type {s} while expecting CONTINUATION frame: " ++
                            "PROTOCOL_ERROR\n",
                        .{@tagName(frame.header.frame_type)},
                    );
                    try self.conn.send_goaway(
                        0,
                        0x01,
                        "Expected CONTINUATION frame: PROTOCOL_ERROR",
                    );
                    return error.ProtocolError;
                }

                try self.processFrame(frame);

                // State machine driven END_STREAM handling
                const may_end_stream = frame.header.frame_type == .HEADERS or
                    frame.header.frame_type == .DATA;
                if (may_end_stream and frame.header.flags.isEndStream()) {
                    self.state = transitionState(self.state, .RecvEndStream);
                    if (self.state == .Closed) {
                        try self.conn.mark_stream_closed(self.id);
                    }
                }
            }

            fn processFrame(self: *Self.StreamInstance, frame: Frame) !void {
                // Exhaustive frame type processing with no default case
                switch (frame.header.frame_type) {
                    .HEADERS => {
                        try self.handleHeadersFrame(frame);
                        self.state = transitionState(self.state, .RecvHeaders);
                    },
                    .CONTINUATION => {
                        try self.handleContinuationFrame(frame);
                        self.state = transitionState(self.state, .RecvContinuation);
                    },
                    .DATA => {
                        try self.handleData(frame);
                        self.state = transitionState(self.state, .RecvData);
                    },
                    .WINDOW_UPDATE => {
                        try self.handleWindowUpdate(frame);
                        self.state = transitionState(self.state, .RecvWindowUpdate);
                    },
                    .RST_STREAM => {
                        try self.handleRstStream(frame);
                        self.state = transitionState(self.state, .RecvRstStream);
                    },
                    .PRIORITY => {
                        try self.handlePriorityFrame(frame);
                        self.state = transitionState(self.state, .RecvPriority);
                    },
                    // Handle remaining frame types that shouldn't reach stream level
                    .SETTINGS, .PING, .GOAWAY, .PUSH_PROMISE, .PRIORITY_UPDATE => {
                        log.err(
                            "Received connection-level frame type {s} on stream {d}: " ++
                                "PROTOCOL_ERROR\n",
                            .{ @tagName(frame.header.frame_type), self.id },
                        );
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    },
                }
            }

            fn frameAllowed(state: StreamState, frame_type: FrameType) bool {
                return switch (state) {
                    .Idle => frame_type == .HEADERS or frame_type == .PRIORITY,
                    .Open, .HalfClosedLocal => switch (frame_type) {
                        .HEADERS,
                        .DATA,
                        .PRIORITY,
                        .RST_STREAM,
                        .WINDOW_UPDATE,
                        .CONTINUATION,
                        => true,
                        else => false,
                    },
                    .HalfClosedRemote => switch (frame_type) {
                        .WINDOW_UPDATE, .PRIORITY, .RST_STREAM, .CONTINUATION => true,
                        else => false,
                    },
                    .Closed => false,
                    .ReservedLocal, .ReservedRemote => switch (frame_type) {
                        .PRIORITY, .RST_STREAM, .WINDOW_UPDATE => true,
                        else => false,
                    },
                };
            }

            // Compile-time optimized flow control with window size calculations
            pub fn updateSendWindow(self: *Self.StreamInstance, increment: i32) !void {
                assert(increment > 0);

                // Use overflow-aware arithmetic to prevent panic on overflow
                const result = @addWithOverflow(self.send_window_size, increment);
                const new_window = result[0];
                const overflowed = result[1];

                // Check for overflow - this can happen when window exceeds 2^31-1
                if (overflowed != 0 or new_window > protocol.flow_control_window_size_max) {
                    log.err(
                        "Stream {} flow control window overflow: FLOW_CONTROL_ERROR\n",
                        .{self.id},
                    );
                    return error.FlowControlError;
                }

                // SETTINGS_INITIAL_WINDOW_SIZE may make a stream window
                // negative. A WINDOW_UPDATE can legally leave it negative.
                self.send_window_size = new_window;
            }

            /// Low-level single-frame primitive for protocol/client machinery.
            /// It does not enforce HEADERS sequencing or response ownership.
            /// Server handlers must use `ResponseBuilder.stream()` instead.
            pub fn sendDataFrameUnsafe(
                self: *Self.StreamInstance,
                data: []const u8,
                end_stream: bool,
            ) !void {
                switch (self.state) {
                    .Open, .HalfClosedRemote => {},
                    else => return error.InvalidStreamState,
                }

                if (data.len > self.conn.settings.peer_max_frame_size) {
                    return error.FrameSizeError;
                }
                if (data.len > 0) {
                    if (self.send_window_size <= 0) return error.FlowControlError;
                    if (self.conn.send_window_size <= 0) return error.FlowControlError;
                    const stream_window: usize = @intCast(self.send_window_size);
                    const connection_window: usize = @intCast(self.conn.send_window_size);
                    if (data.len > stream_window or data.len > connection_window) {
                        return error.FlowControlError;
                    }
                }

                const frame_flags = if (end_stream)
                    FrameFlags.init(FrameFlags.END_STREAM)
                else
                    FrameFlags.init(0);

                var frame = Frame{
                    .header = FrameHeader{
                        .length = @intCast(data.len),
                        .frame_type = FrameType.DATA,
                        .flags = frame_flags,
                        .reserved = false,
                        .stream_id = self.id,
                    },
                    .payload = data,
                };

                try frame.write(self.conn.writer);
                self.send_window_size -= @intCast(data.len);
                self.conn.send_window_size -= @intCast(data.len);

                if (end_stream) {
                    self.state = transitionState(self.state, .SendEndStream);
                    if (self.state == .Closed) {
                        try self.conn.mark_stream_closed(self.id);
                    }
                }
            }

            pub fn sendRstStream(self: *Self.StreamInstance, error_code: u32) !void {
                const frame_header = FrameHeader{
                    .length = 4,
                    .frame_type = FrameType.RST_STREAM,
                    .flags = FrameFlags.init(0),
                    .reserved = false,
                    .stream_id = self.id,
                };

                var frame_header_mut = frame_header;
                try frame_header_mut.write(self.conn.writer);

                var error_code_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, error_code_bytes[0..4], error_code, .big);
                try self.conn.writer.writeAll(&error_code_bytes);

                self.state = .Closed;
            }

            // Optimized frame handlers with static buffer management
            fn handleHeadersFrame(self: *Self.StreamInstance, frame: Frame) !void {
                if (self.expecting_continuation) {
                    log.err(
                        "Received HEADERS frame while expecting CONTINUATION on " ++
                            "stream {d}: PROTOCOL_ERROR\n",
                        .{self.id},
                    );
                    try self.sendRstStream(0x1); // PROTOCOL_ERROR
                    return error.ProtocolError;
                }

                try self.beginHeaders(frame);

                const hpack_data = field_block.headersFragment(frame) catch |err| {
                    const code: u32 = if (err == error.FrameSizeError) 0x6 else 0x1;
                    try self.conn.send_goaway(self.conn.last_stream_id, code, "Invalid HEADERS");
                    return err;
                };

                // Use static buffer for header block fragments
                if (self.header_block_fragments_len + hpack_data.len > HeaderBufferSize) {
                    log.err("Field block exceeds reassembly capacity: COMPRESSION_ERROR\n", .{});
                    try self.conn.send_goaway(
                        0,
                        0x9,
                        "Field block not decompressed: COMPRESSION_ERROR",
                    );
                    return error.CompressionError;
                }

                const fragment_start = self.header_block_fragments_len;
                @memcpy(
                    self.header_block_fragments_buf[fragment_start..][0..hpack_data.len],
                    hpack_data,
                );
                self.header_block_fragments_len += hpack_data.len;

                if (frame.header.flags.isEndHeaders()) {
                    try self.decodeHeaderBlock();
                    self.header_block_fragments_len = 0; // Reset buffer

                    self.expecting_continuation = false;
                    self.conn.expecting_continuation_stream_id = null;
                } else {
                    self.expecting_continuation = true;
                    self.conn.expecting_continuation_stream_id = self.id;
                }

                if (frame.header.flags.isEndStream() and frame.header.flags.isEndHeaders()) {
                    try self.completeRequest();
                }
            }

            fn beginHeaders(self: *Self.StreamInstance, frame: Frame) !void {
                // Exhaustive state transition validation
                switch (self.state) {
                    .Idle => self.state = .Open,
                    .Open, .HalfClosedLocal => {
                        self.trailer_missing_end_stream = !frame.header.flags.isEndStream();
                    },
                    .HalfClosedRemote => {
                        log.err(
                            "HEADERS frame received on half-closed stream {d}: STREAM_CLOSED\n",
                            .{self.id},
                        );
                        try self.sendRstStream(0x5); // STREAM_CLOSED
                        return error.StreamClosed;
                    },
                    .Closed => {
                        log.err(
                            "HEADERS frame received on closed stream {d}: already " ++
                                "handled by GOAWAY\n",
                            .{self.id},
                        );
                        return error.StreamClosed;
                    },
                    .ReservedLocal, .ReservedRemote => {
                        log.err(
                            "HEADERS frame received in reserved state on stream {d}: " ++
                                "PROTOCOL_ERROR\n",
                            .{self.id},
                        );
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    },
                }
            }

            fn handleContinuationFrame(self: *Self.StreamInstance, frame: Frame) !void {
                if (!self.expecting_continuation) {
                    log.err(
                        "Received unexpected CONTINUATION frame on stream {d}: PROTOCOL_ERROR\n",
                        .{self.id},
                    );
                    try self.conn.send_goaway(
                        0,
                        0x1,
                        "Unexpected CONTINUATION frame: PROTOCOL_ERROR",
                    );
                    return error.ProtocolError;
                }

                // Use static buffer for continuation fragments
                if (self.header_block_fragments_len + frame.payload.len > HeaderBufferSize) {
                    log.err("Field block exceeds reassembly capacity: COMPRESSION_ERROR\n", .{});
                    try self.conn.send_goaway(
                        0,
                        0x9,
                        "Field block not decompressed: COMPRESSION_ERROR",
                    );
                    return error.CompressionError;
                }

                const fragment_start = self.header_block_fragments_len;
                @memcpy(
                    self.header_block_fragments_buf[fragment_start..][0..frame.payload.len],
                    frame.payload,
                );
                self.header_block_fragments_len += frame.payload.len;

                if (frame.header.flags.isEndHeaders()) {
                    try self.decodeHeaderBlock();
                    self.header_block_fragments_len = 0; // Reset buffer

                    self.expecting_continuation = false;
                    self.conn.expecting_continuation_stream_id = null;
                    if (self.state == .HalfClosedRemote) {
                        try self.completeRequest();
                    }
                }
            }

            fn handleData(self: *Self.StreamInstance, frame: Frame) !void {
                // Exhaustive state validation
                switch (self.state) {
                    .Open, .HalfClosedLocal => {},
                    else => return error.InvalidStreamState,
                }

                var payload = frame.payload;
                var pad_length: u8 = 0;

                if (frame.header.flags.has(FrameFlags.PADDED)) {
                    if (payload.len < 1) {
                        return error.ProtocolError;
                    }
                    pad_length = payload[0];
                    payload = payload[1..];

                    if (@as(u32, pad_length) > payload.len) {
                        return error.ProtocolError;
                    }

                    payload = payload[0 .. payload.len - @as(u32, pad_length)];
                }

                self.total_data_received += payload.len;
                if (self.request_body_len + payload.len > self.request_body_storage.len) {
                    try self.sendRstStream(0x2); // INTERNAL_ERROR
                    return error.BufferOverflow;
                }
                const body_start = self.request_body_len;
                const body_end = body_start + payload.len;
                std.mem.copyForwards(
                    u8,
                    self.request_body_storage[body_start..body_end],
                    payload,
                );
                self.request_body_len = body_end;

                // Compile-time optimized flow control
                self.recv_window_size -= @intCast(frame.header.length);
                if (self.recv_window_size < 0) {
                    return error.FlowControlError;
                }

                // Send WINDOW_UPDATE to allow client to send more data
                // This is critical for HTTP/2 flow control
                if (frame.header.length > 0) {
                    try self.conn.send_window_update(self.id, @intCast(frame.header.length));
                    log.debug(
                        "Sent WINDOW_UPDATE for stream {} with increment {}",
                        .{ self.id, frame.header.length },
                    );
                    const restored = @addWithOverflow(
                        self.recv_window_size,
                        @as(i32, @intCast(frame.header.length)),
                    );
                    assert(restored[1] == 0);
                    self.recv_window_size = restored[0];
                }

                if (frame.header.flags.isEndStream()) {
                    try self.completeRequest();
                }
            }

            // RFC 9113 § 8.1.1: a content-length that disagrees with the summed
            // DATA payload lengths is malformed, including when no DATA arrived.
            fn completeRequest(self: *Self.StreamInstance) !void {
                if (self.content_length) |expected_length| {
                    const received: u64 = @intCast(self.total_data_received);
                    if (received != expected_length) {
                        try self.rejectMalformed("content-length disagrees with DATA length");
                    }
                }
                self.request_complete = true;
            }

            fn handleWindowUpdate(self: *Self.StreamInstance, frame: Frame) !void {
                switch (self.state) {
                    .Idle => {
                        log.err(
                            "WINDOW_UPDATE received on idle stream {}: PROTOCOL_ERROR\n",
                            .{self.id},
                        );
                        return error.ProtocolError;
                    },
                    .Closed => {
                        log.debug(
                            "WINDOW_UPDATE received on closed stream {}: ignoring\n",
                            .{self.id},
                        );
                        return;
                    },
                    else => {},
                }

                if (frame.payload.len != 4) {
                    log.err(
                        "WINDOW_UPDATE frame with invalid payload length {} " ++
                            "(expected 4): FRAME_SIZE_ERROR\n",
                        .{frame.payload.len},
                    );
                    return error.FrameSizeError;
                }

                const increment =
                    std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFFFFFF;

                if (increment == 0) {
                    log.err(
                        "WINDOW_UPDATE received with increment 0 on stream {}: PROTOCOL_ERROR\n",
                        .{self.id},
                    );
                    try self.sendRstStream(0x1);
                    return;
                }

                self.updateSendWindow(@intCast(increment)) catch |err| {
                    if (err != error.FlowControlError) return err;
                    try self.sendRstStream(0x3);
                };
            }

            fn handleRstStream(self: *Self.StreamInstance, frame: Frame) !void {
                if (frame.payload.len != 4) {
                    log.err(
                        "RST_STREAM frame has invalid payload length: {d} (expected 4)\n",
                        .{frame.payload.len},
                    );
                    return error.FrameSizeError;
                }

                // Exhaustive state validation
                switch (self.state) {
                    .Idle => {
                        log.err("RST_STREAM received on idle stream {d}\n", .{self.id});
                        return error.IdleStreamError;
                    },
                    else => {},
                }

                const error_code = std.mem.readInt(u32, frame.payload[0..4], .big);
                _ = error_code; // Acknowledge we read it but don't need to log

                self.state = .Closed;
                try self.conn.mark_stream_closed(self.id);
            }

            fn handlePriorityFrame(self: *Self.StreamInstance, frame: Frame) !void {
                if (frame.payload.len != 5) {
                    log.err(
                        "PRIORITY frame with invalid payload length {} (expected 5): " ++
                            "FRAME_SIZE_ERROR\n",
                        .{frame.payload.len},
                    );
                    try self.conn.send_goaway(
                        0,
                        0x6,
                        "PRIORITY frame with invalid payload length: FRAME_SIZE_ERROR",
                    );
                    return error.FrameSizeError;
                }

                // RFC 9113 § 6.3: PRIORITY is deprecated and affects no stream state, so the
                // payload is discarded. RFC 7540 § 5.3.1's self-dependency error is not kept.
            }

            fn decodeHeaderBlock(self: *Self.StreamInstance) !void {
                var pseudo_headers = RequestPseudoHeaders{};
                var priority_header_seen = false;

                if (!self.request_headers_complete) {
                    self.headers.clearRetainingCapacity();
                    self.headers_bytes_len = 0;
                }

                if (try self.decodeHeaderFields(&pseudo_headers, &priority_header_seen)) |reason| {
                    if (self.request_headers_complete) {
                        try self.rejectMalformedTrailer(reason);
                    }
                    try self.rejectMalformed(reason);
                }

                if (self.request_headers_complete) {
                    return;
                }
                self.normalizeCookieFields(&pseudo_headers);
                if (self.finishRequestHeaders(&pseudo_headers, priority_header_seen)) |reason| {
                    try self.rejectMalformed(reason);
                }
            }

            const HeaderOffsets = struct {
                name_start: usize,
                name_end: usize,
                value_start: usize,
                value_end: usize,
            };

            /// RFC 9113 § 8.2.3 requires split Cookie fields to be joined with
            /// "; " before a generic server application sees them. Reuse the
            /// consumed HPACK block buffer as bounded scratch storage.
            fn normalizeCookieFields(
                self: *Self.StreamInstance,
                pseudo_headers: *RequestPseudoHeaders,
            ) void {
                var cookie_count: u8 = 0;
                for (self.headers.items) |header| {
                    if (std.mem.eql(u8, header.name, "cookie")) cookie_count += 1;
                }
                if (cookie_count <= 1) return;

                var offsets: [HeaderCountMax]HeaderOffsets = undefined;
                var output_count: usize = 0;
                var output_len: usize = 0;
                var cookie_written = false;

                for (self.headers.items) |header| {
                    const is_cookie = std.mem.eql(u8, header.name, "cookie");
                    if (is_cookie and cookie_written) continue;

                    const name_start = output_len;
                    const name_end = name_start + header.name.len;
                    assert(name_end <= self.header_block_fragments_buf.len);
                    @memcpy(self.header_block_fragments_buf[name_start..name_end], header.name);
                    output_len = name_end;

                    const value_start = output_len;
                    if (is_cookie) {
                        output_len = self.appendCookieValues(output_len, cookie_count);
                        cookie_written = true;
                    } else {
                        const value_end = output_len + header.value.len;
                        assert(value_end <= self.header_block_fragments_buf.len);
                        @memcpy(
                            self.header_block_fragments_buf[output_len..value_end],
                            header.value,
                        );
                        output_len = value_end;
                    }

                    assert(output_count < offsets.len);
                    offsets[output_count] = .{
                        .name_start = name_start,
                        .name_end = name_end,
                        .value_start = value_start,
                        .value_end = output_len,
                    };
                    output_count += 1;
                }

                // Removing each duplicate six-byte name pays for the two-byte
                // delimiter, so normalization cannot expand the stored block.
                assert(output_len <= self.headers_bytes_len);
                @memcpy(
                    self.headers_bytes_storage[0..output_len],
                    self.header_block_fragments_buf[0..output_len],
                );
                self.headers.items.len = output_count;
                self.headers_bytes_len = output_len;

                for (self.headers.items, offsets[0..output_count]) |*header, offset| {
                    header.* = .{
                        .name = self.headers_bytes_storage[offset.name_start..offset.name_end],
                        .value = self.headers_bytes_storage[offset.value_start..offset.value_end],
                    };
                    if (header.name[0] == ':') {
                        if (pseudo_headers.slot(header.name)) |slot| slot.* = header.value;
                    }
                }
            }

            fn appendCookieValues(
                self: *Self.StreamInstance,
                start: usize,
                cookie_count: u8,
            ) usize {
                var output_len = start;
                var value_count: u8 = 0;
                for (self.headers.items) |candidate| {
                    if (!std.mem.eql(u8, candidate.name, "cookie")) continue;
                    if (value_count > 0) {
                        assert(output_len + 2 <= self.header_block_fragments_buf.len);
                        @memcpy(
                            self.header_block_fragments_buf[output_len .. output_len + 2],
                            "; ",
                        );
                        output_len += 2;
                    }
                    const value_end = output_len + candidate.value.len;
                    assert(value_end <= self.header_block_fragments_buf.len);
                    @memcpy(
                        self.header_block_fragments_buf[output_len..value_end],
                        candidate.value,
                    );
                    output_len = value_end;
                    value_count += 1;
                }
                assert(value_count == cookie_count);
                return output_len;
            }

            /// Decode the whole block even once malformed, because RFC 9113 § 4.3 shares the
            /// HPACK table with the peer; only validating and storing stop at the fault.
            fn decodeHeaderFields(
                self: *Self.StreamInstance,
                pseudo_headers: *RequestPseudoHeaders,
                priority_header_seen: *bool,
            ) !MalformedReason {
                const header_block =
                    self.header_block_fragments_buf[0..self.header_block_fragments_len];
                var cursor: usize = 0;
                var saw_header_field = false;
                var malformed: MalformedReason = if (self.trailer_missing_end_stream)
                    "Trailer section omitted END_STREAM"
                else
                    null;
                var header_list_refused = false;

                while (cursor < header_block.len) {
                    const decoded_header = Hpack.decodeHeaderFieldView(
                        header_block[cursor..],
                        &self.conn.hpack_decoder_table,
                    ) catch |err| {
                        log.debug("Header decompression failed: {}\n", .{err});
                        try self.conn.send_goaway(0, 0x09, "Compression Error: COMPRESSION_ERROR");
                        return error.CompressionError;
                    };
                    assert(decoded_header.bytes_consumed > 0);
                    cursor += decoded_header.bytes_consumed;
                    assert(cursor <= header_block.len);
                    const header = switch (decoded_header.representation) {
                        .field => |value| value,
                        .table_size_update => {
                            if (!saw_header_field) continue;
                            try self.conn.send_goaway(0, 0x09, "Late HPACK size update");
                            return error.CompressionError;
                        },
                    };
                    saw_header_field = true;

                    if (malformed != null or header_list_refused) continue;

                    malformed = if (self.request_headers_complete)
                        validateTrailerHeader(header)
                    else request: {
                        break :request self.validateRequestHeader(
                            header,
                            pseudo_headers,
                            priority_header_seen,
                        ) catch {
                            header_list_refused = true;
                            continue;
                        };
                    };
                    if (malformed != null) continue;

                    if (!self.request_headers_complete and self.shouldStoreRequestHeaders()) {
                        self.storeHeader(header) catch |err| switch (err) {
                            error.HeadersTooLarge, error.TooManyHeaders => {
                                header_list_refused = true;
                                continue;
                            },
                        };
                    }
                }

                if (header_list_refused) {
                    try self.sendRstStream(0x0b); // ENHANCE_YOUR_CALM
                    return error.HeaderListTooLarge;
                }

                return malformed;
            }

            fn storeHeader(self: *Self.StreamInstance, header: Hpack.HeaderField) !void {
                if (self.headers.items.len >= self.headers.capacity) {
                    log.debug("Too many request fields for bounded storage\n", .{});
                    return error.TooManyHeaders;
                }

                const total_len = header.name.len + header.value.len;
                if (self.headers_bytes_len + total_len > self.headers_bytes_storage.len) {
                    return error.HeadersTooLarge;
                }

                const name_start = self.headers_bytes_len;
                const name_end = name_start + header.name.len;
                const value_start = name_end;
                const value_end = value_start + header.value.len;

                std.mem.copyForwards(
                    u8,
                    self.headers_bytes_storage[name_start..name_end],
                    header.name,
                );
                std.mem.copyForwards(
                    u8,
                    self.headers_bytes_storage[value_start..value_end],
                    header.value,
                );
                self.headers_bytes_len = value_end;

                self.headers.appendAssumeCapacity(.{
                    .name = self.headers_bytes_storage[name_start..name_end],
                    .value = self.headers_bytes_storage[value_start..value_end],
                });
            }

            fn shouldStoreRequestHeaders(self: *const Self.StreamInstance) bool {
                const request_dispatcher = self.conn.request_dispatcher orelse return true;
                return request_dispatcher.needs_headers;
            }

            const RequestPseudoHeaders = struct {
                method: ?[]const u8 = null,
                scheme: ?[]const u8 = null,
                authority: ?[]const u8 = null,
                path: ?[]const u8 = null,
                regular_header_seen: bool = false,

                fn add(self: *@This(), header: Hpack.HeaderField) !void {
                    if (self.regular_header_seen) {
                        return error.ProtocolError;
                    }

                    const target = self.slot(header.name) orelse return error.ProtocolError;
                    if (target.* != null) {
                        return error.ProtocolError;
                    }

                    target.* = header.value;
                }

                fn markRegularHeader(self: *@This()) void {
                    self.regular_header_seen = true;
                }

                fn validateRequest(self: *const @This()) !void {
                    const method = self.method orelse return error.ProtocolError;
                    if (method.len == 0) return error.ProtocolError;

                    // RFC 9113 § 8.5: CONNECT carries ":authority" alone, an authority-form target
                    // with no userinfo; ":scheme" and ":path" MUST be omitted.
                    if (self.isConnect()) {
                        if (self.scheme != null) return error.ProtocolError;
                        if (self.path != null) return error.ProtocolError;
                        const authority = self.authority orelse return error.ProtocolError;
                        if (!field.connectAuthorityIsValid(authority)) return error.ProtocolError;
                        return;
                    }

                    const scheme = self.scheme orelse return error.ProtocolError;
                    if (scheme.len == 0) return error.ProtocolError;

                    const path_value = self.path orelse return error.ProtocolError;
                    if (!field.pathIsValid(scheme, method, path_value)) {
                        return error.ProtocolError;
                    }

                    try self.validateAuthority(scheme);
                }

                /// RFC 9113 § 8.3.1: no userinfo in ":authority" for http and https. Other
                /// schemes arrive through a gateway that owns its own URI rules.
                fn validateAuthority(self: *const @This(), scheme: []const u8) !void {
                    const authority = self.authority orelse return;
                    if (!field.schemeIsHttp(scheme)) return;
                    if (!field.authorityIsValid(authority, false)) return error.ProtocolError;
                }

                fn isConnect(self: *const @This()) bool {
                    const method = self.method orelse return false;
                    return std.mem.eql(u8, method, "CONNECT");
                }

                fn slot(self: *@This(), name: []const u8) ?*?[]const u8 {
                    if (std.mem.eql(u8, name, ":method")) return &self.method;
                    if (std.mem.eql(u8, name, ":scheme")) return &self.scheme;
                    if (std.mem.eql(u8, name, ":authority")) return &self.authority;
                    if (std.mem.eql(u8, name, ":path")) return &self.path;
                    return null;
                }
            };

            /// Run request validation over an already-decoded header list, mirroring the
            /// verdict handling in `decodeHeaderBlock` without building an HPACK block.
            fn validateHeaders(
                self: *Self.StreamInstance,
                headers: []const Hpack.HeaderField,
            ) !void {
                var pseudo_headers = RequestPseudoHeaders{};
                var priority_header_seen = false;

                for (headers) |header| {
                    const reason = try self.validateRequestHeader(
                        header,
                        &pseudo_headers,
                        &priority_header_seen,
                    );
                    if (reason) |value| {
                        try self.rejectMalformed(value);
                    }
                }

                if (self.finishRequestHeaders(&pseudo_headers, priority_header_seen)) |reason| {
                    try self.rejectMalformed(reason);
                }
            }

            /// Returns why the message is malformed, or null. Reporting rather than raising
            /// is what lets `decodeHeaderFields` finish the block first; see the note there.
            fn validateRequestHeader(
                self: *Self.StreamInstance,
                header: Hpack.HeaderField,
                pseudo_headers: *RequestPseudoHeaders,
                priority_header_seen: *bool,
            ) !MalformedReason {
                if (header.name.len == 0) {
                    return "Empty header name";
                }

                if (header.name[0] == ':') {
                    return self.validatePseudoHeader(header, pseudo_headers);
                }

                if (!field.nameIsValid(header.name)) {
                    return "Invalid field name";
                }
                if (!field.valueIsValid(header.value)) {
                    return "Invalid field value";
                }

                pseudo_headers.markRegularHeader();
                if (validateRegularHeader(header)) |reason| {
                    return reason;
                }
                if (validateHostHeader(header, pseudo_headers)) |reason| {
                    return reason;
                }
                if (self.validateContentLength(header)) |reason| {
                    return reason;
                }
                if (self.applyPriorityHeader(header)) {
                    priority_header_seen.* = true;
                }
                return null;
            }

            fn validatePseudoHeader(
                self: *Self.StreamInstance,
                header: Hpack.HeaderField,
                pseudo_headers: *RequestPseudoHeaders,
            ) !MalformedReason {
                if (!field.pseudoNameIsValid(header.name)) {
                    return "Invalid pseudo-header field name";
                }
                if (!field.pseudoValueIsValid(header.value)) {
                    return "Invalid pseudo-header field value";
                }

                const value_stable = try self.storeHeaderValue(header.value);
                pseudo_headers.add(.{
                    .name = header.name,
                    .value = value_stable,
                }) catch {
                    return "Invalid pseudo-header field";
                };
                return null;
            }

            /// RFC 9113 § 8.3.1: Host must identify the same entity as ":authority". Pseudo-
            /// headers precede regular ones, so no Host value is retained for a second pass.
            fn validateHostHeader(
                header: Hpack.HeaderField,
                pseudo_headers: *const RequestPseudoHeaders,
            ) MalformedReason {
                if (!std.mem.eql(u8, header.name, "host")) {
                    return null;
                }

                const authority = pseudo_headers.authority orelse return null;
                const scheme = pseudo_headers.scheme orelse "";
                if (field.authorityMatchesHost(scheme, authority, header.value)) {
                    return null;
                }
                return "Host header field disagrees with :authority";
            }

            fn storeHeaderValue(
                self: *Self.StreamInstance,
                value: []const u8,
            ) ![]const u8 {
                if (self.headers_bytes_len + value.len > self.headers_bytes_storage.len) {
                    return error.HeadersTooLarge;
                }

                const start = self.headers_bytes_len;
                const end = start + value.len;
                std.mem.copyForwards(u8, self.headers_bytes_storage[start..end], value);
                self.headers_bytes_len = end;
                return self.headers_bytes_storage[start..end];
            }

            fn finishRequestHeaders(
                self: *Self.StreamInstance,
                pseudo_headers: *const RequestPseudoHeaders,
                priority_header_seen: bool,
            ) MalformedReason {
                pseudo_headers.validateRequest() catch {
                    return "Invalid request pseudo-header fields";
                };
                self.request_method_bytes = pseudo_headers.method;
                self.request_method = handler.Method.fromBytes(pseudo_headers.method.?);
                self.request_path = pseudo_headers.path;
                self.request_headers_complete = true;
                self.applyDefaultRequestPriority(
                    pseudo_headers,
                    priority_header_seen,
                );
                return null;
            }

            fn validateRegularHeader(header: Hpack.HeaderField) MalformedReason {
                if (isConnectionSpecificHeader(header.name)) {
                    return "Connection-specific header field";
                }

                if (std.mem.eql(u8, header.name, "te")) {
                    if (!std.mem.eql(u8, header.value, "trailers")) {
                        return "Invalid TE header field value";
                    }
                }
                return null;
            }

            fn validateContentLength(
                self: *Self.StreamInstance,
                header: Hpack.HeaderField,
            ) MalformedReason {
                if (!std.mem.eql(u8, header.name, "content-length")) {
                    return null;
                }

                // RFC 9110 § 8.6 allows one content-length per message; a repeat
                // is how a disagreeing length gets smuggled in.
                if (self.content_length != null) {
                    return "Duplicate content-length header field";
                }

                const content_length = field.parseContentLength(header.value) orelse {
                    return "Invalid content-length header field";
                };
                self.content_length = content_length;
                assert(self.content_length != null);
                return null;
            }

            fn validateTrailerHeader(header: Hpack.HeaderField) MalformedReason {
                if (header.name.len == 0) {
                    return "Empty trailer header name";
                }
                if (header.name[0] == ':') {
                    return "Pseudo-header field in trailers";
                }
                if (!field.nameIsValid(header.name)) {
                    return "Invalid trailer field name";
                }
                if (!field.valueIsValid(header.value)) {
                    return "Invalid trailer field value";
                }

                if (std.mem.eql(u8, header.name, "content-length")) {
                    return "content-length in trailer section";
                }
                return validateRegularHeader(header);
            }

            /// RFC 9113 § 8.1.1 requires a PROTOCOL_ERROR stream error, § 8.2.1 a 400 first.
            /// Debug, not error: every field reaches here, so `err` would be a log-flood.
            fn rejectMalformed(self: *Self.StreamInstance, reason: []const u8) !noreturn {
                assert(reason.len > 0);
                log.debug("{s}: PROTOCOL_ERROR\n", .{reason});
                self.sendBadRequest() catch |err| {
                    log.debug("Stream {d} could not send 400: {s}\n", .{
                        self.id,
                        @errorName(err),
                    });
                };
                try self.sendRstStream(0x1);
                assert(self.state == .Closed);
                return error.MalformedRequest;
            }

            /// A malformed trailer cannot be answered with a new 400 response;
            /// RFC 9113 § 8.1.1 requires the stream error on its own.
            fn rejectMalformedTrailer(self: *Self.StreamInstance, reason: []const u8) !noreturn {
                assert(reason.len > 0);
                log.debug("{s}: PROTOCOL_ERROR\n", .{reason});
                try self.sendRstStream(0x1);
                assert(self.state == .Closed);
                return error.MalformedRequest;
            }

            /// Answer with 400 per RFC 9113 § 8.2.1, unless a response is already under way
            /// — the trailer case the RFC names. Those get the stream error alone.
            fn sendBadRequest(self: *Self.StreamInstance) !void {
                if (self.response_writer.isPrepared()) return;
                if (self.response_writer.response_headers_sent) return;
                if (self.state == .Closed) return;

                var block_storage: [bad_request_block_bytes]u8 = undefined;
                var block = std.ArrayList(u8).initBuffer(&block_storage);
                try Hpack.encodeHeaderField(
                    .{ .name = ":status", .value = "400" },
                    &self.conn.hpack_encoder_table,
                    &block,
                );
                assert(block.items.len > 0);
                assert(block.items.len <= bad_request_block_bytes);

                var frame_header = FrameHeader{
                    .length = @intCast(block.items.len),
                    .frame_type = FrameType.HEADERS,
                    .flags = FrameFlags.init(FrameFlags.END_HEADERS | FrameFlags.END_STREAM),
                    .reserved = false,
                    .stream_id = self.id,
                };
                try frame_header.write(self.conn.writer);
                try self.conn.writer.writeAll(block.items);

                // The response is complete, so no later dispatch may add to it.
                self.response_writer.response_headers_sent = true;
            }

            pub fn applyPriority(self: *Self.StreamInstance, priority: Priority) void {
                assert(priority.urgency <= 7);

                self.priority = priority;
                self.priority_update_received = true;
            }

            fn applyPriorityHeader(
                self: *Self.StreamInstance,
                header: Hpack.HeaderField,
            ) bool {
                if (!std.mem.eql(u8, header.name, "priority")) {
                    return false;
                }
                if (self.priority_update_received) {
                    return true;
                }

                const priority = Priority.parse(header.value) catch {
                    log.debug("Ignoring malformed Priority header on stream {d}\n", .{self.id});
                    return true;
                };
                self.priority = priority;
                return true;
            }

            fn applyDefaultRequestPriority(
                self: *Self.StreamInstance,
                pseudo_headers: *const RequestPseudoHeaders,
                priority_header_seen: bool,
            ) void {
                if (self.priority_update_received) {
                    return;
                }
                if (priority_header_seen) {
                    return;
                }
                if (!pseudo_headers.isConnect()) {
                    return;
                }

                self.priority.incremental = true;
            }
        };
    };
}

// Utility functions for header validation
fn isConnectionSpecificHeader(header_name: []const u8) bool {
    const prohibited_headers = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    };

    for (prohibited_headers) |prohibited| {
        if (std.mem.eql(u8, header_name, prohibited)) {
            return true;
        }
    }
    return false;
}

pub const DefaultStream = Stream(
    16,
    @intCast(memory_budget.MemBudget.max_streams_per_connection),
);

comptime {
    const Instance = DefaultStream.StreamInstance;
    const Budget = memory_budget.MemBudget;
    const fields = @typeInfo(Instance).@"struct".fields;
    var found_header_fragments: bool = false;
    var found_headers_storage: bool = false;
    var found_request_body: bool = false;
    var found_response_body: bool = false;
    var found_headers_array: bool = false;
    for (fields) |struct_field| {
        if (std.mem.eql(u8, struct_field.name, "header_block_fragments_buf")) {
            found_header_fragments = true;
            if (@sizeOf(struct_field.type) != Budget.stream_header_fragments_bytes) {
                @compileError("stream_header_fragments_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, struct_field.name, "headers_bytes_storage")) {
            found_headers_storage = true;
            if (@sizeOf(struct_field.type) != Budget.stream_headers_storage_bytes) {
                @compileError("stream_headers_storage_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, struct_field.name, "request_body_storage")) {
            found_request_body = true;
            if (@sizeOf(struct_field.type) != Budget.stream_request_body_bytes) {
                @compileError("stream_request_body_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, struct_field.name, "response_body_storage")) {
            found_response_body = true;
            if (@sizeOf(struct_field.type) != Budget.stream_response_body_bytes) {
                @compileError("stream_response_body_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, struct_field.name, "headers_storage")) {
            found_headers_array = true;
            if (@sizeOf(struct_field.type) != Budget.stream_headers_array_bytes) {
                @compileError("stream_headers_array_bytes budget mismatch");
            }
        }
    }
    if (!found_header_fragments) @compileError("Missing field: header_block_fragments_buf");
    if (!found_headers_storage) @compileError("Missing field: headers_bytes_storage");
    if (!found_request_body) @compileError("Missing field: request_body_storage");
    if (!found_response_body) @compileError("Missing field: response_body_storage");
    if (!found_headers_array) @compileError("Missing field: headers_storage");
}

test "compile-time stream configuration" {
    // Test different configurations compile successfully
    const SmallStream = Stream(16, 100); // 64KB window, 100 streams
    const LargeStream = Stream(20, 10000); // 1MB window, 10000 streams

    // These should compile successfully showing the generic works
    _ = SmallStream;
    _ = LargeStream;
}

test "state machine transitions" {
    // Test state machine functionality
    try std.testing.expectEqual(StreamState.Open, transitionState(.Idle, .RecvHeaders));
    try std.testing.expectEqual(
        StreamState.HalfClosedRemote,
        transitionState(.Open, .RecvEndStream),
    );
    try std.testing.expectEqual(
        StreamState.Closed,
        transitionState(.HalfClosedLocal, .RecvEndStream),
    );
}

test "CONNECT defaults request priority to incremental" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);

    var connection = try Connection.initOwnedForTesting(
        arena.allocator(),
        &test_io.reader,
        &test_io.writer,
        .client,
    );
    const stream = try connection.get_stream(1);

    const headers = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    };

    try stream.validateHeaders(&headers);
    try std.testing.expect(stream.priority.incremental);
    try std.testing.expectEqual(@as(u8, 3), stream.priority.urgency);
}

test "CONNECT priority header overrides default incremental behavior" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);

    var connection = try Connection.initOwnedForTesting(
        arena.allocator(),
        &test_io.reader,
        &test_io.writer,
        .client,
    );
    const stream = try connection.get_stream(1);

    const headers = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = "priority", .value = "u=1" },
    };

    try stream.validateHeaders(&headers);
    try std.testing.expectEqual(@as(u8, 1), stream.priority.urgency);
    try std.testing.expect(!stream.priority.incremental);
}

/// Validate `headers` and hand back what the stream wrote. Each case needs its
/// own connection, since validation records state that would decide the next.
fn validateHeadersForTesting(headers: []const Hpack.HeaderField) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);

    var connection = try Connection.initOwnedForTesting(
        arena.allocator(),
        &test_io.reader,
        &test_io.writer,
        .client,
    );
    const stream = try connection.get_stream(1);
    try stream.validateHeaders(headers);
}

fn expectHeadersMalformed(headers: []const Hpack.HeaderField) !void {
    try std.testing.expectError(
        error.MalformedRequest,
        validateHeadersForTesting(headers),
    );
}

test "RFC 9113 8.2.1 rejects invalid field names" {
    const base = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    const invalid_names = [_][]const u8{
        "Content-Length",
        "content length",
        "content:length",
        "content\x00length",
        "content\rlength",
        "content\x7flength",
        "content\xfflength",
        "(comment)",
    };

    for (invalid_names) |name| {
        const headers = base ++ [_]Hpack.HeaderField{.{ .name = name, .value = "x" }};
        try expectHeadersMalformed(&headers);
    }
}

test "RFC 9113 8.2.1 rejects invalid field values" {
    const base = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    const invalid_values = [_][]const u8{
        "has\x00nul",
        "has\rcr",
        "has\nlf",
        "has\x7fdel",
        " leading",
        "trailing ",
        "\ttab",
    };

    for (invalid_values) |value| {
        const headers = base ++ [_]Hpack.HeaderField{.{ .name = "x-test", .value = value }};
        try expectHeadersMalformed(&headers);
    }

    const valid = base ++ [_]Hpack.HeaderField{
        .{ .name = "x-test", .value = "one two" },
    };
    try validateHeadersForTesting(&valid);
}

test "RFC 9113 8.2.1 validates pseudo-header names and values" {
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index\r\nx: y" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/a b" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = "::method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":Method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    });
}

test "RFC 9113 8.3.1 requires Host to agree with :authority" {
    try validateHeadersForTesting(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "host", .value = "example.com" },
    });
    // A port equal to the scheme default normalizes away (RFC 3986 § 6.2.3).
    try validateHeadersForTesting(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "Example.COM:443" },
        .{ .name = "host", .value = "example.com" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "host", .value = "evil.test" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com:8443" },
        .{ .name = "host", .value = "example.com" },
    });
}

test "RFC 9113 8.3.1 rejects userinfo in :authority" {
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com@evil.test" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "user@example.com:443" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com/path" },
    });
}

test "RFC 9113 8.5 requires CONNECT authority-form host and port" {
    try validateHeadersForTesting(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    });
    try validateHeadersForTesting(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "[::1]:8443" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:https" },
    });
}

test "RFC 9113 8.3.1 constrains the :path form for http and https" {
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "index.html" },
    });
    try expectHeadersMalformed(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "*" },
    });
    try validateHeadersForTesting(&[_]Hpack.HeaderField{
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "*" },
    });
}

test "RFC 9113 8.1.1 constrains content-length to a single 1*DIGIT value" {
    const base = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    const invalid_lengths = [_][]const u8{ "+5", "-5", "1_0", "0x10", "", "five" };

    for (invalid_lengths) |value| {
        const headers = base ++ [_]Hpack.HeaderField{
            .{ .name = "content-length", .value = value },
        };
        try expectHeadersMalformed(&headers);
    }

    // A second content-length is how a disagreeing length gets smuggled in,
    // even when both spellings parse.
    const duplicated = base ++ [_]Hpack.HeaderField{
        .{ .name = "content-length", .value = "5" },
        .{ .name = "content-length", .value = "5" },
    };
    try expectHeadersMalformed(&duplicated);

    const accepted = base ++ [_]Hpack.HeaderField{
        .{ .name = "content-length", .value = "5" },
    };
    try validateHeadersForTesting(&accepted);
}

/// Run request validation and hand back everything the stream wrote in reply,
/// so a test can assert on frames rather than only on the returned error.
fn validateHeadersCapturingOutput(
    headers: []const Hpack.HeaderField,
    write_buffer: []u8,
    written_out: *usize,
) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var test_io = TestIo.init(&.{}, write_buffer);
    var connection = try Connection.initOwnedForTesting(
        arena.allocator(),
        &test_io.reader,
        &test_io.writer,
        .client,
    );
    const stream = try connection.get_stream(1);

    // Discard the preface and SETTINGS the connection sends on init, so the
    // buffer holds only what rejecting this request produced.
    test_io.resetWriter(write_buffer);

    defer written_out.* = test_io.written().len;
    try stream.validateHeaders(headers);
}

test "RFC 9113 8.2.1 answers a malformed request with 400 before the stream error" {
    var write_buffer: [1024]u8 = undefined;
    var written_len: usize = 0;
    try std.testing.expectError(error.MalformedRequest, validateHeadersCapturingOutput(
        &[_]Hpack.HeaderField{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = "Bad-Name", .value = "x" },
        },
        &write_buffer,
        &written_len,
    ));

    const written = write_buffer[0..written_len];
    var frame_reader: std.Io.Reader = .fixed(written);
    const headers_frame = try FrameHeader.read(&frame_reader);
    try std.testing.expectEqual(FrameType.HEADERS, headers_frame.frame_type);
    try std.testing.expectEqual(@as(u32, 1), headers_frame.stream_id);
    try std.testing.expect(headers_frame.flags.isEndHeaders());
    try std.testing.expect(headers_frame.flags.isEndStream());

    // ":status: 400" is entry 12 of the HPACK static table.
    const status_block = written[9 .. 9 + headers_frame.length];
    try std.testing.expectEqualSlices(u8, &[_]u8{0x8c}, status_block);

    const reset_offset = 9 + headers_frame.length;
    var reset_reader: std.Io.Reader = .fixed(written[reset_offset..]);
    const reset_frame = try FrameHeader.read(&reset_reader);
    try std.testing.expectEqual(FrameType.RST_STREAM, reset_frame.frame_type);
    try std.testing.expectEqual(@as(u32, 1), reset_frame.stream_id);

    const error_code = std.mem.readInt(u32, written[reset_offset + 9 ..][0..4], .big);
    try std.testing.expectEqual(@as(u32, 0x1), error_code); // PROTOCOL_ERROR
}

test "RFC 9113 4.3 keeps the HPACK table in sync across a malformed field block" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var write_buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &write_buffer);
    var connection = try Connection.initOwnedForTesting(
        allocator,
        &test_io.reader,
        &test_io.writer,
        .client,
    );

    // The second field is malformed and the third still adds a table entry. Stopping
    // at the fault would leave the decoder table disagreeing with the encoder.
    var encoder_table = Hpack.DynamicTable.init(protocol.hpack_dynamic_table_size_default);
    defer encoder_table.deinit();
    var block = std.ArrayList(u8).initBuffer(try allocator.alloc(u8, 1024));
    inline for (.{
        .{ ":method", "GET" },
        .{ ":scheme", "https" },
        .{ ":path", "/" },
        .{ "bad name", "x" },
        .{ "x-trailing-entry", "kept" },
    }) |pair| {
        try Hpack.encodeHeaderField(
            .{ .name = pair[0], .value = pair[1] },
            &encoder_table,
            &block,
        );
    }

    const stream = try connection.get_stream(1);
    @memcpy(stream.header_block_fragments_buf[0..block.items.len], block.items);
    stream.header_block_fragments_len = block.items.len;

    try std.testing.expectError(error.MalformedRequest, stream.decodeHeaderBlock());

    // Both tables saw every field, so they agree on size and contents.
    try std.testing.expectEqual(
        encoder_table.current_size,
        connection.hpack_decoder_table.current_size,
    );
    try std.testing.expectEqual(encoder_table.count, connection.hpack_decoder_table.count);
}

test "RFC 9113 8.2.3 joins split Cookie fields for generic handlers" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var write_buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &write_buffer);
    var connection = try Connection.initOwnedForTesting(
        allocator,
        &test_io.reader,
        &test_io.writer,
        .client,
    );
    var encoder_table = Hpack.DynamicTable.init(protocol.hpack_dynamic_table_size_default);
    defer encoder_table.deinit();
    var block = std.ArrayList(u8).initBuffer(try allocator.alloc(u8, 1024));
    inline for (.{
        .{ ":method", "GET" },
        .{ ":scheme", "https" },
        .{ ":path", "/cookies" },
        .{ "cookie", "a=b" },
        .{ "x-between", "kept" },
        .{ "cookie", "c=d" },
    }) |pair| {
        try Hpack.encodeHeaderField(
            .{ .name = pair[0], .value = pair[1] },
            &encoder_table,
            &block,
        );
    }

    const stream = try connection.get_stream(1);
    @memcpy(stream.header_block_fragments_buf[0..block.items.len], block.items);
    stream.header_block_fragments_len = block.items.len;
    try stream.decodeHeaderBlock();

    var cookie_count: u8 = 0;
    for (stream.headers.items) |header| {
        if (!std.mem.eql(u8, header.name, "cookie")) continue;
        cookie_count += 1;
        try std.testing.expectEqualStrings("a=b; c=d", header.value);
    }
    try std.testing.expectEqual(@as(u8, 1), cookie_count);
    try std.testing.expectEqualStrings("GET", stream.request_method_bytes.?);
    try std.testing.expectEqualStrings("/cookies", stream.request_path.?);
}

test "RFC 9113 trailer decoding preserves initial request fields" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var write_buffer: [4096]u8 = undefined;
    var test_io = TestIo.init(&.{}, &write_buffer);
    var connection = try Connection.initOwnedForTesting(
        allocator,
        &test_io.reader,
        &test_io.writer,
        .client,
    );
    var encoder_table = Hpack.DynamicTable.init(protocol.hpack_dynamic_table_size_default);
    defer encoder_table.deinit();
    var initial = std.ArrayList(u8).initBuffer(try allocator.alloc(u8, 1024));
    inline for (.{
        .{ ":method", "POST" },
        .{ ":scheme", "https" },
        .{ ":path", "/upload" },
        .{ "x-original", "kept" },
    }) |pair| {
        try Hpack.encodeHeaderField(
            .{ .name = pair[0], .value = pair[1] },
            &encoder_table,
            &initial,
        );
    }
    var trailers = std.ArrayList(u8).initBuffer(try allocator.alloc(u8, 256));
    try Hpack.encodeHeaderField(
        .{ .name = "x-trailer", .value = "checked" },
        &encoder_table,
        &trailers,
    );

    const stream = try connection.get_stream(1);
    @memcpy(stream.header_block_fragments_buf[0..initial.items.len], initial.items);
    stream.header_block_fragments_len = initial.items.len;
    try stream.decodeHeaderBlock();
    const initial_header_count = stream.headers.items.len;

    @memcpy(stream.header_block_fragments_buf[0..trailers.items.len], trailers.items);
    stream.header_block_fragments_len = trailers.items.len;
    try stream.decodeHeaderBlock();

    try std.testing.expectEqual(initial_header_count, stream.headers.items.len);
    var found_original = false;
    for (stream.headers.items) |header| {
        if (std.mem.eql(u8, header.name, "x-original")) {
            found_original = true;
            try std.testing.expectEqualStrings("kept", header.value);
        }
        try std.testing.expect(!std.mem.eql(u8, header.name, "x-trailer"));
    }
    try std.testing.expect(found_original);
}
