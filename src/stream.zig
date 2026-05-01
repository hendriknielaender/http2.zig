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
const memory_budget = @import("memory_budget.zig");
const TestIo = @import("testing/fixed_io.zig").FixedIo;
const ResponseWriter = @import("response.zig").ResponseWriter;

const log = std.log.scoped(.stream);

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
    table[@intFromEnum(StreamState.Open)][@intFromEnum(StreamEvent.RecvEndStream)] = StreamState.HalfClosedRemote;
    table[@intFromEnum(StreamState.Open)][@intFromEnum(StreamEvent.SendEndStream)] = StreamState.HalfClosedLocal;
    table[@intFromEnum(StreamState.Open)][@intFromEnum(StreamEvent.RecvRstStream)] = StreamState.Closed;
    table[@intFromEnum(StreamState.Open)][@intFromEnum(StreamEvent.SendRstStream)] = StreamState.Closed;

    // From HalfClosedLocal
    table[@intFromEnum(StreamState.HalfClosedLocal)][@intFromEnum(StreamEvent.RecvEndStream)] = StreamState.Closed;
    table[@intFromEnum(StreamState.HalfClosedLocal)][@intFromEnum(StreamEvent.RecvRstStream)] = StreamState.Closed;
    table[@intFromEnum(StreamState.HalfClosedLocal)][@intFromEnum(StreamEvent.SendRstStream)] = StreamState.Closed;

    // From HalfClosedRemote
    table[@intFromEnum(StreamState.HalfClosedRemote)][@intFromEnum(StreamEvent.SendEndStream)] = StreamState.Closed;
    table[@intFromEnum(StreamState.HalfClosedRemote)][@intFromEnum(StreamEvent.RecvRstStream)] = StreamState.Closed;
    table[@intFromEnum(StreamState.HalfClosedRemote)][@intFromEnum(StreamEvent.SendRstStream)] = StreamState.Closed;

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

        // Per-stream scratch the dispatcher can format small response bodies
        // into without touching the heap. 256 bytes covers numeric, status, or
        // short text replies (the hot benchmark path); larger payloads must
        // continue to use the request allocator. Sizing is a compile-time
        // tradeoff between covering the common case and per-connection memory.
        const ResponseBodyStorageSize: usize = 256;

        // Static memory allocation for streams
        const StreamPool = struct {
            streams: [MaxStreamCount]?*Self.StreamInstance = [_]?*Self.StreamInstance{null} ** MaxStreamCount,
            next_free: u32 = 0,

            fn allocate(self: *StreamPool, allocator: std.mem.Allocator) !*Self.StreamInstance {
                if (self.next_free >= MaxStreamCount) return error.StreamPoolExhausted;

                const stream = try allocator.create(Self.StreamInstance);
                self.streams[self.next_free] = stream;
                const index = self.next_free;
                self.next_free += 1;
                return self.streams[index].?;
            }

            fn deallocate(self: *StreamPool, stream: *Self.StreamInstance, allocator: std.mem.Allocator) void {
                for (self.streams[0..self.next_free], 0..) |s, i| {
                    if (s == stream) {
                        allocator.destroy(stream);
                        self.streams[i] = null;
                        // Compact the pool to maintain efficiency
                        if (i == self.next_free - 1) {
                            self.next_free -= 1;
                        }
                        return;
                    }
                }
            }
        };

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
            content_length: ?usize,
            request_method_bytes: ?[]const u8,
            request_method: ?handler.Method,
            request_path: ?[]const u8,
            total_data_received: usize,
            request_body_storage: [memory_budget.MemBudget.max_data_buffer_bytes]u8,
            request_body_len: usize,
            // Scratch the request handler formats small response bodies into,
            // owned by the stream so the body slice on `response` stays valid
            // until the stream slot is released. See `ResponseBodyStorageSize`.
            response_body_storage: [ResponseBodyStorageSize]u8,
            request_headers_complete: bool,
            request_complete: bool,
            response_writer: ResponseWriter,
            cleaned_up: bool,

            // RFC 9218 extensible priority state.
            priority: Priority,
            priority_update_received: bool,
            schedule_epoch_last: u64,
            schedule_count: u32,

            // HTTP/2 priority fields with defaults
            stream_dependency: u32,
            exclusive: bool,
            weight: u16,

            // Compile-time optimized initialization
            pub fn init(self: *Self.StreamInstance, conn: *Connection, id: u32) void {
                self.* = Self.StreamInstance{
                    .id = id,
                    .state = .Idle,
                    .conn = conn,
                    .recv_window_size = @intCast(WindowDefault),
                    .send_window_size = @intCast(WindowDefault),
                    .initial_window_size = WindowDefault,

                    .header_block_fragments_buf = undefined,
                    .headers_bytes_storage = undefined,

                    .header_block_fragments_len = 0,
                    .headers_bytes_len = 0,

                    .expecting_continuation = false,
                    .headers_storage = undefined,
                    .headers = .empty,
                    .content_length = null,
                    .request_method_bytes = null,
                    .request_method = null,
                    .request_path = null,
                    .total_data_received = 0,
                    .request_body_storage = undefined,
                    .request_body_len = 0,
                    .response_body_storage = undefined,
                    .request_headers_complete = false,
                    .request_complete = false,
                    .response_writer = undefined,
                    .cleaned_up = false,
                    .priority = .{},
                    .priority_update_received = false,
                    .schedule_epoch_last = 0,
                    .schedule_count = 0,
                    .stream_dependency = 0,
                    .exclusive = false,
                    .weight = 16,
                };
                self.headers = std.ArrayList(Hpack.HeaderField).initBuffer(&self.headers_storage);
                self.response_writer = ResponseWriter.init(&self.header_block_fragments_buf);
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
                self.cleaned_up = true;
            }

            // High-performance frame handling with exhaustive switching
            pub fn handleFrame(self: *Self.StreamInstance, frame: Frame) !void {

                // Exhaustive state validation before processing
                const current_state = self.state;

                // Exhaustive frame type validation against current state
                const is_valid_frame = switch (current_state) {
                    .Idle => switch (frame.header.frame_type) {
                        .HEADERS, .PRIORITY => true,
                        .DATA,
                        .RST_STREAM,
                        .SETTINGS,
                        .PUSH_PROMISE,
                        .PING,
                        .GOAWAY,
                        .WINDOW_UPDATE,
                        .CONTINUATION,
                        .PRIORITY_UPDATE,
                        => false,
                    },
                    .Open => switch (frame.header.frame_type) {
                        .HEADERS, .DATA, .PRIORITY, .RST_STREAM, .WINDOW_UPDATE, .CONTINUATION => true,
                        .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .PRIORITY_UPDATE => false,
                    },
                    .HalfClosedRemote => switch (frame.header.frame_type) {
                        .WINDOW_UPDATE, .PRIORITY, .RST_STREAM, .CONTINUATION => true,
                        .DATA, .HEADERS, .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .PRIORITY_UPDATE => false,
                    },
                    .HalfClosedLocal => switch (frame.header.frame_type) {
                        .HEADERS, .DATA, .PRIORITY, .RST_STREAM, .WINDOW_UPDATE, .CONTINUATION => true,
                        .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .PRIORITY_UPDATE => false,
                    },
                    .Closed => false, // No frames allowed
                    .ReservedLocal, .ReservedRemote => switch (frame.header.frame_type) {
                        .PRIORITY, .RST_STREAM, .WINDOW_UPDATE => true,
                        .DATA,
                        .HEADERS,
                        .SETTINGS,
                        .PUSH_PROMISE,
                        .PING,
                        .GOAWAY,
                        .CONTINUATION,
                        .PRIORITY_UPDATE,
                        => false,
                    },
                };

                if (!is_valid_frame) {
                    log.err("Invalid frame type {s} for state {s} on stream {d}\n", .{ @tagName(frame.header.frame_type), @tagName(current_state), self.id });
                    try self.sendRstStream(0x1); // PROTOCOL_ERROR
                    return error.ProtocolError;
                }

                // Exhaustive validation for CONTINUATION expectation
                if (self.expecting_continuation and frame.header.frame_type != .CONTINUATION) {
                    log.err("Received frame type {s} while expecting CONTINUATION frame: PROTOCOL_ERROR\n", .{@tagName(frame.header.frame_type)});
                    try self.conn.send_goaway(0, 0x01, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }

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
                        log.err("Received connection-level frame type {s} on stream {d}: PROTOCOL_ERROR\n", .{ @tagName(frame.header.frame_type), self.id });
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    },
                }

                // State machine driven END_STREAM handling
                if (frame.header.flags.isEndStream()) {
                    self.state = transitionState(self.state, .RecvEndStream);
                    if (self.state == .Closed) {
                        try self.conn.mark_stream_closed(self.id);
                    }
                }
            }

            // Compile-time optimized flow control with window size calculations
            pub fn updateSendWindow(self: *Self.StreamInstance, increment: i32) !void {
                assert(increment > 0);

                // Use overflow-aware arithmetic to prevent panic on overflow
                const result = @addWithOverflow(self.send_window_size, increment);
                const new_window = result[0];
                const overflowed = result[1];

                // Check for overflow - this can happen when window exceeds 2^31-1
                if (overflowed != 0 or new_window > 2147483647) {
                    log.err("Stream {} flow control window overflow: FLOW_CONTROL_ERROR\n", .{self.id});
                    try self.sendRstStream(0x3);
                    return error.FlowControlError;
                }
                // Check for underflow (should not happen with positive increment, but be safe)
                if (new_window < 0) {
                    log.err("Stream {} flow control window underflow: {} below 0: FLOW_CONTROL_ERROR\n", .{ self.id, new_window });
                    try self.sendRstStream(0x3);
                    return error.FlowControlError;
                }

                self.send_window_size = new_window;
            }

            // High-performance data sending with static buffers
            pub fn sendData(self: *Self.StreamInstance, data: []const u8, end_stream: bool) !void {
                // Exhaustive state validation
                switch (self.state) {
                    .Open, .HalfClosedRemote => {},
                    else => return error.InvalidStreamState,
                }

                if (self.send_window_size <= 0) {
                    return error.FlowControlError;
                }

                const send_window_size: usize = @intCast(self.send_window_size);
                if (data.len > send_window_size) {
                    return error.FlowControlError;
                }

                self.send_window_size -= @intCast(data.len);

                const frame_flags = if (end_stream) FrameFlags.init(FrameFlags.END_STREAM) else FrameFlags.init(0);

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
                    log.err("Received HEADERS frame while expecting CONTINUATION on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                    try self.sendRstStream(0x1); // PROTOCOL_ERROR
                    return error.ProtocolError;
                }

                // Exhaustive state transition validation
                switch (self.state) {
                    .Idle => self.state = .Open,
                    .Open => {
                        if (!frame.header.flags.isEndStream()) {
                            log.err("Received second HEADERS frame without END_STREAM on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                            try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            return error.ProtocolError;
                        }
                    },
                    .HalfClosedRemote, .HalfClosedLocal => {
                        log.err("HEADERS frame received on half-closed stream {d}: STREAM_CLOSED\n", .{self.id});
                        try self.sendRstStream(0x5); // STREAM_CLOSED
                        return error.StreamClosed;
                    },
                    .Closed => {
                        log.err("HEADERS frame received on closed stream {d}: already handled by GOAWAY\n", .{self.id});
                        return error.StreamClosed;
                    },
                    .ReservedLocal, .ReservedRemote => {
                        log.err("HEADERS frame received in reserved state on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    },
                }

                // Process frame with static buffer management
                var hpack_data = frame.payload;

                // Handle PADDED flag
                if (frame.header.flags.has(FrameFlags.PADDED)) {
                    if (hpack_data.len == 0) {
                        log.err("PADDED HEADERS frame has zero payload length: FRAME_SIZE_ERROR\n", .{});
                        try self.sendRstStream(0x6); // FRAME_SIZE_ERROR
                        return error.FrameSizeError;
                    }

                    const padding_length = hpack_data[0];
                    if (1 + padding_length >= hpack_data.len) {
                        log.err("PADDED HEADERS frame has invalid padding length: FRAME_SIZE_ERROR\n", .{});
                        try self.sendRstStream(0x6); // FRAME_SIZE_ERROR
                        return error.FrameSizeError;
                    }

                    hpack_data = hpack_data[1 .. hpack_data.len - padding_length];
                }

                // Handle PRIORITY flag
                if (frame.header.flags.has(FrameFlags.PRIORITY)) {
                    if (hpack_data.len < 5) {
                        log.err("HEADERS frame with PRIORITY flag has insufficient payload length: FRAME_SIZE_ERROR\n", .{});
                        try self.sendRstStream(0x6); // FRAME_SIZE_ERROR
                        return error.FrameSizeError;
                    }

                    const stream_dependency_raw = std.mem.readInt(u32, hpack_data[0..4], .big);
                    const exclusive = (stream_dependency_raw & 0x80000000) != 0;
                    const stream_dependency = stream_dependency_raw & 0x7FFFFFFF;
                    const weight: u16 = @as(u16, hpack_data[4]) + 1;

                    if (stream_dependency == self.id) {
                        log.err("HEADERS frame with PRIORITY depends on itself (stream {d}): PROTOCOL_ERROR\n", .{self.id});
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    }

                    if (!self.conn.rfc7540_priority_signals_ignored()) {
                        self.stream_dependency = stream_dependency;
                        self.exclusive = exclusive;
                        self.weight = weight;
                    }

                    hpack_data = hpack_data[5..];
                }

                // Use static buffer for header block fragments
                if (self.header_block_fragments_len + hpack_data.len > HeaderBufferSize) {
                    log.err("Header block fragments exceed buffer size: INTERNAL_ERROR\n", .{});
                    try self.sendRstStream(0x2); // INTERNAL_ERROR
                    return error.BufferOverflow;
                }

                @memcpy(self.header_block_fragments_buf[self.header_block_fragments_len .. self.header_block_fragments_len + hpack_data.len], hpack_data);
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
                    self.request_complete = true;
                }
            }

            fn handleContinuationFrame(self: *Self.StreamInstance, frame: Frame) !void {
                if (!self.expecting_continuation) {
                    log.err("Received unexpected CONTINUATION frame on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                    try self.conn.send_goaway(0, 0x1, "Unexpected CONTINUATION frame: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }

                // Use static buffer for continuation fragments
                if (self.header_block_fragments_len + frame.payload.len > HeaderBufferSize) {
                    log.err("Header block fragments exceed buffer size: INTERNAL_ERROR\n", .{});
                    try self.sendRstStream(0x2); // INTERNAL_ERROR
                    return error.BufferOverflow;
                }

                @memcpy(self.header_block_fragments_buf[self.header_block_fragments_len .. self.header_block_fragments_len + frame.payload.len], frame.payload);
                self.header_block_fragments_len += frame.payload.len;

                if (frame.header.flags.isEndHeaders()) {
                    try self.decodeHeaderBlock();
                    self.header_block_fragments_len = 0; // Reset buffer

                    self.expecting_continuation = false;
                    self.conn.expecting_continuation_stream_id = null;
                    if (self.state == .HalfClosedRemote) {
                        self.request_complete = true;
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
                    log.debug("Sent WINDOW_UPDATE for stream {} with increment {}", .{ self.id, frame.header.length });
                }

                if (frame.header.flags.isEndStream()) {
                    if (self.content_length) |expected_length| {
                        if (self.total_data_received != expected_length) {
                            log.err("Received data length ({d}) does not match content-length ({d}): PROTOCOL_ERROR\n", .{ self.total_data_received, expected_length });
                            try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            return error.ProtocolError;
                        }
                    }
                    self.request_complete = true;
                }
            }

            fn handleWindowUpdate(self: *Self.StreamInstance, frame: Frame) !void {
                switch (self.state) {
                    .Idle => {
                        log.err("WINDOW_UPDATE received on idle stream {}: PROTOCOL_ERROR\n", .{self.id});
                        try self.sendRstStream(0x1);
                        return error.ProtocolError;
                    },
                    .Closed => {
                        log.debug("WINDOW_UPDATE received on closed stream {}: ignoring\n", .{self.id});
                        return;
                    },
                    else => {},
                }

                if (frame.payload.len != 4) {
                    log.err("WINDOW_UPDATE frame with invalid payload length {} (expected 4): FRAME_SIZE_ERROR\n", .{frame.payload.len});
                    try self.conn.send_goaway(0, 0x6, "WINDOW_UPDATE frame with invalid payload length: FRAME_SIZE_ERROR");
                    return error.FrameSizeError;
                }

                const increment = std.mem.readInt(u32, frame.payload[0..4], .big);

                if (increment == 0) {
                    log.err("WINDOW_UPDATE received with increment 0 on stream {}: PROTOCOL_ERROR\n", .{self.id});
                    try self.sendRstStream(0x1);
                    return error.ProtocolError;
                }

                if (increment > 0x7FFFFFFF) {
                    log.err("WINDOW_UPDATE increment {} exceeds maximum on stream {}: FLOW_CONTROL_ERROR\n", .{ increment, self.id });
                    try self.sendRstStream(0x3);
                    return error.FlowControlError;
                }

                try self.updateSendWindow(@intCast(increment));
            }

            fn handleRstStream(self: *Self.StreamInstance, frame: Frame) !void {
                if (frame.payload.len != 4) {
                    log.err("RST_STREAM frame has invalid payload length: {d} (expected 4)\n", .{frame.payload.len});
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
                    log.err("PRIORITY frame with invalid payload length {} (expected 5): FRAME_SIZE_ERROR\n", .{frame.payload.len});
                    try self.conn.send_goaway(0, 0x6, "PRIORITY frame with invalid payload length: FRAME_SIZE_ERROR");
                    return error.FrameSizeError;
                }

                const payload = frame.payload;
                const stream_dependency = (@as(u32, payload[0]) << 24) |
                    (@as(u32, payload[1]) << 16) |
                    (@as(u32, payload[2]) << 8) |
                    (@as(u32, payload[3]));

                const exclusive = (stream_dependency & 0x80000000) != 0;
                const dependency_stream_id = stream_dependency & 0x7FFFFFFF;
                const weight = payload[4];

                if (dependency_stream_id == self.id) {
                    log.err("Stream {} PRIORITY frame depends on itself: PROTOCOL_ERROR\n", .{self.id});
                    try self.sendRstStream(0x1);
                    return error.ProtocolError;
                }

                if (self.conn.rfc7540_priority_signals_ignored()) {
                    return;
                }

                self.stream_dependency = dependency_stream_id;
                self.exclusive = exclusive;
                self.weight = @as(u16, weight) + 1;
            }

            fn decodeHeaderBlock(self: *Self.StreamInstance) !void {
                const header_block = self.header_block_fragments_buf[0..self.header_block_fragments_len];
                var cursor: usize = 0;
                var saw_header_field = false;
                var pseudo_headers = RequestPseudoHeaders{};
                var priority_header_seen = false;

                self.headers.clearRetainingCapacity();
                self.headers_bytes_len = 0;

                while (cursor < header_block.len) {
                    Hpack.resetScratchBuffer();
                    const remaining_data = header_block[cursor..];
                    const decoded_header = Hpack.decodeHeaderFieldView(
                        remaining_data,
                        &self.conn.hpack_decoder_table,
                    ) catch |err| {
                        log.err("Header decompression failed: {}\n", .{err});
                        try self.conn.send_goaway(0, 0x09, "Compression Error: COMPRESSION_ERROR");
                        return error.CompressionError;
                    };

                    // Filter out empty headers from HPACK dynamic table size updates.
                    if (decoded_header.header.name.len > 0) {
                        saw_header_field = true;

                        if (self.request_headers_complete) {
                            try self.validateTrailerHeader(decoded_header.header);
                        } else {
                            try self.validateRequestHeader(
                                decoded_header.header,
                                &pseudo_headers,
                                &priority_header_seen,
                            );
                        }

                        if (self.shouldStoreRequestHeaders()) {
                            try self.storeHeader(decoded_header.header);
                        }
                    } else if (saw_header_field) {
                        try self.conn.send_goaway(0, 0x09, "Compression Error: COMPRESSION_ERROR");
                        return error.CompressionError;
                    }

                    cursor += decoded_header.bytes_consumed;
                }

                if (!self.request_headers_complete) {
                    try self.finishRequestHeaders(
                        &pseudo_headers,
                        priority_header_seen,
                    );
                }
            }

            fn storeHeader(self: *Self.StreamInstance, header: Hpack.HeaderField) !void {
                if (self.headers.items.len >= self.headers.capacity) {
                    log.err("Too many headers: INTERNAL_ERROR\n", .{});
                    try self.sendRstStream(0x2);
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

                    if (self.isConnect()) {
                        if (self.scheme != null) return error.ProtocolError;
                        if (self.path != null) return error.ProtocolError;
                        if (self.authority == null) return error.ProtocolError;
                        return;
                    }

                    const scheme = self.scheme orelse return error.ProtocolError;
                    const path = self.path orelse return error.ProtocolError;
                    if (scheme.len == 0) return error.ProtocolError;
                    if (path.len == 0) return error.ProtocolError;
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

            fn validateHeaders(self: *Self.StreamInstance, headers: []const Hpack.HeaderField) !void {
                var pseudo_headers = RequestPseudoHeaders{};
                var priority_header_seen = false;

                for (headers) |header| {
                    try self.validateRequestHeader(
                        header,
                        &pseudo_headers,
                        &priority_header_seen,
                    );
                }

                try self.finishRequestHeaders(
                    &pseudo_headers,
                    priority_header_seen,
                );
            }

            fn validateRequestHeader(
                self: *Self.StreamInstance,
                header: Hpack.HeaderField,
                pseudo_headers: *RequestPseudoHeaders,
                priority_header_seen: *bool,
            ) !void {
                if (header.name.len == 0) {
                    try self.fail_protocol_error("Empty header name");
                }

                if (header.name[0] == ':') {
                    const value_stable = try self.storeHeaderValue(header.value);
                    pseudo_headers.add(.{
                        .name = header.name,
                        .value = value_stable,
                    }) catch {
                        try self.fail_protocol_error("Invalid pseudo-header field");
                    };
                    return;
                }

                pseudo_headers.markRegularHeader();
                try self.validateRegularHeader(header);
                try self.validateContentLength(header);
                if (self.applyPriorityHeader(header)) {
                    priority_header_seen.* = true;
                }
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
            ) !void {
                pseudo_headers.validateRequest() catch {
                    try self.fail_protocol_error("Invalid request pseudo-header fields");
                };
                self.request_method_bytes = pseudo_headers.method;
                self.request_method = handler.Method.fromBytes(pseudo_headers.method.?);
                self.request_path = pseudo_headers.path;
                self.request_headers_complete = true;
                self.applyDefaultRequestPriority(
                    pseudo_headers,
                    priority_header_seen,
                );
            }

            fn validateRegularHeader(self: *Self.StreamInstance, header: Hpack.HeaderField) !void {
                if (isConnectionSpecificHeader(header.name)) {
                    try self.fail_protocol_error("Connection-specific header field");
                }

                if (std.mem.eql(u8, header.name, "te")) {
                    if (!std.mem.eql(u8, header.value, "trailers")) {
                        try self.fail_protocol_error("Invalid TE header field value");
                    }
                }

                if (!handler.isAllLowercaseHeaderName(header.name)) {
                    try self.fail_protocol_error("Header field name contains uppercase letters");
                }
            }

            fn validateContentLength(self: *Self.StreamInstance, header: Hpack.HeaderField) !void {
                if (!std.mem.eql(u8, header.name, "content-length")) {
                    return;
                }

                const content_length = std.fmt.parseInt(usize, header.value, 10) catch {
                    try self.fail_protocol_error("Invalid content-length header field");
                };
                self.content_length = content_length;
            }

            fn validateTrailers(self: *Self.StreamInstance, headers: []const Hpack.HeaderField) !void {
                for (headers) |header| {
                    try self.validateTrailerHeader(header);
                }
            }

            fn validateTrailerHeader(self: *Self.StreamInstance, header: Hpack.HeaderField) !void {
                if (header.name.len == 0) {
                    try self.fail_protocol_error("Empty trailer header name");
                }
                if (header.name[0] == ':') {
                    try self.fail_protocol_error("Pseudo-header field in trailers");
                }

                try self.validateRegularHeader(header);
                try self.validateContentLength(header);
            }

            fn fail_protocol_error(self: *Self.StreamInstance, message: []const u8) !noreturn {
                log.err("{s}: PROTOCOL_ERROR\n", .{message});
                try self.sendRstStream(0x1);
                return error.ProtocolError;
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

        // Public API for the generic Stream type
        pool: StreamPool = StreamPool{},

        pub fn createStream(self: *Self, allocator: std.mem.Allocator, conn: *Connection, id: u32) !*Self.StreamInstance {
            const stream = try self.pool.allocate(allocator);
            stream.init(conn, id);
            return stream;
        }

        pub fn destroyStream(self: *Self, stream: *Self.StreamInstance, allocator: std.mem.Allocator) void {
            stream.deinit();
            self.pool.deallocate(stream, allocator);
        }

        // Static factory method for compatibility with connection code
        pub fn init(allocator: std.mem.Allocator, conn: anytype, id: u32) !*Self.StreamInstance {
            var pool = StreamPool{};
            const stream = try pool.allocate(allocator);
            stream.init(conn, id);
            return stream;
        }
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

pub const DefaultStream = Stream(16, 1000); // 64KB window, 1000 max streams

comptime {
    const Instance = DefaultStream.StreamInstance;
    const Budget = memory_budget.MemBudget;
    const fields = @typeInfo(Instance).@"struct".fields;
    var found_header_fragments: bool = false;
    var found_headers_storage: bool = false;
    var found_request_body: bool = false;
    var found_response_body: bool = false;
    var found_headers_array: bool = false;
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, "header_block_fragments_buf")) {
            found_header_fragments = true;
            if (@sizeOf(field.type) != Budget.stream_header_fragments_bytes) {
                @compileError("stream_header_fragments_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, field.name, "headers_bytes_storage")) {
            found_headers_storage = true;
            if (@sizeOf(field.type) != Budget.stream_headers_storage_bytes) {
                @compileError("stream_headers_storage_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, field.name, "request_body_storage")) {
            found_request_body = true;
            if (@sizeOf(field.type) != Budget.stream_request_body_bytes) {
                @compileError("stream_request_body_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, field.name, "response_body_storage")) {
            found_response_body = true;
            if (@sizeOf(field.type) != Budget.stream_response_body_bytes) {
                @compileError("stream_response_body_bytes budget mismatch");
            }
        } else if (std.mem.eql(u8, field.name, "headers_storage")) {
            found_headers_array = true;
            if (@sizeOf(field.type) != Budget.stream_headers_array_bytes) {
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
    try std.testing.expectEqual(StreamState.HalfClosedRemote, transitionState(.Open, .RecvEndStream));
    try std.testing.expectEqual(StreamState.Closed, transitionState(.HalfClosedLocal, .RecvEndStream));
}

test "CONNECT defaults request priority to incremental" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var test_io = TestIo.init(&.{}, &buffer);

    var connection = try Connection.init(
        arena.allocator(),
        &test_io.reader,
        &test_io.writer,
        false,
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

    var connection = try Connection.init(
        arena.allocator(),
        &test_io.reader,
        &test_io.writer,
        false,
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
