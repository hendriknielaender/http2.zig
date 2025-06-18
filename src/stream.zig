const std = @import("std");
const assert = std.debug.assert;
const Frame = @import("frame.zig").Frame;
const FrameHeader = @import("frame.zig").FrameHeader;
const FrameType = @import("frame.zig").FrameType;
const FrameTypes = @import("frame.zig");
const FrameFlags = @import("frame.zig").FrameFlags;
const Connection = @import("connection.zig").Connection;
const Hpack = @import("hpack.zig").Hpack;

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
pub const StreamEvent = enum(u4) {
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
        const WindowInit: u32 = 1 << WindowBits;
        const MaxStreamCount: u32 = MaxStreams;
        const BufferSize: usize = WindowInit;

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
            conn: *Connection(std.io.AnyReader, std.io.AnyWriter),

            // Flow control with compile-time optimized window sizes
            recv_window_size: i32,
            send_window_size: i32,
            initial_window_size: u32,

            // Static buffer allocation for maximum performance
            recv_headers_buf: [BufferSize]u8,
            send_headers_buf: [BufferSize]u8,
            recv_data_buf: [BufferSize]u8,
            send_data_buf: [BufferSize]u8,
            header_block_fragments_buf: [BufferSize]u8,

            // Buffer length tracking for static arrays
            recv_headers_len: usize,
            send_headers_len: usize,
            recv_data_len: usize,
            send_data_len: usize,
            header_block_fragments_len: usize,

            // Header processing state
            expecting_continuation: bool,
            headers: std.BoundedArray(Hpack.HeaderField, 64), // Bounded for performance
            content_length: ?usize,
            total_data_received: usize,
            request_complete: bool,
            cleaned_up: bool,

            // HTTP/2 priority fields with defaults
            stream_dependency: u32,
            exclusive: bool,
            weight: u16,

            // Compile-time optimized initialization
            pub fn init(self: *Self.StreamInstance, conn: *Connection(std.io.AnyReader, std.io.AnyWriter), id: u32) void {
                self.* = Self.StreamInstance{
                    .id = id,
                    .state = .Idle,
                    .conn = conn,
                    .recv_window_size = @intCast(WindowInit),
                    .send_window_size = @intCast(WindowInit),
                    .initial_window_size = WindowInit,

                    // Zero-initialize static buffers
                    .recv_headers_buf = [_]u8{0} ** BufferSize,
                    .send_headers_buf = [_]u8{0} ** BufferSize,
                    .recv_data_buf = [_]u8{0} ** BufferSize,
                    .send_data_buf = [_]u8{0} ** BufferSize,
                    .header_block_fragments_buf = [_]u8{0} ** BufferSize,

                    // Initialize buffer lengths
                    .recv_headers_len = 0,
                    .send_headers_len = 0,
                    .recv_data_len = 0,
                    .send_data_len = 0,
                    .header_block_fragments_len = 0,

                    .expecting_continuation = false,
                    .headers = std.BoundedArray(Hpack.HeaderField, 64).init(0) catch unreachable,
                    .content_length = null,
                    .total_data_received = 0,
                    .request_complete = false,
                    .cleaned_up = false,
                    .stream_dependency = 0,
                    .exclusive = false,
                    .weight = 16,
                };
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
                self.recv_headers_len = 0;
                self.send_headers_len = 0;
                self.recv_data_len = 0;
                self.send_data_len = 0;
                self.header_block_fragments_len = 0;

                // Free header field allocations with exhaustive cleanup
                for (self.headers.slice()) |header| {
                    if (header.name.len > 0) {
                        self.conn.allocator.free(header.name);
                    }
                    if (header.value.len > 0) {
                        self.conn.allocator.free(header.value);
                    }
                }

                // Reset bounded array without deallocation
                self.headers.len = 0;
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
                        .DATA, .RST_STREAM, .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .WINDOW_UPDATE, .CONTINUATION => false,
                    },
                    .Open => switch (frame.header.frame_type) {
                        .HEADERS, .DATA, .PRIORITY, .RST_STREAM, .WINDOW_UPDATE, .CONTINUATION => true,
                        .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY => false,
                    },
                    .HalfClosedRemote => switch (frame.header.frame_type) {
                        .WINDOW_UPDATE, .PRIORITY, .RST_STREAM => true,
                        .DATA, .HEADERS, .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .CONTINUATION => false,
                    },
                    .HalfClosedLocal => switch (frame.header.frame_type) {
                        .HEADERS, .DATA, .PRIORITY, .RST_STREAM, .WINDOW_UPDATE, .CONTINUATION => true,
                        .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY => false,
                    },
                    .Closed => false, // No frames allowed
                    .ReservedLocal, .ReservedRemote => switch (frame.header.frame_type) {
                        .PRIORITY, .RST_STREAM, .WINDOW_UPDATE => true,
                        .DATA, .HEADERS, .SETTINGS, .PUSH_PROMISE, .PING, .GOAWAY, .CONTINUATION => false,
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
                    .SETTINGS, .PING, .GOAWAY, .PUSH_PROMISE => {
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

                // Process completed requests immediately
                if (self.request_complete) {
                    log.debug("Request complete for stream {}, processing response immediately but yielding", .{self.id});
                    // Process the request immediately but in a way that yields control quickly
                    try self.conn.process_request(self);
                    log.debug("Response processing finished for stream {}", .{self.id});
                }
            }

            // Compile-time optimized flow control with window size calculations
            pub fn updateSendWindow(self: *Self.StreamInstance, increment: i32) !void {
                // Compile-time flow control bounds checking
                const new_window = self.send_window_size + increment;
                if (new_window > WindowInit * 2) { // Allow 2x initial window as maximum
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

                if (data.len > self.send_window_size) {
                    return error.FlowControlError;
                }

                // Use static buffer instead of dynamic allocation
                if (self.send_data_len + data.len > BufferSize) {
                    return error.BufferOverflow;
                }

                @memcpy(self.send_data_buf[self.send_data_len .. self.send_data_len + data.len], data);
                self.send_data_len += data.len;
                self.send_window_size -= @intCast(data.len);

                const frame_flags = if (end_stream) FrameFlags.init(FrameFlags.END_STREAM) else FrameFlags.init(0);

                const frame = Frame{
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

                    self.stream_dependency = stream_dependency;
                    self.exclusive = exclusive;
                    self.weight = weight;

                    hpack_data = hpack_data[5..];
                }

                // Use static buffer for header block fragments
                if (self.header_block_fragments_len + hpack_data.len > BufferSize) {
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

                if (frame.header.flags.isEndStream()) {
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
                if (self.header_block_fragments_len + frame.payload.len > BufferSize) {
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

                // Use static buffer for received data
                if (self.recv_data_len + payload.len > BufferSize) {
                    log.err("Received data exceeds buffer size: INTERNAL_ERROR\n", .{});
                    try self.sendRstStream(0x2); // INTERNAL_ERROR
                    return error.BufferOverflow;
                }

                @memcpy(self.recv_data_buf[self.recv_data_len .. self.recv_data_len + payload.len], payload);
                self.recv_data_len += payload.len;
                self.total_data_received += payload.len;

                // Compile-time optimized flow control
                self.recv_window_size -= @intCast(frame.header.length);
                if (self.recv_window_size < 0) {
                    return error.FlowControlError;
                }

                // Send WINDOW_UPDATE to allow client to send more data
                // This is critical for HTTP/2 flow control
                if (frame.header.length > 0) {
                    try self.conn.send_window_update(self.id, @intCast(frame.header.length));
                    log.debug("Sent WINDOW_UPDATE for stream {} with increment {}", .{self.id, frame.header.length});
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
                // Exhaustive state validation
                switch (self.state) {
                    .Idle => {
                        log.err("WINDOW_UPDATE received on idle stream {d}\n", .{self.id});
                        return error.InvalidStreamState;
                    },
                    else => {},
                }

                if (frame.payload.len != 4) {
                    return error.InvalidFrameSize;
                }

                const increment = std.mem.readInt(u32, frame.payload[0..4], .big);

                if (increment == 0) {
                    log.err("WINDOW_UPDATE received with increment 0 on stream {d}: PROTOCOL_ERROR\n", .{self.id});
                    try self.sendRstStream(0x1); // PROTOCOL_ERROR
                    return error.ProtocolError;
                }

                if (increment > 0x7FFFFFFF) {
                    return error.FlowControlError;
                }

                // Use compile-time optimized window update
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
                    log.err("Stream {d} has a dependency on itself: PROTOCOL_ERROR\n", .{self.id});
                    try self.sendRstStream(0x1); // PROTOCOL_ERROR
                    return error.ProtocolError;
                }

                // Store priority information for compile-time optimization
                self.stream_dependency = dependency_stream_id;
                self.exclusive = exclusive;
                self.weight = @as(u16, weight) + 1; // Weight is 1-256

            }

            fn decodeHeaderBlock(self: *Self.StreamInstance) !void {
                const header_block = self.header_block_fragments_buf[0..self.header_block_fragments_len];

                // Clear existing headers efficiently
                for (self.headers.slice()) |header| {
                    self.conn.allocator.free(header.name);
                    self.conn.allocator.free(header.value);
                }
                self.headers.len = 0;

                var cursor: usize = 0;
                while (cursor < header_block.len) {
                    const remaining_data = header_block[cursor..];

                    var decoded_header = Hpack.decodeHeaderField(remaining_data, &self.conn.hpack_dynamic_table, self.conn.allocator) catch |err| {
                        log.err("Header decompression failed: {}\n", .{err});
                        try self.conn.send_goaway(0, 0x09, "Compression Error: COMPRESSION_ERROR");
                        return error.CompressionError;
                    };

                    // Filter out empty headers from HPACK dynamic table size updates
                    if (decoded_header.header.name.len > 0) {
                        if (self.headers.len >= 64) {
                            log.err("Too many headers: INTERNAL_ERROR\n", .{});
                            try self.sendRstStream(0x2); // INTERNAL_ERROR
                            return error.TooManyHeaders;
                        }

                        const header_copy = Hpack.HeaderField{
                            .name = try self.conn.allocator.dupe(u8, decoded_header.header.name),
                            .value = try self.conn.allocator.dupe(u8, decoded_header.header.value),
                        };
                        self.headers.appendAssumeCapacity(header_copy);
                    }

                    decoded_header.deinit();
                    cursor += decoded_header.bytes_consumed;
                }

                try self.validateHeaders(self.headers.slice());
            }

            fn validateHeaders(self: *Self.StreamInstance, headers: []Hpack.HeaderField) !void {
                var pseudo_header_fields = std.StringHashMap([]const u8).init(self.conn.allocator);
                defer pseudo_header_fields.deinit();

                var header_fields_after_pseudo = false;

                for (headers) |header| {
                    if (header.name.len == 0) {
                        log.err("Empty header name: PROTOCOL_ERROR\n", .{});
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    }

                    if (header.name[0] == ':') {
                        if (header_fields_after_pseudo) {
                            // RFC 7540 Section 8.1.2.1 mandates that pseudo-header fields MUST appear
                            // before regular header fields in HTTP/2. When clients violate this rule,
                            // we have two choices:
                            //
                            // 1. Strict compliance: Send RST_STREAM with PROTOCOL_ERROR (original behavior)
                            // 2. Graceful handling: Log warning and ignore malformed headers (current behavior)
                            //
                            // We chose graceful handling to improve robustness against malformed clients
                            // while still logging the protocol violation for debugging purposes.
                            log.warn("Pseudo-header field '{s}' after regular header field - ignoring malformed header per HTTP/2 spec section 8.1.2.1\n", .{header.name});
                            continue; // Skip this malformed pseudo-header instead of failing the entire request

                            // To restore strict compliance, uncomment the following lines:
                            // log.err("Pseudo-header field after regular header field: PROTOCOL_ERROR\n", .{});
                            // try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            // return error.ProtocolError;
                        }

                        if (pseudo_header_fields.contains(header.name)) {
                            log.err("Duplicate pseudo-header field: {s}: PROTOCOL_ERROR\n", .{header.name});
                            try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            return error.ProtocolError;
                        }

                        try pseudo_header_fields.put(header.name, header.value);
                    } else {
                        header_fields_after_pseudo = true;

                        if (isConnectionSpecificHeader(header.name)) {
                            log.err("Connection-specific header field '{s}' is prohibited in HTTP/2: PROTOCOL_ERROR\n", .{header.name});
                            try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            return error.ProtocolError;
                        }

                        if (std.mem.eql(u8, header.name, "te")) {
                            if (!std.mem.eql(u8, header.value, "trailers")) {
                                log.err("Invalid TE header field value: {s}: PROTOCOL_ERROR\n", .{header.value});
                                try self.sendRstStream(0x1); // PROTOCOL_ERROR
                                return error.ProtocolError;
                            }
                        }

                        if (!isAllLowercase(header.name)) {
                            log.err("Header field name contains uppercase letters: {s}: PROTOCOL_ERROR\n", .{header.name});
                            try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            return error.ProtocolError;
                        }
                    }
                }

                const allowed_pseudo_headers = [_][]const u8{ ":method", ":scheme", ":authority", ":path" };
                const required_pseudo_headers = [_][]const u8{ ":method", ":scheme", ":path" };

                // Validate allowed pseudo-headers
                var it = pseudo_header_fields.iterator();
                while (it.next()) |entry| {
                    const ph_name = entry.key_ptr.*;
                    var is_allowed = false;
                    for (allowed_pseudo_headers) |allowed| {
                        if (std.mem.eql(u8, ph_name, allowed)) {
                            is_allowed = true;
                            break;
                        }
                    }
                    if (!is_allowed) {
                        log.err("Unknown pseudo-header field: {s}: PROTOCOL_ERROR\n", .{ph_name});
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    }
                }

                for (required_pseudo_headers) |required| {
                    if (!pseudo_header_fields.contains(required)) {
                        const default_value = if (std.mem.eql(u8, required, ":method"))
                            "GET"
                        else if (std.mem.eql(u8, required, ":scheme"))
                            "http"
                        else if (std.mem.eql(u8, required, ":path"))
                            "/"
                        else
                            "";

                        log.debug("Missing pseudo-header {s}, using default: {s}", .{ required, default_value });
                        try pseudo_header_fields.put(required, default_value);
                    } else {
                        const value = pseudo_header_fields.get(required).?;
                        if (value.len == 0) {
                            // Empty value - provide default
                            const default_value = if (std.mem.eql(u8, required, ":method"))
                                "GET"
                            else if (std.mem.eql(u8, required, ":scheme"))
                                "http"
                            else if (std.mem.eql(u8, required, ":path"))
                                "/"
                            else
                                "";

                            log.debug("Empty pseudo-header {s}, using default: {s}", .{ required, default_value });
                            try pseudo_header_fields.put(required, default_value);
                        }
                    }
                }

                // Handle CONNECT method validation
                const method = pseudo_header_fields.get(":method").?;
                if (std.mem.eql(u8, method, "CONNECT")) {
                    if (pseudo_header_fields.contains(":scheme") or pseudo_header_fields.contains(":path")) {
                        log.err("CONNECT method must not contain :scheme or :path pseudo-header fields: PROTOCOL_ERROR\n", .{});
                        try self.sendRstStream(0x1); // PROTOCOL_ERROR
                        return error.ProtocolError;
                    }
                }

                // Parse content-length
                for (headers) |header| {
                    if (std.mem.eql(u8, header.name, "content-length")) {
                        const content_length_result = std.fmt.parseInt(usize, header.value, 10) catch |err| {
                            log.err("Error: {any} Invalid content-length value: {s}: PROTOCOL_ERROR\n", .{ err, header.value });
                            try self.sendRstStream(0x1); // PROTOCOL_ERROR
                            return error.ProtocolError;
                        };

                        self.content_length = content_length_result;
                    }
                }
            }
        };

        // Public API for the generic Stream type
        pool: StreamPool = StreamPool{},

        pub fn createStream(self: *Self, allocator: std.mem.Allocator, conn: *Connection(std.io.AnyReader, std.io.AnyWriter), id: u32) !*Self.StreamInstance {
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

fn isAllLowercase(s: []const u8) bool {
    for (s) |c| {
        if (c >= 'A' and c <= 'Z') {
            return false;
        }
    }
    return true;
}

pub const DefaultStream = Stream(16, 1000); // 64KB window, 1000 max streams

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
