const std = @import("std");
const builtin = @import("builtin");
const os = std.os;
const net = std.net;
const posix = std.posix;
const native_endian = builtin.cpu.arch.endian();
const has_sse42 = blk: {
    if (builtin.cpu.arch == .x86_64) {
        break :blk std.Target.x86.featureSetHas(builtin.cpu.features, .sse4_2);
    }
    break :blk false;
};
fn validate_preface_simd(preface: []const u8, expected: []const u8) bool {
    if (comptime has_sse42) {
        if (preface.len == 24) {
            if (expected.len == 24) {
                // Use SIMD for 24-byte preface comparison.
                const preface_ptr: *const [24]u8 = @ptrCast(preface.ptr);
                const expected_ptr: *const [24]u8 = @ptrCast(expected.ptr);

                // Compare in 16-byte chunks using SIMD.
                const preface_v1 = @as(@Vector(16, u8), preface_ptr[0..16].*);
                const expected_v1 = @as(@Vector(16, u8), expected_ptr[0..16].*);
                const eq1 = @reduce(.And, preface_v1 == expected_v1);

                // Compare remaining 8 bytes.
                const preface_v2 = @as(@Vector(8, u8), preface_ptr[16..24].*);
                const expected_v2 = @as(@Vector(8, u8), expected_ptr[16..24].*);
                const eq2 = @reduce(.And, preface_v2 == expected_v2);

                return eq1 and eq2;
            }
        }
    }

    // Fallback to standard comparison.
    return std.mem.eql(u8, preface, expected);
}
fn compare_header_name_simd(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    if (comptime has_sse42 and a.len >= 16) {
        // Process 16-byte chunks with SIMD
        var i: usize = 0;
        while (i + 16 <= a.len) {
            const a_chunk = @as(@Vector(16, u8), a[i .. i + 16].*);
            const b_chunk = @as(@Vector(16, u8), b[i .. i + 16].*);
            if (!@reduce(.And, a_chunk == b_chunk)) return false;
            i += 16;
        }
        // Handle remaining bytes
        while (i < a.len) {
            if (a[i] != b[i]) return false;
            i += 1;
        }
        return true;
    }
    return std.mem.eql(u8, a, b);
}
pub const Stream = @import("stream.zig").Stream;
pub const DefaultStream = @import("stream.zig").DefaultStream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const FrameType = @import("frame.zig").FrameType;
const SIMDFrameParser = @import("simd_frame_parser.zig").SIMDFrameParser;
pub const FrameTypes = @import("frame.zig");
pub const FrameArena = @import("frame.zig").FrameArena;
pub const FrameMeta = @import("frame.zig").FrameMeta;
pub const initFrameArena = @import("frame.zig").initFrameArena;
pub const Hpack = @import("hpack.zig").Hpack;
pub const http2 = @import("http2.zig");
const MAX_IN_FLIGHT_FRAMES = 64;
const max_frame_size_default = http2.max_frame_size_default;
const log = std.log.scoped(.connection);
const assert = std.debug.assert;
const http2_preface: []const u8 = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const Config = struct {
    // Socket options - configured at comptime for zero-cost abstractions
    pub const SocketOpts = struct {
        reuse_port: bool = true,
        no_delay: bool = true,
        fast_open: bool = true,
        quick_ack: bool = true,
        defer_accept: bool = true,
        recv_buffer_size: u32 = 1024 * 1024, // 1MB
        send_buffer_size: u32 = 1024 * 1024, // 1MB
    };
    // Event loop configuration
    pub const EventLoop = struct {
        max_events: u32 = 1024,
        timeout_ms: i32 = 1000,
        batch_accept_size: u32 = 32,
    };
    // Static allocation sizes
    pub const StaticSizes = struct {
        max_connections: u32 = 10000,
        frame_buffer_size: u32 = 64 * 1024, // 64KB
        header_buffer_size: u32 = 8 * 1024, // 8KB
    };
};
pub const FrameHandler = enum(u8) {
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
            else => null,
        };
    }
};
pub fn setSockopts(comptime opts: Config.SocketOpts) type {
    return struct {
        pub fn apply(socket: os.socket_t) anyerror!void {
            if (opts.reuse_port) {
                try os.setsockopt(socket, os.SOL.SOCKET, os.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
            }
            if (opts.no_delay) {
                try os.setsockopt(socket, os.IPPROTO.TCP, os.TCP.NODELAY, &std.mem.toBytes(@as(c_int, 1)));
            }
            if (opts.quick_ack) {
                try os.setsockopt(socket, os.IPPROTO.TCP, os.TCP.QUICKACK, &std.mem.toBytes(@as(c_int, 1)));
            }
            if (opts.defer_accept) {
                try os.setsockopt(socket, os.IPPROTO.TCP, os.TCP.DEFER_ACCEPT, &std.mem.toBytes(@as(c_int, 1)));
            }
            // Buffer sizes
            try os.setsockopt(socket, os.SOL.SOCKET, os.SO.RCVBUF, &std.mem.toBytes(@as(c_int, @intCast(opts.recv_buffer_size))));
            try os.setsockopt(socket, os.SOL.SOCKET, os.SO.SNDBUF, &std.mem.toBytes(@as(c_int, @intCast(opts.send_buffer_size))));
            if (opts.fast_open) {
                os.setsockopt(socket, os.IPPROTO.TCP, os.TCP.FASTOPEN, &std.mem.toBytes(@as(c_int, 1))) catch |err| {
                    switch (err) {
                        error.ProtocolNotSupported, error.InvalidArgument => {
                            // Fast open not supported on this system, continue
                            log.debug("TCP_FASTOPEN not supported, continuing without it\n", .{});
                        },
                        else => return err,
                    }
                };
            }
        }
    }.apply;
}
pub fn acceptMany(listener: std.net.Server, connections: []std.net.Server.Connection) !u32 {
    var accepted: u32 = 0;
    while (accepted < connections.len) {
        const conn = listener.accept() catch |err| switch (err) {
            error.WouldBlock => break, // No more connections available
            else => return err,
        };
        connections[accepted] = conn;
        accepted += 1;
    }
    return accepted;
}
pub fn Connection(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        allocator: std.mem.Allocator,
        reader: ReaderType,
        writer: WriterType,
        settings: Settings,
        recv_window_size: i32 = 65535,
        send_window_size: i32 = 65535,
        streams: std.AutoHashMap(u32, *DefaultStream.StreamInstance),
        hpack_dynamic_table: Hpack.DynamicTable,
        goaway_sent: bool = false,
        goaway_received: bool = false,
        expecting_continuation_stream_id: ?u32 = null,
        last_stream_id: u32 = 0,
        client_settings_received: bool = false,
        closed_stream_ids: std.AutoHashMap(u32, void),
        connection_closed: bool = false,
        frame_arena_buffer: [MAX_IN_FLIGHT_FRAMES * (max_frame_size_default + @sizeOf(FrameMeta))]u8,
        frame_arena: FrameArena,

        pub fn init(allocator: std.mem.Allocator, reader: ReaderType, writer: WriterType, comptime is_server: bool) !@This() {
            var self = @This(){
                .allocator = allocator,
                .reader = reader,
                .writer = writer,
                .settings = Settings.default(),
                .recv_window_size = 65535,
                .send_window_size = 65535,
                .streams = std.AutoHashMap(u32, *DefaultStream.StreamInstance).init(allocator),
                .hpack_dynamic_table = Hpack.DynamicTable.init(allocator, 4096),
                .closed_stream_ids = std.AutoHashMap(u32, void).init(allocator),
                .frame_arena_buffer = undefined,
                .frame_arena = undefined,
            };
            self.frame_arena = initFrameArena(&self.frame_arena_buffer);
            if (is_server) {
                try self.check_server_preface();
            } else {
                try self.send_preface();
            }
            try self.send_settings();
            return self;
        }
        fn check_server_preface(self: *@This()) !void {
            const preface_len = http2_preface.len;
            var preface_buf: [preface_len]u8 = undefined;
            var bytes_read: usize = 0;
            while (bytes_read < preface_len) {
                const read_result = try self.reader.read(preface_buf[bytes_read..]);
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
        pub fn deinit(self: @This()) void {
            // Mark connection as closed to prevent further operations
            @constCast(&self).connection_closed = true;
            // Deinitialize and free streams
            var it = self.streams.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit();
                self.allocator.destroy(entry.value_ptr.*);
            }
            @constCast(&self.streams).deinit();
            @constCast(&self.closed_stream_ids).deinit();
            @constCast(&self.hpack_dynamic_table).deinit();
            log.debug("Resources deinitialized for connection\n", .{});
        }
        /// Mark a stream as closed and track it in the closed set
        /// Note: The stream will be cleaned up later by process_pending_streams
        pub fn mark_stream_closed(self: *@This(), stream_id: u32) !void {
            try self.closed_stream_ids.put(stream_id, {});
            log.debug("Marked stream {d} as closed\n", .{stream_id});
        }
        fn send_preface(self: @This()) !void {
            try self.writer.writeAll(http2_preface);
        }
        pub fn highest_stream_id(self: @This()) u32 {
            var stream_id: u32 = 0;
            var it = self.streams.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* > stream_id) {
                    stream_id = entry.key_ptr.*;
                }
            }
            return stream_id;
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
        fn error_code_from_error(err: anyerror) u32 {
            return switch (err) {
                error.FrameSizeError => 0x6, // FRAME_SIZE_ERROR
                error.ProtocolError => 0x1, // PROTOCOL_ERROR
                // Map other errors as needed...
                else => 0x1, // Default to PROTOCOL_ERROR
            };
        }

        pub fn receiveFrameStatic(self: *@This(), buffer: []u8) !Frame {
            if (buffer.len < 9) return error.BufferTooSmall;
            const header_bytes = buffer[0..9];
            var header_read: usize = 0;
            while (header_read < 9) {
                const bytes_read = try self.reader.read(header_bytes[header_read..]);
                if (bytes_read == 0) {
                    if (header_read == 0) {
                        return error.UnexpectedEOF;
                    } else {
                        // Partial header read - wait for more data
                        return error.WouldBlock;
                    }
                }
                header_read += bytes_read;
            }

            // Use SIMD-optimized frame header parsing
            const frame_header = SIMDFrameParser.parseFrameHeader(header_bytes) catch |err| switch (err) {
                error.InvalidFrameLength => {
                    log.err("Invalid frame length detected by SIMD parser, sending GOAWAY", .{});
                    try self.send_goaway(0, 0x6, "Frame size error: FRAME_SIZE_ERROR");
                    return error.FrameSizeError;
                },
                error.InvalidFrameType => {
                    log.err("Invalid frame type detected by SIMD parser", .{});
                    return error.InvalidFrameType;
                },
                else => return err,
            };

            if (frame_header.length > self.settings.max_frame_size) {
                log.err("Received frame size {} exceeds SETTINGS_MAX_FRAME_SIZE {}, sending GOAWAY", .{ frame_header.length, self.settings.max_frame_size });
                try self.send_goaway(0, 0x6, "Frame size exceeded, sending GOAWAY: FRAME_SIZE_ERROR.");
                return error.FrameSizeError;
            }
            if (frame_header.length + 9 > buffer.len) return error.BufferTooSmall;

            if (frame_header.length > 0) {
                const payload_buffer = buffer[9 .. 9 + frame_header.length];
                var payload_read: usize = 0;
                while (payload_read < frame_header.length) {
                    const bytes_read = try self.reader.read(payload_buffer[payload_read..]);
                    if (bytes_read == 0) {
                        // Connection closed while reading payload
                        return error.UnexpectedEOF;
                    }
                    payload_read += bytes_read;
                }
            }

            return Frame{
                .header = frame_header,
                .payload = if (frame_header.length > 0) buffer[9 .. 9 + frame_header.length] else &[_]u8{},
            };
        }

        pub fn dispatchFrameOptimized(self: *@This(), frame: Frame) !void {
            const handler = FrameHandler.fromFrameType(@intFromEnum(frame.header.frame_type)) orelse {
                // Unknown frame type - ignore per RFC 7540 Section 5.5
                log.debug("Ignoring unknown frame type {d}\n", .{@intFromEnum(frame.header.frame_type)});
                return;
            };
            switch (handler) {
                .data => try self.handleDataFrameOptimized(frame),
                .headers => try self.handleHeadersFrameOptimized(frame),
                .priority => try self.handlePriorityFrameOptimized(frame),
                .rst_stream => try self.handleRstStreamFrameOptimized(frame),
                .settings => try self.handleSettingsFrameOptimized(frame),
                .push_promise => try self.handlePushPromiseFrameOptimized(frame),
                .ping => try self.handlePingFrameOptimized(frame),
                .goaway => try self.handleGoawayFrameOptimized(frame),
                .window_update => try self.handleWindowUpdateFrameOptimized(frame),
                .continuation => try self.handleContinuationFrameOptimized(frame),
            }
        }
        fn handleDataFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id == 0) {
                return self.sendGoawayAndClose(0x1, "DATA frame on stream 0");
            }
            const stream = self.streams.get(frame.header.stream_id) orelse {
                return self.send_rst_stream(frame.header.stream_id, 0x5); // STREAM_CLOSED
            };
            
            // Update connection-level flow control and send WINDOW_UPDATE
            if (frame.header.length > 0) {
                // Send connection-level WINDOW_UPDATE (stream_id = 0)
                try self.send_window_update(0, @intCast(frame.header.length));
                log.debug("Sent connection-level WINDOW_UPDATE with increment {}", .{frame.header.length});
            }
            
            try stream.handleFrame(frame);
        }
        fn handleHeadersFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id == 0) {
                return self.sendGoawayAndClose(0x1, "HEADERS frame on stream 0");
            }
            var stream = self.get_stream(frame.header.stream_id) catch |err| {
                if (err == error.MaxConcurrentStreamsExceeded) {
                    return self.send_rst_stream(frame.header.stream_id, 0x7); // REFUSED_STREAM
                }
                return err;
            };
            try stream.handleFrame(frame);
        }
        fn handlePriorityFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id == 0) {
                return self.sendGoawayAndClose(0x1, "PRIORITY frame on stream 0");
            }
            // Priority frames are always safe to ignore if stream doesn't exist
            if (self.streams.get(frame.header.stream_id)) |stream| {
                try stream.handleFrame(frame);
            }
        }
        fn handleRstStreamFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id == 0) {
                return self.sendGoawayAndClose(0x1, "RST_STREAM frame on stream 0");
            }
            if (self.streams.get(frame.header.stream_id)) |stream| {
                stream.state = .Closed;
                try self.mark_stream_closed(frame.header.stream_id);
            }
        }
        fn handleSettingsFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id != 0) {
                return self.sendGoawayAndClose(0x1, "SETTINGS frame on non-zero stream");
            }
            try self.apply_frame_settings(frame);
            if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                try self.send_settings_ack();
            }
        }
        fn handlePushPromiseFrameOptimized(self: *@This(), frame: Frame) !void {
            _ = frame; // Suppress unused parameter warning
            // Clients must not send PUSH_PROMISE
            return self.sendGoawayAndClose(0x1, "Client sent PUSH_PROMISE");
        }
        fn handlePingFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id != 0) {
                return self.sendGoawayAndClose(0x1, "PING frame on non-zero stream");
            }
            if (frame.payload.len != 8) {
                return self.sendGoawayAndClose(0x6, "Invalid PING payload size");
            }
            if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                try self.send_ping(frame.payload, true);
            }
        }
        fn handleGoawayFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id != 0) {
                return self.sendGoawayAndClose(0x1, "GOAWAY frame on non-zero stream");
            }
            try self.handle_goaway_frame(frame);
        }
        fn handleWindowUpdateFrameOptimized(self: *@This(), frame: Frame) !void {
            try self.handle_window_update(frame);
        }
        fn handleContinuationFrameOptimized(self: *@This(), frame: Frame) !void {
            if (frame.header.stream_id == 0) {
                return self.sendGoawayAndClose(0x1, "CONTINUATION frame on stream 0");
            }
            const expected_stream = self.expecting_continuation_stream_id orelse {
                return self.sendGoawayAndClose(0x1, "Unexpected CONTINUATION frame");
            };
            if (frame.header.stream_id != expected_stream) {
                return self.sendGoawayAndClose(0x1, "CONTINUATION frame on wrong stream");
            }
            const stream = self.streams.get(frame.header.stream_id) orelse {
                return self.send_rst_stream(frame.header.stream_id, 0x5);
            };
            try stream.handleFrame(frame);
        }

        fn sendGoawayAndClose(self: *@This(), error_code: u32, debug_msg: []const u8) !void {
            if (!self.goaway_sent) {
                try self.send_goaway(self.last_stream_id, error_code, debug_msg);
                self.goaway_sent = true;
            }
        }

        pub fn handle_connection_optimized(self: *@This()) !void {
            // Static frame buffer - no allocations on hot path
            var frame_buffer: [64 * 1024]u8 = undefined; // 64KB static buffer

            // Phase 1: Exchange SETTINGS frames with SIMD optimization
            while (!self.client_settings_received) {
                const frame = self.receiveFrameStatic(&frame_buffer) catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };

                // Process with optimized dispatch (SIMD-parsed frame)
                try self.dispatchFrameOptimized(frame);
                if (frame.header.frame_type == FrameType.SETTINGS) {
                    if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                        self.client_settings_received = true;
                    }
                }
            }

            // Phase 2: Main connection loop with SIMD-optimized frame parsing
            while (!self.goaway_sent) {
                if (self.connection_closed) {
                    break;
                }
                const frame = self.receiveFrameStatic(&frame_buffer) catch |err| switch (err) {
                    error.BufferTooSmall => {
                        log.err("Frame too large for static buffer, connection corrupted", .{});
                        try self.send_goaway(0, 0x2, "Frame size exceeds buffer: INTERNAL_ERROR");
                        break;
                    },
                    error.UnexpectedEOF => {
                        log.debug("Connection read error: UnexpectedEOF", .{});
                        break;
                    },
                    error.FrameSizeError => {
                        // Already handled by receiveFrameStatic (GOAWAY sent)
                        break;
                    },
                    else => {
                        log.debug("Connection read error: {s}", .{@errorName(err)});
                        break;
                    },
                };

                // Handle CONTINUATION frame validation
                if (self.expecting_continuation_stream_id) |stream_id| {
                    if (frame.header.stream_id != stream_id or frame.header.frame_type != FrameType.CONTINUATION) {
                        log.err("Received frame type {d} on stream {d} while expecting CONTINUATION frame on stream {d}: PROTOCOL_ERROR", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id, stream_id });
                        try self.send_goaway(self.highest_stream_id(), 0x1, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                        return error.ProtocolError;
                    }
                }

                // Process frame with SIMD-optimized dispatch
                try self.dispatchFrameOptimized(frame);
                try self.process_pending_streams();

                // Exit if both sides sent GOAWAY
                if (self.goaway_sent) {
                    if (self.goaway_received) {
                        log.debug("Both GOAWAY sent and received, gracefully closing connection.", .{});
                        break;
                    }
                }
            }
            log.debug("SIMD-optimized connection handler terminated gracefully.", .{});
        }
        /// Adjust frame handling and validation per RFC 9113.
        pub fn handle_connection(self: *@This()) !void {
            // Use optimized connection handler with SIMD frame parsing
            return self.handle_connection_optimized();
        }

        /// Original frame handling method (kept for compatibility)
        pub fn handle_connection_original(self: *@This()) !void {
            try self.handle_connection_original_phase_settings();
            try self.handle_connection_original_phase_frames();
            log.debug("Connection terminated gracefully after GOAWAY.\n", .{});
        }

        /// Phase 1: Exchange SETTINGS frames
        fn handle_connection_original_phase_settings(self: *@This()) !void {
            while (!self.client_settings_received) {
                var frame = self.receive_frame() catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };
                defer frame.deinit(self.allocator);

                if (frame.header.stream_id == 0) {
                    self.handle_connection_original_phase_settings_connection_frame(frame);
                } else {
                    try handle_stream_level_frame(self, frame);
                }

                if (frame.header.frame_type == FrameType.SETTINGS) {
                    if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                        self.client_settings_received = true;
                    }
                }
            }
        }

        /// Handle connection-level frame during settings phase
        fn handle_connection_original_phase_settings_connection_frame(self: *@This(), frame: Frame) void {
            handle_connection_level_frame(self, frame) catch |err| {
                log.err("Error handling connection-level frame in phase 1: {s}\n", .{@errorName(err)});
                if (!self.goaway_sent) {
                    self.send_goaway(self.last_stream_id, error_code_from_error(err), "Connection-level error") catch {};
                    self.goaway_sent = true;
                }
            };
        }

        /// Phase 2: Handle other frames
        fn handle_connection_original_phase_frames(self: *@This()) !void {
            while (!self.goaway_sent and !self.connection_closed) {
                var frame = self.receive_frame() catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };
                defer frame.deinit(self.allocator);

                try self.handle_connection_original_phase_frames_validate_continuation(frame);

                if (!is_valid_frame_type(@intFromEnum(frame.header.frame_type))) {
                    log.debug("Ignoring unknown frame type {d}\n", .{@intFromEnum(frame.header.frame_type)});
                    continue;
                }

                log.debug("Received frame of type: {d}, stream ID: {d}\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id });

                const is_connection_level = is_connection_level_frame(@intFromEnum(frame.header.frame_type));
                const is_connection_window_update = (frame.header.frame_type == FrameType.WINDOW_UPDATE and frame.header.stream_id == 0);

                if (is_connection_level or is_connection_window_update) {
                    try self.handle_connection_original_phase_frames_connection_level(frame);
                } else {
                    try self.handle_connection_original_phase_frames_stream_level(frame);
                }

                if (self.goaway_sent and self.goaway_received) {
                    log.debug("Both GOAWAY sent and received, stopping frame processing.\n", .{});
                    break;
                }
            }
        }

        /// Validate CONTINUATION frame expectations
        fn handle_connection_original_phase_frames_validate_continuation(self: *@This(), frame: Frame) !void {
            if (self.expecting_continuation_stream_id) |stream_id| {
                if (frame.header.stream_id != stream_id) {
                    log.err("Received frame type {d} on stream {d} while expecting CONTINUATION frame on stream {d}: PROTOCOL_ERROR\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id, stream_id });
                    try self.send_goaway(self.highest_stream_id(), 0x1, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }
                if (frame.header.frame_type != FrameType.CONTINUATION) {
                    log.err("Received frame type {d} on stream {d} while expecting CONTINUATION frame on stream {d}: PROTOCOL_ERROR\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id, stream_id });
                    try self.send_goaway(self.highest_stream_id(), 0x1, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }
            }
        }

        /// Handle connection-level frame during main processing
        fn handle_connection_original_phase_frames_connection_level(self: *@This(), frame: Frame) !void {
            handle_connection_level_frame(self, frame) catch |err| switch (err) {
                error.BrokenPipe, error.ConnectionResetByPeer, error.ConnectionReset => {
                    log.debug("Error handling connection-level frame in phase 1: {s}\n", .{@errorName(err)});
                    return err;
                },
                error.UnexpectedEOF => {
                    log.debug("Client closed connection during frame processing\n", .{});
                    return err;
                },
                else => {
                    log.err("Error handling connection-level frame: {s}\n", .{@errorName(err)});
                    if (!self.goaway_sent) {
                        self.send_goaway(self.last_stream_id, error_code_from_error(err), "Connection-level error") catch {};
                        self.goaway_sent = true;
                    }
                    return err;
                },
            };
        }

        /// Handle stream-level frame during main processing
        fn handle_connection_original_phase_frames_stream_level(self: *@This(), frame: Frame) !void {
            if (self.goaway_received) {
                if (frame.header.stream_id > self.last_stream_id) {
                    log.debug("Ignoring frame on stream {d} as it exceeds last_stream_id {d}\n", .{ frame.header.stream_id, self.last_stream_id });
                    return;
                }
            }
            try handle_stream_level_frame(self, frame);
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
            
            // If we've also sent GOAWAY, or if there are no active streams, close the connection
            if (self.goaway_sent or self.streams.count() == 0) {
                self.connection_closed = true;
                log.debug("Connection marked for closure after GOAWAY (goaway_sent: {}, active_streams: {})\n", 
                         .{ self.goaway_sent, self.streams.count() });
            }
            
            return;
        }
        fn handle_stream_level_frame(self: *@This(), frame: Frame) !void {
            std.debug.assert(frame.header.stream_id > 0);

            try self.handle_stream_level_frame_validate(frame);
            try self.handle_stream_level_frame_check_closed_stream(frame);

            const stream = try self.handle_stream_level_frame_get_stream(frame);
            try self.handle_stream_level_frame_process(stream, frame);
            self.handle_stream_level_frame_update_continuation_state(frame);
        }

        /// Validate stream-level frame basic properties
        fn handle_stream_level_frame_validate(self: *@This(), frame: Frame) !void {
            if (!is_valid_frame_type(@intFromEnum(frame.header.frame_type))) {
                log.debug("Ignoring unknown stream-level frame type {d}\n", .{@intFromEnum(frame.header.frame_type)});
                return;
            }

            if (frame.header.stream_id == 0) {
                log.err("Received stream-level frame {d} with stream ID 0: PROTOCOL_ERROR\n", .{@intFromEnum(frame.header.frame_type)});
                try self.send_goaway(self.last_stream_id, 0x1, "Stream-level frame with stream ID 0: PROTOCOL_ERROR");
                return error.ProtocolError;
            }

            if (self.goaway_received) {
                if (frame.header.stream_id > self.last_stream_id) {
                    log.debug("Ignoring frame on stream {d} as it exceeds peer_last_stream_id {d}\n", .{ frame.header.stream_id, self.last_stream_id });
                    return;
                }
            }

            if (frame.header.frame_type == FrameType.PUSH_PROMISE) {
                log.err("Received PUSH_PROMISE frame from client on stream {d}: PROTOCOL_ERROR\n", .{frame.header.stream_id});
                try self.send_goaway(self.last_stream_id, 0x1, "Client sent PUSH_PROMISE: PROTOCOL_ERROR");
                self.goaway_sent = true;
                return error.ProtocolError;
            }
        }

        /// Check if frame is being sent to a closed stream
        fn handle_stream_level_frame_check_closed_stream(self: *@This(), frame: Frame) !void {
            if (!self.closed_stream_ids.contains(frame.header.stream_id)) {
                return;
            }

            const is_priority_frame = (frame.header.frame_type == FrameType.PRIORITY);
            const is_rst_stream_frame = (frame.header.frame_type == FrameType.RST_STREAM);

            if (is_priority_frame or is_rst_stream_frame) {
                log.debug("Ignoring frame type {d} on closed stream {d}\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id });
                return;
            }

            log.err("Received frame type {d} on closed stream {d}: STREAM_CLOSED\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id });
            try self.send_goaway(self.highest_stream_id(), 0x5, "Frame received on closed stream: STREAM_CLOSED");
            self.goaway_sent = true;
            return error.StreamClosed;
        }

        /// Retrieve stream for frame processing
        fn handle_stream_level_frame_get_stream(self: *@This(), frame: Frame) !*Stream {
            return self.get_stream(frame.header.stream_id) catch |err| {
                if (err == error.ProtocolError) {
                    return err;
                }
                if (err == error.MaxConcurrentStreamsExceeded) {
                    log.err("Cannot create stream {d}: Max concurrent streams exceeded.\n", .{frame.header.stream_id});
                    try self.send_rst_stream(frame.header.stream_id, 0x7);
                    log.debug("Sent RST_STREAM with REFUSED_STREAM (0x7) for stream ID {d}\n", .{frame.header.stream_id});
                    return err;
                }
                return err;
            };
        }

        /// Process frame within the stream and handle errors
        fn handle_stream_level_frame_process(self: *@This(), stream: *Stream, frame: Frame) !void {
            stream.handleFrame(frame) catch |err| {
                log.err("Error handling frame in stream {d}: {s}\n", .{ frame.header.stream_id, @errorName(err) });

                if (self.goaway_sent) {
                    return;
                }

                try self.handle_stream_level_frame_process_error(frame.header.stream_id, err);
            };
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
        fn process_pending_streams(self: *@This()) !void {
            var to_remove = std.ArrayList(u32).init(self.allocator);
            defer to_remove.deinit();
            var it = self.streams.iterator();
            while (it.next()) |entry| {
                const stream = entry.value_ptr.*;
                if (stream.request_complete and stream.state == .Closed) {
                    try to_remove.append(entry.key_ptr.*);
                }
            }
            // Remove the closed streams from the map and track them as closed
            for (to_remove.items) |stream_id| {
                _ = self.streams.remove(stream_id);
                try self.closed_stream_ids.put(stream_id, {});
                log.debug("Marked stream {d} as closed\n", .{stream_id});
            }
        }
        fn handle_connection_level_frame(self: *@This(), frame: Frame) !void {
            if (!is_valid_frame_type(@intFromEnum(frame.header.frame_type))) {
                // Unknown frame type, ignore as per RFC 7540 Section 5.5
                log.debug("Ignoring unknown connection-level frame type {d}\n", .{@intFromEnum(frame.header.frame_type)});
                return;
            }
            // Enforce stream_id == 0 for true connection-level frames.
            // WINDOW_UPDATE frames reach here only when stream_id == 0 due to routing logic.
            if (frame.header.stream_id != 0 and frame.header.frame_type != FrameType.WINDOW_UPDATE) {
                log.err("Received {d} frame with non-zero stream ID {d}: PROTOCOL_ERROR\n", .{ @intFromEnum(frame.header.frame_type), frame.header.stream_id });
                try self.send_goaway(self.last_stream_id, 0x1, "Frame with invalid stream ID: PROTOCOL_ERROR");
                return error.ProtocolError;
            }
            switch (frame.header.frame_type) {
                FrameType.SETTINGS => {
                    try self.apply_frame_settings(frame);
                    if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                        // Send SETTINGS ACK
                        try self.send_settings_ack();
                    }
                    // If ACK is set, no action needed
                },
                FrameType.PING => {
                    try handle_ping_frame(self, frame);
                },
                FrameType.WINDOW_UPDATE => {
                    try self.handle_window_update(frame);
                },
                FrameType.GOAWAY => {
                    try handle_goaway_frame(self, frame);
                },
                else => {
                    // Ignore unknown connection-level frame types as per RFC 7540 Section 6
                    log.warn("Received unknown connection-level frame type {d}, ignoring as per RFC 7540 Section 6\n", .{@intFromEnum(frame.header.frame_type)});
                    // No action needed; simply ignore and continue
                },
            }
        }
        fn handle_ping_frame(self: *@This(), frame: Frame) !void {
            // PING frames must have stream identifier 0x0
            if (frame.header.stream_id != 0) {
                log.err("PING frame with non-zero stream identifier {d}: PROTOCOL_ERROR\n", .{frame.header.stream_id});
                if (!self.goaway_sent) {
                    try self.send_goaway(0, 0x1, "PING frame with non-zero stream identifier: PROTOCOL_ERROR");
                    self.goaway_sent = true;
                }
                return; // Don't return error to avoid duplicate GOAWAY
            }
            // PING frame payload must be exactly 8 bytes
            if (frame.payload.len != 8) {
                log.err("PING frame with invalid payload length {d} (expected 8): FRAME_SIZE_ERROR\n", .{frame.payload.len});
                if (!self.goaway_sent) {
                    try self.send_goaway(0, 0x6, "PING frame with invalid payload length: FRAME_SIZE_ERROR");
                    self.goaway_sent = true;
                }
                return; // Don't return error to avoid duplicate GOAWAY
            }
            // Only respond if ACK flag is not set
            if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                try self.send_ping(frame.payload, true); // Send PING response with ACK
                log.debug("Responded to PING frame with ACK\n", .{});
            } else {
                log.debug("Received PING frame with ACK flag set, no response sent.\n", .{});
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
                error.BrokenPipe, error.ConnectionResetByPeer => {
                    log.debug("Client disconnected (BrokenPipe/ConnectionResetByPeer)\n", .{});
                    self.connection_closed = true;
                    return error.ConnectionReset;
                },
                else => {
                    log.err("Error receiving frame: {s}\n", .{@errorName(err)});
                    return err;
                },
            }
        }
        /// Sends a PING frame over the connection. The opaque data must always be exactly 8 bytes.
        /// If `ack` is true, the ACK flag will be set in the PING frame.
        /// The opaque data should be echoed exactly in case of a PING response.
        pub fn send_ping(self: *@This(), opaque_data: []const u8, ack: bool) !void {
            // Ensure the opaque data is 8 bytes long
            if (opaque_data.len != 8) {
                return error.InvalidPingPayloadSize;
            }
            var frame_header = FrameHeader{
                .length = 8, // PING payload length is always 8
                .frame_type = FrameType.PING,
                .flags = if (ack) FrameFlags{ .value = FrameFlags.ACK } else FrameFlags{ .value = 0 }, // Set ACK flag if true
                .reserved = false,
                .stream_id = 0, // PING frames must always be on stream 0
            };
            // Write the frame header
            try frame_header.write(self.writer);
            // Write the opaque data
            try self.writer.writeAll(opaque_data);
            log.debug("Sent PING frame (flags: {d}, opaque_data: {any})\n", .{ frame_header.flags.value, opaque_data });
        }

        pub fn process_request(self: *@This(), stream: *DefaultStream.StreamInstance) !void {
            log.debug("Processing request for stream ID: {d}, state: {s}", .{ stream.id, @tagName(stream.state) });

            // Prepare a basic response: "Hello, World!"
            const response_body =
                \\<!DOCTYPE html>
                \\<html>
                \\<body>
                \\<h1>Hello, World!</h1>
                \\</body>
                \\</html>
            ;
            const response_headers = [_]Hpack.HeaderField{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "text/html" },
            };

            // Use static buffer instead of dynamic allocation for HPACK encoding
            var header_buffer: [256]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&header_buffer);
            var buffer = std.ArrayList(u8).init(fba.allocator());

            // Encode headers into static buffer
            for (response_headers) |header| {
                try Hpack.encodeHeaderField(header, &self.hpack_dynamic_table, &buffer);
            }
            const encoded_headers = buffer.items;
            log.debug("Encoded {} header bytes for stream {}", .{ encoded_headers.len, stream.id });
            // Send HEADERS frame with pre-encoded static headers
            var headers_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(encoded_headers.len),
                    .frame_type = FrameType.HEADERS,
                    .flags = FrameFlags{
                        .value = FrameFlags.END_HEADERS, // Mark end of headers
                    },
                    .reserved = false,
                    .stream_id = stream.id,
                },
                .payload = encoded_headers,
            };
            log.debug("Sending HEADERS frame for stream {} ({} bytes)", .{ stream.id, encoded_headers.len });
            try headers_frame.write(self.writer);
            log.debug("HEADERS frame sent successfully for stream {}", .{stream.id});
            // Send DATA frame with "Hello, World!" response
            var data_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(response_body.len),
                    .frame_type = FrameType.DATA,
                    .flags = FrameFlags{
                        .value = FrameFlags.END_STREAM, // Mark end of stream
                    },
                    .reserved = false,
                    .stream_id = stream.id,
                },
                .payload = response_body,
            };
            log.debug("Sending DATA frame for stream {} ({} bytes)", .{ stream.id, response_body.len });
            try data_frame.write(self.writer);
            log.debug("DATA frame sent successfully for stream {}", .{stream.id});
            log.debug("Sent 200 OK response with body: \"Hello, World!\" for stream {}", .{stream.id});
            // Mark stream as closed after sending complete response
            // This allows the stream to be garbage collected properly
            if (stream.state == .Open) {
                stream.state = .Closed;
                log.debug("Stream {d}: Transitioned to Closed state after sending complete response", .{stream.id});
            } else if (stream.state == .HalfClosedRemote) {
                stream.state = .Closed;
                log.debug("Stream {d}: Transitioned to Closed state after sending complete response", .{stream.id});
            }
            
            // Immediately clean up completed streams to prevent accumulation
            self.process_pending_streams() catch |err| {
                log.err("Failed to clean up pending streams: {}", .{err});
            };
        }
        pub fn send_settings(self: *@This()) !void {
            const settings = [_][2]u32{
                .{ 1, self.settings.header_table_size }, // HEADER_TABLE_SIZE
                .{ 3, self.settings.max_concurrent_streams }, // MAX_CONCURRENT_STREAMS
                .{ 4, self.settings.initial_window_size }, // INITIAL_WINDOW_SIZE
                .{ 5, self.settings.max_frame_size }, // MAX_FRAME_SIZE
                .{ 6, self.settings.max_header_list_size }, // MAX_HEADER_LIST_SIZE
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

        pub fn receive_frame_arena(self: *@This()) !Frame {
            var header_buf: [9]u8 = undefined;
            // Read the frame header (9 bytes) in a loop to handle partial reads
            var header_read: usize = 0;
            while (header_read < 9) {
                const bytes_read = try self.reader.read(header_buf[header_read..]);
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                }
                header_read += bytes_read;
            }
            // Manually parse frame length (first 3 bytes)
            const length: u32 = (@as(u32, header_buf[0]) << 16) | (@as(u32, header_buf[1]) << 8) | @as(u32, header_buf[2]);
            if (length > max_frame_size_default) {
                log.err("Received frame size {d} exceeds compile-time limit {d}, sending GOAWAY\n", .{ length, max_frame_size_default });
                try self.send_goaway(self.highest_stream_id(), 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
                return error.FrameSizeError;
            }
            // Validate the length against the max_frame_size
            if (length > self.settings.max_frame_size) {
                log.err("Received frame size {d} exceeds SETTINGS_MAX_FRAME_SIZE {d}, sending GOAWAY\n", .{ length, self.settings.max_frame_size });
                try self.send_goaway(self.highest_stream_id(), 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
                return error.FrameSizeError;
            }
            const frame_type_u8: u8 = header_buf[3];
            const frame_type = FrameType.fromU8(frame_type_u8) orelse {
                log.err("Invalid frame type: {d}\n", .{frame_type_u8});
                return error.InvalidFrameType;
            };
            const flags = FrameFlags{ .value = header_buf[4] };
            // Parse the stream ID (last 4 bytes of the header) in big-endian
            const stream_id_u32 = std.mem.readInt(u32, header_buf[5..9], .big) & 0x7FFFFFFF;
            const stream_id: u32 = @intCast(stream_id_u32);
            const payload = try self.frame_arena.allocator().alloc(u8, length);
            var total_read: usize = 0;
            while (total_read < length) {
                const bytes_read = try self.reader.read(payload[total_read..]);
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                }
                total_read += bytes_read;
            }
            return Frame{
                .header = FrameHeader{
                    .length = length,
                    .frame_type = @enumFromInt(frame_type),
                    .flags = flags,
                    .stream_id = stream_id,
                    .reserved = false,
                },
                .payload = payload,
            };
        }
        pub fn receive_frame(self: *@This()) !Frame {
            var header_buf: [9]u8 = undefined;
            // Read the frame header (9 bytes) in a loop to handle partial reads
            var header_read: usize = 0;
            while (header_read < 9) {
                const bytes_read = try self.reader.read(header_buf[header_read..]);
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                }
                header_read += bytes_read;
            }
            // Manually parse frame length (first 3 bytes)
            const length: u32 = (@as(u32, header_buf[0]) << 16) | (@as(u32, header_buf[1]) << 8) | @as(u32, header_buf[2]);
            // Validate the length against the max_frame_size
            if (length > self.settings.max_frame_size) {
                log.err("Received frame size {d} exceeds SETTINGS_MAX_FRAME_SIZE {d}, sending GOAWAY\n", .{ length, self.settings.max_frame_size });
                try self.send_goaway(self.highest_stream_id(), 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
                return error.FrameSizeError;
            }
            const frame_type: u8 = header_buf[3];
            const flags = FrameFlags{ .value = header_buf[4] };
            // Parse the stream ID (last 4 bytes of the header) in big-endian
            const stream_id_u32 = std.mem.readInt(u32, header_buf[5..9], .big) & 0x7FFFFFFF;
            const stream_id: u32 = @intCast(stream_id_u32);
            // Read the frame payload in a loop to ensure all data is read
            const payload = try self.allocator.alloc(u8, length);
            var total_read: usize = 0;
            while (total_read < length) {
                const bytes_read = try self.reader.read(payload[total_read..]);
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                }
                total_read += bytes_read;
            }
            return Frame{
                .header = FrameHeader{
                    .length = length,
                    .frame_type = @enumFromInt(frame_type),
                    .flags = flags,
                    .stream_id = stream_id,
                    .reserved = false,
                },
                .payload = payload,
            };
        }
        fn from_int(val: u8) FrameType {
            return std.meta.int_to_enum(FrameType, val) catch undefined;
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

            while (index + 6 <= buffer_size_u32) {
                const setting_id_ptr: *const [2]u8 = @ptrCast(&buffer[index]);
                const setting_id = std.mem.readInt(u16, setting_id_ptr, .big);

                const setting_value_ptr: *const [4]u8 = @ptrCast(&buffer[index + 2]);
                const setting_value = std.mem.readInt(u32, setting_value_ptr, .big);

                try self.apply_frame_settings_process_single_parameter(setting_id, setting_value);
                index += 6;
            }
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

        /// Handle SETTINGS_HEADER_TABLE_SIZE
        fn apply_frame_settings_header_table_size(self: *@This(), value: u32) !void {
            self.settings.header_table_size = value;
            try self.hpack_dynamic_table.updateMaxSize(value);
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
            const max_window_size: u32 = 2147483647;
            if (value > max_window_size) {
                log.err("SETTINGS_INITIAL_WINDOW_SIZE too large {d}: FLOW_CONTROL_ERROR\n", .{value});
                if (!self.goaway_sent) {
                    try self.send_goaway(0, 0x3, "SETTINGS_INITIAL_WINDOW_SIZE too large: FLOW_CONTROL_ERROR");
                    self.goaway_sent = true;
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
            const max_window_size: i32 = 2147483647;
            const min_window_size: i32 = 0;

            var streams_iterator = self.streams.iterator();
            while (streams_iterator.next()) |entry| {
                const stream = entry.value_ptr.*;
                stream.recv_window_size += window_delta;

                if (stream.recv_window_size > max_window_size) {
                    log.err("Stream window size overflow on stream {d}: FLOW_CONTROL_ERROR\n", .{stream.id});
                    if (!self.goaway_sent) {
                        try self.send_goaway(0, 0x3, "Stream window size overflow: FLOW_CONTROL_ERROR");
                        self.goaway_sent = true;
                    }
                    return;
                }
                if (stream.recv_window_size < min_window_size) {
                    log.err("Stream window size underflow on stream {d}: FLOW_CONTROL_ERROR\n", .{stream.id});
                    if (!self.goaway_sent) {
                        try self.send_goaway(0, 0x3, "Stream window size underflow: FLOW_CONTROL_ERROR");
                        self.goaway_sent = true;
                    }
                    return;
                }
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
        pub fn send_settings_ack(self: *@This()) !void {
            if (self.goaway_sent) return;
            var frame_header = FrameHeader{
                .length = 0,
                .frame_type = FrameType.SETTINGS,
                .flags = FrameFlags{ .value = FrameFlags.ACK }, // Set ACK flag
                .reserved = false,
                .stream_id = 0,
            };
            frame_header.write(self.writer) catch |err| {
                if (err == error.BrokenPipe) {
                    log.err("Client disconnected (BrokenPipe)\n", .{});
                    return err;
                }
                return err;
            };
        }
        pub fn receive_settings(self: *@This()) !void {
            const settings_frame_header_size = 9;
            var frame_header: [settings_frame_header_size]u8 = undefined;
            _ = try self.reader.readAll(&frame_header);
            const length = std.mem.readInt(u24, frame_header[0..3], .big);
            if (length % 6 != 0) return error.InvalidSettingsFrameSize;
            var settings_payload: []u8 = try self.allocator.alloc(u8, length);
            defer self.allocator.free(settings_payload);
            _ = try self.reader.readAll(settings_payload);
            var i: usize = 0;
            while (i < settings_payload.len) {
                const setting = settings_payload[i .. i + 6];
                const id = std.mem.readInt(u16, setting[0..2], .big);
                const value = std.mem.readInt(u32, setting[2..6], .big);
                switch (id) {
                    1 => self.settings.header_table_size = value,
                    3 => self.settings.max_concurrent_streams = value,
                    4 => self.settings.initial_window_size = value,
                    5 => self.settings.max_frame_size = value,
                    6 => self.settings.max_header_list_size = value,
                    else => {},
                }
                i += 6;
            }
        }
        /// Sends a GOAWAY frame with the given parameters.
        pub fn send_goaway(self: *@This(), last_stream_id: u32, error_code: u32, debug_data: []const u8) !void {
            const payload_size = 8 + debug_data.len;
            assert(payload_size > 0);
            var payload = self.allocator.alloc(u8, payload_size) catch |err| {
                log.err("Failed to allocate memory for GOAWAY frame payload: {s}\n", .{@errorName(err)});
                return err;
            };
            defer self.allocator.free(payload);
            std.mem.writeInt(u32, payload[0..4], last_stream_id & 0x7FFFFFFF, .big);
            std.mem.writeInt(u32, payload[4..8], error_code, .big);
            if (debug_data.len > 0) {
                std.mem.copyForwards(u8, payload[8..], debug_data);
            }
            var goaway_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(payload_size),
                    .frame_type = FrameType.GOAWAY,
                    .flags = FrameFlags.init(0),
                    .reserved = false,
                    .stream_id = 0,
                },
                .payload = payload,
            };
            try goaway_frame.write(self.writer);
            self.goaway_sent = true;
        }
        pub fn close(self: *@This()) !void {
            if (self.connection_closed) {
                return; // Already closed
            }
            // Mark as closed to prevent double-closing
            self.connection_closed = true;
            // Determine the highest stream ID that was processed
            var stream_id: u32 = 0;
            var it = self.streams.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* > stream_id) {
                    stream_id = entry.key_ptr.*;
                }
            }
            // Error code 0 indicates graceful shutdown
            const error_code: u32 = 0; // 0: NO_ERROR, indicating graceful shutdown
            const debug_data = "Connection closing: graceful shutdown";
            // Send the GOAWAY frame with the highest stream ID and debug information
            if (!self.goaway_sent) {
                self.send_goaway(stream_id, error_code, debug_data) catch |err| {
                    log.debug("Failed to send GOAWAY frame: {any}\n", .{err});
                };
            }
            log.debug("Connection closed gracefully\n", .{});
        }
        pub fn get_stream(self: *@This(), stream_id: u32) !*DefaultStream.StreamInstance {
            // Ensure the stream ID is valid (odd numbers for client-initiated streams)
            if (stream_id % 2 == 0) {
                log.err("Received invalid stream ID {d} from client: PROTOCOL_ERROR\n", .{stream_id});
                try self.send_goaway(0, 0x1, "Invalid stream ID: PROTOCOL_ERROR");
                return error.ProtocolError;
            }
            // Check if the stream already exists
            if (self.streams.get(stream_id)) |stream| {
                return stream;
            } else {
                // Enforce the max concurrent streams limit
                if (self.streams.count() >= self.settings.max_concurrent_streams) {
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
                const new_stream = DefaultStream.init(self.allocator, self, stream_id) catch |err| {
                    log.err("Failed to initialize stream {d}: {s}\n", .{ stream_id, @errorName(err) });
                    return err;
                };
                try self.streams.put(stream_id, new_stream);
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
                return; // Don't return error to avoid duplicate GOAWAY
            }
            const increment = std.mem.readInt(u32, frame.payload[0..4], .big);
            // **Check if increment is zero**
            if (increment == 0) {
                log.err("Received WINDOW_UPDATE with increment 0, sending GOAWAY: PROTOCOL_ERROR.\n", .{});
                if (!self.goaway_sent) {
                    try self.send_goaway(self.highest_stream_id(), 0x1, "WINDOW_UPDATE with increment 0: PROTOCOL_ERROR");
                    self.goaway_sent = true;
                }
                return; // Don't return error to avoid duplicate GOAWAY
            }
            if (increment > 0x7FFFFFFF) { // Maximum allowed value
                log.err("Received WINDOW_UPDATE with increment exceeding maximum value, sending GOAWAY: FLOW_CONTROL_ERROR.\n", .{});
                if (!self.goaway_sent) {
                    try self.send_goaway(self.highest_stream_id(), 0x3, "WINDOW_UPDATE increment too large: FLOW_CONTROL_ERROR");
                    self.goaway_sent = true;
                }
                return; // Don't return error to avoid duplicate GOAWAY
            }
            if (frame.header.stream_id == 0) {
                self.update_send_window(@intCast(increment)) catch |err| {
                    if (err == error.FlowControlError) {
                        // GOAWAY already sent by update_send_window
                        return;
                    }
                    return err;
                };
            } else {
                // Forward to the appropriate stream for handling
                var stream = self.get_stream(frame.header.stream_id) catch {
                    // get_stream may send GOAWAY, so just return
                    return;
                };
                stream.updateSendWindow(@intCast(increment)) catch |err| {
                    if (err == error.FlowControlError) {
                        // Send GOAWAY for stream-level flow control error
                        if (!self.goaway_sent) {
                            try self.send_goaway(self.highest_stream_id(), 0x3, "Stream flow control error: FLOW_CONTROL_ERROR");
                            self.goaway_sent = true;
                        }
                        return;
                    }
                    return err;
                };
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
}
const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 50,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
    pub fn default() Settings {
        return Settings{};
    }
};
/// Determines if a frame type is always connection-level (stream ID must be 0).
/// Note: WINDOW_UPDATE can be both connection-level and stream-level depending on stream ID.
fn is_connection_level_frame(frame_type: u8) bool {
    return switch (frame_type) {
        @intFromEnum(FrameType.SETTINGS), @intFromEnum(FrameType.PING), @intFromEnum(FrameType.GOAWAY) => true,
        else => false,
    };
}

fn is_valid_frame_type(frame_type: u8) bool {
    return FrameHandler.fromFrameType(frame_type) != null;
}

inline fn is_valid_frame_type_inline(comptime frame_type: u8) bool {
    return comptime FrameHandler.fromFrameType(frame_type) != null;
}
/// Ensure valid flags for frame types.
fn is_valid_flags(header: FrameHeader) bool {
    const flags = header.flags.value;
    // Get the allowed flags for the frame type
    const allowed_flags = switch (header.frame_type) {
        @intFromEnum(FrameType.DATA) => FrameFlags.END_STREAM | FrameFlags.PADDED,
        @intFromEnum(FrameType.HEADERS) => FrameFlags.END_STREAM | FrameFlags.END_HEADERS | FrameFlags.PADDED | FrameFlags.PRIORITY,
        @intFromEnum(FrameType.PRIORITY) => 0,
        FrameType.RST_STREAM => 0,
        FrameType.SETTINGS => FrameFlags.ACK,
        FrameType.PUSH_PROMISE => FrameFlags.END_HEADERS | FrameFlags.PADDED,
        FrameType.PING => FrameFlags.ACK,
        FrameType.GOAWAY => 0,
        FrameType.WINDOW_UPDATE => 0,
        FrameType.CONTINUATION => FrameFlags.END_HEADERS,
        else => 0, // Unknown frame types have no allowed flags
    };
    // Return true if no invalid flags are set
    return (flags & ~allowed_flags) == 0;
}
test "HTTP/2 connection initialization and flow control" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [8192]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);
    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();
    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    const allocator = arena.allocator();
    var connection = try ConnectionType.init(allocator, reader, writer, false); // Use client mode to avoid preface reading
    // Initialize stream
    var stream = try DefaultStream.init(allocator, &connection, 1);
    const preface_written_data = buffer_stream.getWritten();
    // Encode headers using Hpack.encodeHeaderField (request headers for client)
    const request_headers = [_]Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var encoded_headers = std.ArrayList(u8).init(allocator);
    defer encoded_headers.deinit();
    for (request_headers) |header| {
        try Hpack.encodeHeaderField(header, &connection.hpack_dynamic_table, &encoded_headers);
    }
    const headers_payload = try encoded_headers.toOwnedSlice();
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
    // Check if headers were written
    const headers_written_data = buffer_stream.getWritten();
    // Ensure headers frame was actually written
    assert(headers_written_data.len > preface_written_data.len);
    // Send data
    const data = "Hello, world!";
    try connection.send_data(stream, data, false);
    const written_data = buffer_stream.getWritten();
    // Verify response was written (should include preface + settings + response headers + response data)
    const preface_length = 24; // 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' is 24 bytes
    const settings_frame_length = 39; // As per debug output
    const min_expected_length = preface_length + settings_frame_length + 40; // At least preface + settings + some response
    assert(written_data.len >= min_expected_length); // Should include server response
    // Clear buffer for next operations
    buffer_stream.reset();
    // Check that data was sent after reset
    const data_after_reset = "Hello again!";
    try connection.send_data(stream, data_after_reset, false);
    const sent_data = buffer_stream.getWritten();
    assert(sent_data.len > 0);
    // Simulate receiving a WINDOW_UPDATE frame to increase send window size
    const window_update_frame = Frame{
        .header = FrameHeader{
            .length = 4,
            .frame_type = FrameType.WINDOW_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0, // Connection-level window update
        },
        .payload = &[_]u8{ 0x00, 0x00, 0x01, 0x00 },
    };
    try connection.handle_window_update(window_update_frame);
    // After handling WINDOW_UPDATE, we should be able to send more data
    try connection.send_data(stream, data_after_reset, false);
    const sent_data_after_window_update = buffer_stream.getWritten();
    assert(sent_data_after_window_update.len > sent_data.len);
}
test "apply_frame_settings test" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const reader = stream.reader().any();
    const writer = stream.writer().any();
    const alloc = arena.allocator();
    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var connection = try ConnectionType.init(alloc, reader, writer, false);
    // Frame with the SETTINGS type and 18 bytes of payload
    const frame = Frame{
        .header = FrameHeader{
            .length = 18, // 3 settings of 6 bytes each
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
test "send HEADERS and DATA frames with proper flow" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [8192]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);
    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();
    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    const allocator = arena.allocator();
    var connection = try ConnectionType.init(allocator, reader, writer, false);
    var stream = try DefaultStream.init(allocator, &connection, 1);
    // Send a HEADERS frame with valid header block
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
    // Handle HEADERS frame
    try stream.handleFrame(headers_frame);
    // Check that the HEADERS frame was processed before continuing
    const headers_written_data = buffer_stream.getWritten();
    assert(headers_written_data.len > 0);
    // Now send the DATA frame only after ensuring the HEADERS frame was handled
    const data = "Hello, world!";
    try connection.send_data(stream, data, false);
    const written_data = buffer_stream.getWritten();
    assert(written_data.len > headers_written_data.len);
}
test "send RST_STREAM frame with correct frame_type" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var buffer: [1024]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);
    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();
    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    const allocator = arena.allocator();
    var connection = try ConnectionType.init(allocator, reader, writer, false);
    var stream = try DefaultStream.init(allocator, &connection, 1);
    // Get initial buffer position (after preface and settings)
    const initial_pos = buffer_stream.getWritten().len;
    // Send RST_STREAM
    try stream.sendRstStream(0x1); // PROTOCOL_ERROR
    // Check the buffer to ensure frame_type is 3
    const written_data = buffer_stream.getWritten();
    // Frame header is 9 bytes: length (3), type (1), flags (1), stream_id (4)
    // RST_STREAM frame starts at initial_pos, so frame type is at initial_pos + 3
    try std.testing.expectEqual(written_data[initial_pos + 3], 3); // frame_type = 3 for RST_STREAM
}
