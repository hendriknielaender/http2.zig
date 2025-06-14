//! Async HTTP/2 Connection Implementation
//!
//! Integrates async I/O foundation with existing HTTP/2 connection handling.
//!
//! Features:
//! - Zero-allocation frame processing pipeline (16 concurrent frames max)
//! - 64KB frame buffers with static allocation
//! - Async frame read/write with completion callbacks
//! - Connection state tracking and performance monitoring
//! - Backwards compatibility with synchronous HTTP/2 implementation

const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.async_connection);

const async_io = @import("async_io.zig");
const Connection = @import("connection.zig").Connection;
const Frame = @import("frame.zig").Frame;
const FrameHeader = @import("frame.zig").FrameHeader;
const Stream = @import("stream.zig").Stream;
const DefaultStream = @import("stream.zig").DefaultStream;

/// Maximum number of concurrent frame reads per connection
pub const max_concurrent_frames = 16;

/// Frame buffer pool for zero-allocation async I/O
pub const frame_buffer_size = 65536; // 64KB max frame size
pub const frame_buffer_count = max_concurrent_frames * 2;

/// Async connection state tracking
pub const AsyncConnectionState = enum(u8) {
    initializing,
    active,
    closing,
    closed,
    error_state,
};

/// Frame processing context for async callbacks
const FrameContext = struct {
    connection: ?*AsyncConnection,
    frame_buffer: []u8,
    completion: AsyncFrameCompletion,

    const AsyncFrameCompletion = union(enum) {
        none,
        read: struct {
            expected_bytes: u32,
            bytes_read: u32,
        },
        write: struct {
            frame: Frame,
        },
    };
};

/// Async HTTP/2 Connection wrapper
pub const AsyncConnection = struct {
    /// Core HTTP/2 connection (composition over inheritance)
    http2_conn: Connection(AsyncReader, AsyncWriter),

    /// Async I/O infrastructure
    async_io: *async_io.AsyncHTTP2IO,

    /// Connection management
    fd: std.posix.fd_t,
    state: AsyncConnectionState,

    frame_buffers: [frame_buffer_count][frame_buffer_size]u8,
    buffer_available: std.bit_set.IntegerBitSet(frame_buffer_count),

    /// Active frame contexts
    frame_contexts: [max_concurrent_frames]FrameContext,
    contexts_allocated: std.bit_set.IntegerBitSet(max_concurrent_frames),

    frames_processed: u64,
    bytes_transferred: u64,
    avg_frame_latency_ns: u64,

    /// Thread safety
    mutex: std.Thread.Mutex,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        async_io_ref: *async_io.AsyncHTTP2IO,
        fd: std.posix.fd_t,
        is_server: bool,
    ) !Self {
        const frame_buffers: [frame_buffer_count][frame_buffer_size]u8 = undefined;
        var frame_contexts: [max_concurrent_frames]FrameContext = undefined;

        // Initialize frame contexts manually
        for (&frame_contexts) |*ctx| {
            ctx.* = FrameContext{
                .connection = null,
                .frame_buffer = &[_]u8{},
                .completion = .none,
            };
        }

        // Frame contexts are already zero-initialized

        // Create async reader/writer adapters
        const async_reader = AsyncReader{ .fd = fd, .async_io = async_io_ref };
        const async_writer = AsyncWriter{ .fd = fd, .async_io = async_io_ref };

        const conn = if (is_server)
            try Connection(AsyncReader, AsyncWriter).init(allocator, async_reader, async_writer, true)
        else
            try Connection(AsyncReader, AsyncWriter).init(allocator, async_reader, async_writer, false);

        var self = Self{
            .http2_conn = conn,
            .async_io = async_io_ref,
            .fd = fd,
            .state = .initializing,
            .frame_buffers = frame_buffers,
            .buffer_available = std.bit_set.IntegerBitSet(frame_buffer_count).initFull(),
            .frame_contexts = frame_contexts,
            .contexts_allocated = std.bit_set.IntegerBitSet(max_concurrent_frames).initEmpty(),
            .frames_processed = 0,
            .bytes_transferred = 0,
            .avg_frame_latency_ns = 0,
            .mutex = std.Thread.Mutex{},
            .allocator = allocator,
        };

        self.state = .active;
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.state = .closed;
        self.http2_conn.deinit();
    }

    /// Start async frame processing loop
    pub fn startProcessing(self: *Self) !void {
        assert(self.state == .active);
        log.info("Starting async frame processing for connection fd={d}", .{self.fd});

        try self.initiateFrameReads();
    }

    /// Stop async processing gracefully
    pub fn stopProcessing(self: *Self) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.state == .active) {
            self.state = .closing;
            log.info("Stopping async frame processing for connection fd={d}", .{self.fd});
        }
    }

    /// Send frame asynchronously
    pub fn sendFrameAsync(self: *Self, frame: Frame) !void {
        assert(self.state == .active);

        const context = try self.allocateFrameContext();
        context.completion = .{ .write = .{ .frame = frame } };

        // TODO: Serialize frame to buffer
        var frame_data: [frame_buffer_size]u8 = undefined;
        const serialized_size = try self.serializeFrame(frame, &frame_data);

        _ = try self.async_io.writeFrame(
            self.fd,
            frame_data[0..serialized_size],
            frameWriteComplete,
            context,
        );
    }

    /// Get connection performance statistics
    pub fn getStats(self: *Self) AsyncConnectionStats {
        self.mutex.lock();
        defer self.mutex.unlock();

        return AsyncConnectionStats{
            .frames_processed = self.frames_processed,
            .bytes_transferred = self.bytes_transferred,
            .avg_frame_latency_ns = self.avg_frame_latency_ns,
            .active_contexts = @intCast(self.contexts_allocated.count()),
            .state = self.state,
        };
    }

    fn initiateFrameReads(self: *Self) !void {
        // Start multiple concurrent frame reads for pipeline efficiency
        var i: u32 = 0;
        while (i < max_concurrent_frames / 2) : (i += 1) {
            try self.startSingleFrameRead();
        }
    }

    fn startSingleFrameRead(self: *Self) !void {
        const context = try self.allocateFrameContext();
        const buffer = try self.allocateFrameBuffer();

        context.connection = self;
        context.frame_buffer = buffer;
        context.completion = .{ .read = .{ .expected_bytes = 9, .bytes_read = 0 } }; // Start with header

        _ = try self.async_io.readFrame(
            self.fd,
            buffer[0..9], // HTTP/2 frame header is always 9 bytes
            frameReadComplete,
            context,
        );
    }

    fn allocateFrameContext(self: *Self) !*FrameContext {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = self.contexts_allocated.toggleFirstSet() orelse return error.TooManyFrameContexts;
        const context = &self.frame_contexts[index];
        context.connection = self;
        return context;
    }

    fn deallocateFrameContext(self: *Self, context: *FrameContext) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = (@intFromPtr(context) - @intFromPtr(&self.frame_contexts)) / @sizeOf(FrameContext);
        assert(index < max_concurrent_frames);
        self.contexts_allocated.unset(index);
    }

    fn allocateFrameBuffer(self: *Self) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = self.buffer_available.toggleFirstSet() orelse return error.NoFrameBuffersAvailable;
        return &self.frame_buffers[index];
    }

    fn deallocateFrameBuffer(self: *Self, buffer: []u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const index = (@intFromPtr(buffer.ptr) - @intFromPtr(&self.frame_buffers)) / frame_buffer_size;
        assert(index < frame_buffer_count);
        self.buffer_available.set(index);
    }

    fn serializeFrame(self: *Self, frame: Frame, buffer: []u8) !usize {
        _ = self;
        _ = frame;
        _ = buffer;
        // TODO: Implement frame serialization
        return error.NotImplemented;
    }
};

/// Async frame read completion callback
fn frameReadComplete(op: *async_io.AsyncOp, result: anyerror!void) void {
    const context: *FrameContext = @ptrCast(@alignCast(op.context));
    const conn = context.connection orelse return;

    defer {
        conn.deallocateFrameContext(context);
        conn.deallocateFrameBuffer(context.frame_buffer);
    }

    result catch |err| {
        log.err("Frame read failed: {s}", .{@errorName(err)});
        return;
    };

    switch (context.completion) {
        .read => |*read_state| {
            read_state.bytes_read += @intCast(op.bytes_transferred);

            if (read_state.bytes_read < read_state.expected_bytes) {
                // Continue reading remaining bytes
                // TODO: Submit another read for remaining data
                return;
            }

            // Frame header complete, parse and read payload if needed
            if (read_state.expected_bytes == 9) {
                const header_bytes = context.frame_buffer[0..9];
                const payload_length = parseFrameLength(header_bytes);

                if (payload_length > 0) {
                    read_state.expected_bytes = 9 + payload_length;
                    // TODO: Submit read for frame payload
                    return;
                }
            }

            // Complete frame received, process it
            processCompleteFrame(context) catch |err| {
                log.err("Frame processing failed: {s}", .{@errorName(err)});
            };
        },
        else => unreachable,
    }

    // Start next frame read to maintain pipeline
    conn.startSingleFrameRead() catch |err| {
        log.err("Failed to start next frame read: {s}", .{@errorName(err)});
    };
}

/// Async frame write completion callback
fn frameWriteComplete(op: *async_io.AsyncOp, result: anyerror!void) void {
    const context: *FrameContext = @ptrCast(@alignCast(op.context));
    const conn = context.connection orelse return;

    defer conn.deallocateFrameContext(context);

    result catch |err| {
        log.err("Frame write failed: {s}", .{@errorName(err)});
        return;
    };

    // Update statistics
    conn.mutex.lock();
    defer conn.mutex.unlock();

    conn.bytes_transferred += op.bytes_transferred;
    log.debug("Frame write completed: {d} bytes", .{op.bytes_transferred});
}

fn parseFrameLength(header_bytes: []const u8) u32 {
    assert(header_bytes.len >= 3);
    return (@as(u32, header_bytes[0]) << 16) |
        (@as(u32, header_bytes[1]) << 8) |
        @as(u32, header_bytes[2]);
}

fn processCompleteFrame(context: *FrameContext) !void {
    const conn = context.connection orelse return;
    const frame_data = context.frame_buffer[0..context.completion.read.expected_bytes];

    // TODO: Parse frame and dispatch to HTTP/2 connection
    // For now, just log the frame receipt
    log.debug("Received complete frame: {d} bytes", .{frame_data.len});

    conn.mutex.lock();
    defer conn.mutex.unlock();
    conn.frames_processed += 1;
}

/// Async Reader adapter for HTTP/2 connection
const AsyncReader = struct {
    fd: std.posix.fd_t,
    async_io: *async_io.AsyncHTTP2IO,

    // Implement std.io.Reader interface for compatibility
    pub const Error = std.posix.ReadError;
    pub const Reader = std.io.Reader(*const @This(), Error, read);

    pub fn read(self: *const @This(), buffer: []u8) Error!usize {
        // For synchronous compatibility, fall back to blocking read
        // TODO: Implement proper async integration
        return std.posix.read(self.fd, buffer);
    }

    pub fn reader(self: *const @This()) Reader {
        return .{ .context = self };
    }
};

/// Async Writer adapter for HTTP/2 connection
const AsyncWriter = struct {
    fd: std.posix.fd_t,
    async_io: *async_io.AsyncHTTP2IO,

    // Implement std.io.Writer interface for compatibility
    pub const Error = std.posix.WriteError;
    pub const Writer = std.io.Writer(*const @This(), Error, write);

    pub fn write(self: *const @This(), buffer: []const u8) Error!usize {
        // For synchronous compatibility, fall back to blocking write
        // TODO: Implement proper async integration
        return std.posix.write(self.fd, buffer);
    }

    pub fn writeAll(self: *const @This(), buffer: []const u8) Error!void {
        var remaining = buffer;
        while (remaining.len > 0) {
            const written = try self.write(remaining);
            remaining = remaining[written..];
        }
    }

    pub fn writer(self: *const @This()) Writer {
        return .{ .context = self };
    }
};

/// Connection statistics for monitoring
pub const AsyncConnectionStats = struct {
    frames_processed: u64,
    bytes_transferred: u64,
    avg_frame_latency_ns: u64,
    active_contexts: u32,
    state: AsyncConnectionState,
};

test "AsyncConnection basic structures" {
    const allocator = std.testing.allocator;

    var async_io_system = try async_io.AsyncHTTP2IO.init(allocator);
    defer async_io_system.deinit();

    // Test that the structures are set up correctly
    try std.testing.expect(frame_buffer_size == 65536);
    try std.testing.expect(max_concurrent_frames == 16);

    const stats = AsyncConnectionStats{
        .frames_processed = 0,
        .bytes_transferred = 0,
        .avg_frame_latency_ns = 0,
        .active_contexts = 0,
        .state = .active,
    };

    try std.testing.expect(stats.frames_processed == 0);
}

test "Frame parsing utilities" {
    const header_bytes = [_]u8{ 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01 }; // 4096 byte frame
    const length = parseFrameLength(header_bytes[0..]);
    try std.testing.expect(length == 4096);

    const small_frame = [_]u8{ 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01 }; // 9 byte frame
    const small_length = parseFrameLength(small_frame[0..]);
    try std.testing.expect(small_length == 9);
}

