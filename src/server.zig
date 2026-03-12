//! Proper libxev HTTP/2 server implementation for cross-platform support
//! Uses libxev's native backends: io_uring (Linux), kqueue (macOS), epoll (Linux fallback)

const std = @import("std");
const xev = @import("xev");
const builtin = @import("builtin");

const Frame = @import("frame.zig").Frame;
const FrameHeader = @import("frame.zig").FrameHeader;
const FrameType = @import("frame.zig").FrameType;
const FrameFlags = @import("frame.zig").FrameFlags;
const budget_assertions = @import("budget_assertions.zig");
const tls = @import("tls.zig");
const boringssl = @import("bindings/boringssl-bindings.zig");
const ThreadPool = xev.ThreadPool;
const handler = @import("handler.zig");
const Hpack = @import("hpack.zig").Hpack;
const DefaultStream = @import("stream.zig").DefaultStream;
const connection_module = @import("connection.zig");
const io_adapters = @import("io_adapters.zig");

pub const Server = struct {
    // Core infrastructure - use pointers for proper initialization
    thread_pool: *ThreadPool,
    loop: *xev.Loop,
    server_tcp: xev.TCP,

    // TLS support (optional)
    tls_ctx: ?*tls.TlsServerContext,

    // Request routing
    router: *handler.Router,

    // Configuration and state
    config: Config,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),
    initialized: std.atomic.Value(bool),

    // Completions for server operations - allocate separate instances to avoid reuse
    accept_completions: [2]xev.Completion,
    current_accept_completion: std.atomic.Value(u8),
    accept_active: std.atomic.Value(bool),

    // Connection management
    connections: std.ArrayList(*Connection),
    connection_pool: ConnectionPool,

    // Statistics
    stats: Stats,

    const Self = @This();

    pub const Config = struct {
        address: std.net.Address,
        router: *handler.Router,
        max_connections: u32 = 1000,
        buffer_size: u32 = 32 * 1024,
    };

    const Stats = struct {
        total_connections: std.atomic.Value(u64),
        active_connections: std.atomic.Value(u32),
        requests_processed: std.atomic.Value(u64),

        fn init() Stats {
            return .{
                .total_connections = std.atomic.Value(u64).init(0),
                .active_connections = std.atomic.Value(u32).init(0),
                .requests_processed = std.atomic.Value(u64).init(0),
            };
        }
    };

    fn assertConfigBounds(config: Config) void {
        std.debug.assert(config.max_connections > 0);
        std.debug.assert(config.max_connections <= 10000);
        std.debug.assert(config.buffer_size >= 1024);
        std.debug.assert(config.buffer_size <= 1024 * 1024);
        std.debug.assert(@intFromPtr(config.router) != 0);
    }

    fn assertInitializationInvariants(thread_pool: *ThreadPool, loop: *xev.Loop) void {
        std.debug.assert(@intFromPtr(thread_pool) != 0);
        std.debug.assert(@intFromPtr(loop) != 0);
    }

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        budget_assertions.validateAll();
        assertConfigBounds(config);

        // Allocate thread pool on heap to ensure proper lifetime
        const thread_pool = try allocator.create(ThreadPool);
        errdefer allocator.destroy(thread_pool);

        // Initialize thread pool
        const thread_pool_config = ThreadPool.Config{};
        thread_pool.* = ThreadPool.init(thread_pool_config);

        // Allocate loop on heap
        const loop = try allocator.create(xev.Loop);
        errdefer {
            thread_pool.deinit();
            allocator.destroy(thread_pool);
            allocator.destroy(loop);
        }

        loop.* = try xev.Loop.init(.{ .thread_pool = thread_pool });
        const server_tcp = try xev.TCP.init(config.address);
        assertInitializationInvariants(thread_pool, loop);

        return Self{
            .thread_pool = thread_pool,
            .loop = loop,
            .server_tcp = server_tcp,
            .tls_ctx = null,
            .router = config.router,
            .config = config,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
            .initialized = std.atomic.Value(bool).init(false),
            .accept_completions = [2]xev.Completion{ .{}, .{} },
            .current_accept_completion = std.atomic.Value(u8).init(0),
            .accept_active = std.atomic.Value(bool).init(false),
            .connections = .{},
            .connection_pool = try ConnectionPool.init(allocator, config.max_connections, config.buffer_size),
            .stats = Stats.init(),
        };
    }

    pub fn initWithTLS(allocator: std.mem.Allocator, config: Config, tls_ctx: *tls.TlsServerContext) !Self {
        std.debug.assert(@intFromPtr(tls_ctx) != 0);
        budget_assertions.validateAll();
        assertConfigBounds(config);

        // Allocate thread pool on heap to ensure proper lifetime
        const thread_pool = try allocator.create(ThreadPool);
        errdefer allocator.destroy(thread_pool);

        // Initialize thread pool
        const thread_pool_config = ThreadPool.Config{};
        thread_pool.* = ThreadPool.init(thread_pool_config);

        // Allocate loop on heap
        const loop = try allocator.create(xev.Loop);
        errdefer {
            thread_pool.deinit();
            allocator.destroy(thread_pool);
            allocator.destroy(loop);
        }

        loop.* = try xev.Loop.init(.{ .thread_pool = thread_pool });
        const server_tcp = try xev.TCP.init(config.address);
        assertInitializationInvariants(thread_pool, loop);

        return Self{
            .thread_pool = thread_pool,
            .loop = loop,
            .server_tcp = server_tcp,
            .tls_ctx = tls_ctx,
            .router = config.router,
            .config = config,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
            .initialized = std.atomic.Value(bool).init(false),
            .accept_completions = [2]xev.Completion{ .{}, .{} },
            .current_accept_completion = std.atomic.Value(u8).init(0),
            .accept_active = std.atomic.Value(bool).init(false),
            .connections = .{},
            .connection_pool = try ConnectionPool.init(allocator, config.max_connections, config.buffer_size),
            .stats = Stats.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        self.connection_pool.deinit();
        self.connections.deinit(self.allocator);
        self.loop.deinit();
        self.thread_pool.shutdown();
        self.thread_pool.deinit();
        self.allocator.destroy(self.loop);
        self.allocator.destroy(self.thread_pool);
    }

    pub fn run(self: *Self) !void {
        self.running.store(true, .release);
        defer self.running.store(false, .release);

        // Bind and listen
        try self.server_tcp.bind(self.config.address);
        try self.server_tcp.listen(4096);

        if (self.tls_ctx) |_| {
            std.log.info("Libxev HTTP/2 over TLS server listening on {f} (cross-platform)", .{self.config.address});
            std.log.info("TLS with ALPN h2 negotiation enabled for browsers", .{});
        } else {
            std.log.info("Libxev HTTP/2 server listening on {f} (cross-platform)", .{self.config.address});
        }

        // Start accepting connections
        self.scheduleAcceptRetry();

        // Run the libxev event loop
        try self.loop.run(.until_done);
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .release);
        self.loop.stop();
    }

    pub fn getStats(self: *Self) ServerStats {
        // Ensure atomic loads are safe even during initialization
        return .{
            .total_connections = self.stats.total_connections.load(.acquire),
            .active_connections = self.stats.active_connections.load(.acquire),
            .requests_processed = self.stats.requests_processed.load(.acquire),
        };
    }

    /// Accept the next connection
    fn acceptNext(self: *Self) void {
        if (!self.running.load(.acquire)) return;

        // Prevent double submission of accept
        if (self.accept_active.swap(true, .acquire)) {
            return; // Accept already in progress
        }

        // Use ping-pong completion pattern to avoid reuse issues in release mode
        const completion_idx = self.current_accept_completion.fetchAdd(1, .monotonic) % 2;
        const completion = &self.accept_completions[completion_idx];

        // Always reinitialize completion to ensure clean state
        completion.* = .{};

        self.server_tcp.accept(
            self.loop,
            completion,
            Self,
            self,
            acceptCallback,
        );
    }

    /// Schedule accept retry - now safe with ping-pong completions
    fn scheduleAcceptRetry(self: *Self) void {
        if (!self.running.load(.acquire)) return;

        // With ping-pong completions, we can safely retry immediately in all modes
        self.acceptNext();
    }

    /// Accept callback - called when a new connection is accepted.
    fn acceptCallback(
        self_opt: ?*Self,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.AcceptError!xev.TCP,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;

        const self = self_opt.?;

        // Assert critical state invariants.
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(self.running.load(.acquire));

        // Mark accept as completed.
        self.accept_active.store(false, .release);

        const client_tcp = result catch |err| {
            std.log.warn("Accept failed: {}", .{err});
            self.scheduleAcceptRetry();
            return .disarm;
        };

        const conn = self.acquireConnection() orelse {
            self.scheduleAcceptRetry();
            return .disarm;
        };

        self.initializeConnection(conn, client_tcp);

        self.trackConnection(conn) catch {
            self.releaseConnection(conn);
            self.scheduleAcceptRetry();
            return .disarm;
        };

        self.updateConnectionStats(conn);

        // Start reading from the new connection.
        conn.startReading();

        // Continue accepting new connections.
        self.scheduleAcceptRetry();

        return .disarm;
    }

    /// Acquire a connection from the pool.
    fn acquireConnection(self: *Self) ?*Connection {
        std.debug.assert(@intFromPtr(self) != 0);

        const conn = self.connection_pool.acquire() orelse {
            std.log.warn("Connection pool exhausted, max connections reached", .{});
            return null;
        };

        // Assert connection validity.
        std.debug.assert(@intFromPtr(conn) != 0);
        std.debug.assert(!conn.active);

        return conn;
    }

    /// Initialize a new connection with the given TCP socket.
    fn initializeConnection(self: *Self, conn: *Connection, client_tcp: xev.TCP) void {
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(@intFromPtr(conn) != 0);
        std.debug.assert(!conn.active);

        conn.* = Connection{
            .server = self,
            .tcp = client_tcp,
            .tls_conn = null,
            .read_buffer = conn.read_buffer,
            .write_buffer = conn.write_buffer,
            .read_start = 0,
            .read_pos = 0,
            .write_start = 0,
            .write_pos = 0,
            .h2_conn = null,
            .h2_reader = undefined,
            .h2_writer = undefined,
            .active = true,
            .http2_initialized = false,
            .tls_handshake_complete = false,
            .tls_handshake_attempts = 0,
            .close_after_write = false,
            .negotiated_protocol = null,
            .next_stream_id = 1,
            .active_streams = std.AutoHashMap(u32, StreamState).init(self.allocator),
            .read_completions = [2]xev.Completion{ .{}, .{} },
            .write_completions = [2]xev.Completion{ .{}, .{} },
            .shutdown_completion = .{},
            .close_completion = .{},
            .current_read_completion = std.atomic.Value(u8).init(0),
            .current_write_completion = std.atomic.Value(u8).init(0),
            .read_active = std.atomic.Value(bool).init(false),
            .write_active = std.atomic.Value(bool).init(false),
            .tls_plaintext_buffer = conn.tls_plaintext_buffer,
            .tls_plaintext_read_pos = 0,
            .tls_plaintext_write_pos = 0,
            .write_side_shutdown = false,
            .awaiting_peer_close = false,
        };

        conn.h2_reader = Connection.IoAdapters.Reader.init(conn);
        conn.h2_writer = Connection.IoAdapters.Writer.init(conn);

        std.debug.assert(conn.active);
    }

    /// Track a connection in the active connections list.
    fn trackConnection(self: *Self, conn: *Connection) !void {
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(@intFromPtr(conn) != 0);
        std.debug.assert(conn.active);

        self.connections.append(self.allocator, conn) catch |err| {
            std.log.warn("Failed to track connection: {}", .{err});
            return err;
        };
    }

    /// Release a connection back to the pool.
    fn releaseConnection(self: *Self, conn: *Connection) void {
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(@intFromPtr(conn) != 0);

        conn.active = false;
        self.connection_pool.release(conn);
    }

    /// Update connection statistics.
    fn updateConnectionStats(self: *Self, conn: *Connection) void {
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(@intFromPtr(conn) != 0);
        std.debug.assert(conn.active);

        const total_before = self.stats.total_connections.fetchAdd(1, .monotonic);
        const active_before = self.stats.active_connections.fetchAdd(1, .monotonic);

        std.log.info("Accepted new connection {} (total: {}, active: {})", .{ conn.tcp.fd, total_before + 1, active_before + 1 });

        // Assert reasonable connection counts.
        std.debug.assert(total_before < std.math.maxInt(u32));
        std.debug.assert(active_before < self.config.max_connections);
    }

    /// Close and cleanup a connection
    fn closeConnection(self: *Self, conn: *Connection) void {
        if (!conn.active) return;

        // Check for active operations BEFORE doing any cleanup
        const read_active = conn.read_active.load(.acquire);
        const write_active = conn.write_active.load(.acquire);

        std.log.debug("closeConnection called - read_active: {}, write_active: {}, write_pos: {}", .{ read_active, write_active, conn.write_pos });

        const has_buffered_writes = conn.tlsHasBufferedWrites();
        if (read_active or write_active or has_buffered_writes) {
            conn.close_after_write = true;
            std.log.debug("Deferring connection close - operations still active", .{});
            return;
        }

        std.log.info("Closing connection {} (TLS: {})", .{ conn.tcp.fd, conn.tls_conn != null });

        // Mark as inactive first to prevent further operations
        conn.active = false;

        if (conn.h2_conn) |h2_conn| {
            h2_conn.deinit();
            conn.h2_conn = null;
        }

        // Clean up stream state
        conn.active_streams.deinit();

        // Remove from active connections
        for (self.connections.items, 0..) |active_conn, connection_index| {
            if (active_conn == conn) {
                _ = self.connections.swapRemove(connection_index);
                break;
            }
        }

        // Update statistics
        _ = self.stats.active_connections.fetchSub(1, .monotonic);

        // Reinitialize close completion for safety
        conn.close_completion = .{};

        // Close the TCP connection
        conn.tcp.close(self.loop, &conn.close_completion, Connection, conn, struct {
            fn callback(
                conn_opt: ?*Connection,
                _: *xev.Loop,
                _: *xev.Completion,
                _: xev.TCP,
                _: xev.CloseError!void,
            ) xev.CallbackAction {
                const c = conn_opt.?;
                // Return to pool after close completes - this is now safe
                c.server.connection_pool.release(c);
                return .disarm;
            }
        }.callback);
    }

    // Protocol handling is delegated to connection.zig via Http2Connection
};

/// HTTP/2 stream state for proper multiplexing
const StreamState = enum {
    open,
    half_closed_local,
    half_closed_remote,
    closed,
};

/// Connection state for libxev event handling
const Connection = struct {
    // Core connection state
    server: *Server,
    tcp: xev.TCP,
    tls_conn: ?*tls.TlsServerConnection, // TLS connection if HTTPS

    // I/O buffers (static allocation)
    read_buffer: []u8,
    write_buffer: []u8,
    read_start: u32,
    read_pos: u32,
    write_start: u32,
    write_pos: u32,

    // HTTP/2 protocol engine and event-driven adapters.
    h2_conn: ?Http2Connection,
    h2_reader: IoAdapters.Reader,
    h2_writer: IoAdapters.Writer,

    // Connection state
    active: bool,
    http2_initialized: bool, // Track if HTTP/2 connection has been initialized
    tls_handshake_complete: bool, // Track TLS handshake state
    tls_handshake_attempts: u32, // Track handshake retry attempts
    close_after_write: bool, // Mark connection for closure after writes complete
    negotiated_protocol: ?[]const u8, // ALPN negotiated protocol

    // HTTP/2 stream management
    next_stream_id: u32, // Track stream IDs for proper multiplexing
    active_streams: std.AutoHashMap(u32, StreamState), // Track active streams

    // libxev completions with ping-pong pattern for safety
    read_completions: [2]xev.Completion,
    write_completions: [2]xev.Completion,
    shutdown_completion: xev.Completion,
    close_completion: xev.Completion,
    current_read_completion: std.atomic.Value(u8),
    current_write_completion: std.atomic.Value(u8),

    // Completion state tracking for safety
    read_active: std.atomic.Value(bool),
    write_active: std.atomic.Value(bool),

    // TLS plaintext staging avoids heap allocation in the hot write path.
    tls_plaintext_buffer: []u8,
    tls_plaintext_read_pos: u32,
    tls_plaintext_write_pos: u32,
    write_side_shutdown: bool,
    awaiting_peer_close: bool,

    const Self = @This();
    const IoAdapters = io_adapters.createStdIoAdapters(Self);
    const Http2Connection = connection_module.Connection;

    fn readBytesAvailable(self: *const Self) u32 {
        std.debug.assert(self.read_start <= self.read_pos);
        return self.read_pos - self.read_start;
    }

    fn writeBytesBuffered(self: *const Self) u32 {
        std.debug.assert(self.write_start <= self.write_pos);
        return self.write_pos - self.write_start;
    }

    fn compactReadBuffer(self: *Self) void {
        const buffered_bytes = self.readBytesAvailable();
        if (buffered_bytes == 0) {
            self.read_start = 0;
            self.read_pos = 0;
            return;
        }

        const start: usize = @intCast(self.read_start);
        const end: usize = @intCast(self.read_pos);
        const len: usize = @intCast(buffered_bytes);
        std.mem.copyForwards(u8, self.read_buffer[0..len], self.read_buffer[start..end]);
        self.read_start = 0;
        self.read_pos = buffered_bytes;
    }

    fn compactWriteBuffer(self: *Self) void {
        const buffered_bytes = self.writeBytesBuffered();
        if (buffered_bytes == 0) {
            self.write_start = 0;
            self.write_pos = 0;
            return;
        }

        const start: usize = @intCast(self.write_start);
        const end: usize = @intCast(self.write_pos);
        const len: usize = @intCast(buffered_bytes);
        std.mem.copyForwards(u8, self.write_buffer[0..len], self.write_buffer[start..end]);
        self.write_start = 0;
        self.write_pos = buffered_bytes;
    }

    fn discardBufferedInput(self: *Self) void {
        if (self.readBytesAvailable() == 0) {
            return;
        }

        std.log.debug("Discarding {} buffered bytes while awaiting peer close", .{
            self.readBytesAvailable(),
        });
        self.read_start = 0;
        self.read_pos = 0;
    }

    fn shouldShutdownWriteSideAfterGoaway(self: *const Self) bool {
        if (self.awaiting_peer_close or self.write_side_shutdown) {
            return false;
        }

        if (self.h2_conn) |h2_conn| {
            return h2_conn.goaway_sent;
        }

        return false;
    }

    fn beginGracefulCloseAfterWrite(self: *Self) void {
        if (!self.active) {
            return;
        }

        if (self.awaiting_peer_close or self.write_side_shutdown) {
            return;
        }

        if (self.write_active.load(.acquire) or self.tlsHasBufferedWrites()) {
            self.close_after_write = true;
            return;
        }

        if (!self.shouldShutdownWriteSideAfterGoaway()) {
            self.server.closeConnection(self);
            return;
        }

        self.close_after_write = false;
        self.awaiting_peer_close = true;
        self.shutdown_completion = .{};

        std.log.debug("All GOAWAY bytes flushed; shutting down writer side and waiting for peer close", .{});
        self.tcp.shutdown(
            self.server.loop,
            &self.shutdown_completion,
            Connection,
            self,
            shutdownCallback,
        );
    }

    fn shutdownCallback(
        self_opt: ?*Connection,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        result: xev.ShutdownError!void,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;

        const self = self_opt.?;

        result catch |err| {
            std.log.warn("Write-side shutdown failed: {}", .{err});
            self.server.closeConnection(self);
            return .disarm;
        };

        self.write_side_shutdown = true;
        std.log.debug("Write side shutdown complete; waiting for peer to close", .{});

        if (!self.active) {
            self.server.closeConnection(self);
            return .disarm;
        }

        if (!self.read_active.load(.acquire)) {
            self.startReading();
        }

        return .disarm;
    }

    /// Initialize HTTP/2 protocol connection asynchronously
    fn initHttp2Connection(self: *Self) !void {
        std.debug.assert(self.active);

        // Skip if already initialized
        if (self.http2_initialized) {
            return;
        }

        // Check if we have HTTP/2 preface
        const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        if (self.readBytesAvailable() >= preface.len) {
            const read_start: usize = @intCast(self.read_start);
            const preface_end = read_start + preface.len;
            if (std.mem.eql(u8, self.read_buffer[read_start..preface_end], preface)) {
                std.log.debug("HTTP/2 preface received, initializing connection", .{});

                self.read_start += @intCast(preface.len);
                if (self.read_start == self.read_pos) {
                    self.read_start = 0;
                    self.read_pos = 0;
                }

                std.debug.assert(self.h2_conn == null);
                self.h2_conn = try Http2Connection.initServerEventDriven(
                    self.server.allocator,
                    self.h2_reader.reader(),
                    self.h2_writer.writer(),
                );

                // Mark as initialized
                self.http2_initialized = true;

                std.log.debug("HTTP/2 connection initialized with SETTINGS frame", .{});
            } else {
                std.log.err("Invalid HTTP/2 preface received", .{});
                try self.sendGoawayFrame(0x1, "Invalid preface: PROTOCOL_ERROR");
                self.close_after_write = true;
                return error.InvalidPreface;
            }
        } else {
            // Need more data for complete preface
            return;
        }
    }

    fn sendGoawayFrame(self: *Self, error_code: u32, debug_data: []const u8) !void {
        const max_debug_data = 64;

        std.debug.assert(debug_data.len <= max_debug_data);

        const payload_len = 8 + debug_data.len;
        var frame_header: [9]u8 = undefined;
        var payload_buffer: [8 + max_debug_data]u8 = undefined;

        frame_header[0] = @intCast((payload_len >> 16) & 0xFF);
        frame_header[1] = @intCast((payload_len >> 8) & 0xFF);
        frame_header[2] = @intCast(payload_len & 0xFF);
        frame_header[3] = @intFromEnum(FrameType.GOAWAY);
        frame_header[4] = 0;
        std.mem.writeInt(u32, frame_header[5..9], 0, .big);

        std.mem.writeInt(u32, payload_buffer[0..4], 0, .big);
        std.mem.writeInt(u32, payload_buffer[4..8], error_code, .big);
        if (debug_data.len > 0) {
            @memcpy(payload_buffer[8 .. 8 + debug_data.len], debug_data);
        }

        try self.writeData(&frame_header);
        try self.writeData(payload_buffer[0..payload_len]);
    }

    /// Process available data through simplified HTTP/2 frame handling
    fn processHttp2(self: *Self) !void {
        std.log.debug("processHttp2: Starting with {} bytes in buffer", .{self.readBytesAvailable()});

        // Process ALL available frames to prevent stalling
        while (self.readBytesAvailable() > 0 and self.active) {
            const read_start: usize = @intCast(self.read_start);
            const read_pos: usize = @intCast(self.read_pos);
            const read_buffer = self.read_buffer[read_start..read_pos];
            const buffered_bytes = read_buffer.len;

            // Check if we have enough data for at least a frame header (9 bytes)
            if (buffered_bytes < 9) {
                std.log.debug("Insufficient data for frame header: {} bytes, waiting for more", .{buffered_bytes});
                break;
            }

            // Parse frame header to determine required frame size
            const frame_length = (@as(u32, read_buffer[0]) << 16) |
                (@as(u32, read_buffer[1]) << 8) |
                @as(u32, read_buffer[2]);
            const frame_type = read_buffer[3];
            const total_frame_size = 9 + frame_length; // header + payload

            std.log.debug("Frame detected: type={}, length={}, total_size={}, buffer_has={}", .{
                frame_type,
                frame_length,
                total_frame_size,
                buffered_bytes,
            });

            // Validate frame length (HTTP/2 spec: max 16MB)
            if (frame_length > 16 * 1024 * 1024) {
                std.log.err("Frame length {} exceeds maximum allowed size", .{frame_length});
                self.active = false;
                return error.FrameTooLarge;
            }

            if (self.h2_conn) |*h2_conn| {
                if (frame_length > h2_conn.settings.max_frame_size) {
                    try h2_conn.send_goaway(0, 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
                    self.close_after_write = true;
                    break;
                }
            }

            // Check if we have the complete frame
            if (buffered_bytes < total_frame_size) {
                std.log.debug("Incomplete frame: have {} bytes, need {} bytes, waiting for more", .{
                    buffered_bytes,
                    total_frame_size,
                });
                break;
            }

            std.log.debug("Processing complete HTTP/2 frame: length={}, total_size={}", .{ frame_length, total_frame_size });

            // Extract frame data and process it
            const frame_data = read_buffer[0..total_frame_size];
            try self.handleFrame(frame_data);

            if (self.close_after_write) {
                std.log.debug("Stopping HTTP/2 frame processing after scheduling connection close", .{});
                break;
            }

            self.read_start += @intCast(total_frame_size);
            if (self.read_start == self.read_pos) {
                self.read_start = 0;
                self.read_pos = 0;
            }

            std.log.debug("Frame processed successfully, read_pos now: {}", .{self.readBytesAvailable()});
        }

        if (self.h2_conn) |*h2_conn| {
            if (!self.close_after_write) {
                try h2_conn.flush_ready_streams();
            }
        }

        // Ensure any response data gets sent to the client
        if (self.writeBytesBuffered() > 0) {
            std.log.debug("Starting write of {} bytes for HTTP/2 response", .{self.writeBytesBuffered()});
            self.startWriting();
        }
    }

    /// Handle a single HTTP/2 frame - fast, non-blocking operation
    fn handleFrame(self: *Self, frame_data: []u8) !void {
        std.debug.assert(self.h2_conn != null);
        const h2_conn = &self.h2_conn.?;

        const frame_length = (@as(u32, frame_data[0]) << 16) |
            (@as(u32, frame_data[1]) << 8) |
            @as(u32, frame_data[2]);
        const frame_type_u8 = frame_data[3];
        const frame_type = FrameType.fromU8(frame_type_u8) orelse {
            if (h2_conn.expecting_continuation_stream_id != null) {
                try h2_conn.send_goaway(0, 0x1, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                self.close_after_write = true;
                return;
            }
            std.log.debug("Ignoring unknown frame type {}", .{frame_type_u8});
            return;
        };
        const frame_flags = FrameFlags.init(frame_data[4]);
        const stream_id = std.mem.readInt(u32, frame_data[5..9], .big) & 0x7FFFFFFF;

        if (frame_length > h2_conn.settings.max_frame_size) {
            try h2_conn.send_goaway(0, 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
            self.close_after_write = true;
            return;
        }

        const parsed_frame = connection_module.Frame{
            .header = .{
                .length = frame_length,
                .frame_type = frame_type,
                .flags = frame_flags,
                .reserved = false,
                .stream_id = stream_id,
            },
            .payload = if (frame_length == 0) &[_]u8{} else frame_data[9 .. 9 + frame_length],
        };

        h2_conn.handleFrameEventDriven(parsed_frame) catch |err| {
            if (h2_conn.goaway_sent) {
                self.close_after_write = true;
                std.log.debug("HTTP/2 frame handling stopped after GOAWAY: {}", .{err});
                return;
            }
            return err;
        };

        if (h2_conn.goaway_sent) {
            self.close_after_write = true;
        }
    }

    fn handleHeadersFrame(self: *Self, frame_data: []u8) !void {
        const frame_length = (@as(u32, frame_data[0]) << 16) |
            (@as(u32, frame_data[1]) << 8) |
            @as(u32, frame_data[2]);
        const flags = frame_data[4];
        const stream_id = std.mem.readInt(u32, frame_data[5..9], .big) & 0x7FFFFFFF;
        const end_stream = (flags & 0x1) != 0;
        const end_headers = (flags & 0x4) != 0;

        std.log.debug("Handling HEADERS frame (stream_id={}, length={}, end_stream={}, end_headers={})", .{ stream_id, frame_length, end_stream, end_headers });

        // Debug: Show raw header payload for analysis
        if (frame_length > 0 and frame_data.len >= 9 + frame_length) {
            const header_payload = frame_data[9 .. 9 + frame_length];
            std.log.debug("HEADERS payload ({} bytes): {any}", .{ header_payload.len, header_payload });
        }

        // Track stream state - this is proper HTTP/2 stream management
        if (end_stream) {
            try self.active_streams.put(stream_id, .half_closed_remote);
        } else {
            try self.active_streams.put(stream_id, .open);
        }

        // Process request and send response (keep connection alive for more requests)
        if (end_headers) {
            std.log.debug("Sending response for stream {}", .{stream_id});
            // Extract headers and route through proper handler system
            if (frame_length > 0 and frame_data.len >= 9 + frame_length) {
                const header_payload = frame_data[9 .. 9 + frame_length];
                try self.processHttpRequest(stream_id, header_payload, end_stream);
            } else {
                // Fallback to simple response if no headers
                try self.sendStreamResponse(stream_id, end_stream);
            }
        } else {
            std.log.debug("Waiting for more HEADERS frames for stream {}", .{stream_id});
        }
    }

    /// Process HTTP request by decoding HPACK headers using zero-allocation approach
    fn processHttpRequest(self: *Self, stream_id: u32, header_payload: []const u8, end_stream: bool) !void {
        var method: []const u8 = "GET";
        var path: []const u8 = "/";

        // Parse HPACK headers manually to avoid dynamic allocation
        // This handles the most common cases without full HPACK dynamic table support
        var cursor: usize = 0;
        while (cursor < header_payload.len) {
            if (cursor >= header_payload.len) break;

            const first_byte = header_payload[cursor];

            // Handle indexed header field (first bit = 1)
            if ((first_byte & 0x80) != 0) {
                const index = first_byte & 0x7F;
                cursor += 1;

                // Common HPACK static table entries
                switch (index) {
                    2 => { // :method GET
                        method = "GET";
                        std.log.debug("Extracted method: GET (indexed)", .{});
                    },
                    3 => { // :method POST
                        method = "POST";
                        std.log.debug("Extracted method: POST (indexed)", .{});
                    },
                    4 => { // :path /
                        path = "/";
                        std.log.debug("Extracted path: / (indexed)", .{});
                    },
                    else => {
                        // Skip unknown indexed headers
                    },
                }
            }
            // Handle literal header field (first bit = 0, second bit = 1)
            else if ((first_byte & 0x40) != 0) {
                cursor += 1; // Skip the first byte for now

                // For literal headers, we'd need to decode the length-prefixed strings
                // For now, just skip them to avoid complexity
                if (cursor < header_payload.len) {
                    const len = header_payload[cursor];
                    cursor += 1 + len; // Skip length byte + string data
                    if (cursor < header_payload.len) {
                        const value_len = header_payload[cursor];
                        cursor += 1 + value_len; // Skip value length + value data
                    }
                }
            } else {
                // Skip other header types for now
                cursor += 1;
            }
        }

        std.log.debug("Final extracted - method: {s}, path: {s}", .{ method, path });

        // Route request through handler system
        try self.routeAndHandleRequest(stream_id, method, path, end_stream);
    }

    /// Route request through the handler system using zero-allocation approach
    fn routeAndHandleRequest(self: *Self, stream_id: u32, method: []const u8, path: []const u8, end_stream: bool) !void {
        std.log.debug("Routing request: {s} {s}", .{ method, path });

        // For zero-allocation HTTP/2, directly handle common routes without full handler system
        // This avoids the complex Context creation that may involve allocations

        if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/")) {
            std.log.debug("Handling GET / with static response", .{});

            // Send HTML response directly
            const html_body =
                \\ <!DOCTYPE html>
                \\ <html>
                \\ <head>
                \\     <title>HTTP/2 Server</title>
                \\ </head>
                \\ <body>
                \\     <h1>Hello, World!</h1>
                \\     <p>This is an HTTP/2 server built with Zig!</p>
                \\ </body>
                \\ </html>
            ;

            try self.sendStaticResponse(stream_id, 200, "text/html", html_body, end_stream);
        } else if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/api/hello")) {
            std.log.debug("Handling GET /api/hello with static JSON", .{});

            const json_body =
                \\{
                \\  "message": "Hello from HTTP/2 API!",
                \\  "method": "GET",
                \\  "path": "/api/hello"
                \\}
            ;

            try self.sendStaticResponse(stream_id, 200, "application/json", json_body, end_stream);
        } else {
            std.log.warn("No static route found for {s} {s}", .{ method, path });
            try self.sendErrorResponse(stream_id, 404, "Not Found", end_stream);
        }
    }

    /// Send static response without allocations
    fn sendStaticResponse(self: *Self, stream_id: u32, status_code: u16, content_type: []const u8, body: []const u8, request_end_stream: bool) !void {
        std.log.debug("Sending static response for stream {} (status={}, body_len={})", .{ stream_id, status_code, body.len });

        // Create HEADERS frame with status and content-type
        var headers_payload: [256]u8 = undefined;
        var headers_len: usize = 0;

        // Add :status header (HPACK encoded)
        if (status_code == 200) {
            headers_payload[headers_len] = 0x88; // :status: 200 (indexed)
            headers_len += 1;
        } else {
            // For other status codes, would need proper HPACK encoding
            headers_payload[headers_len] = 0x88; // Default to 200 for now
            headers_len += 1;
        }

        // Simplified: Just send :status 200 for now to test basic functionality
        // Skip content-type header to test if that's causing the issue
        _ = content_type; // Suppress unused parameter warning

        // Create HEADERS frame
        var headers_frame: [9 + 256]u8 = undefined;
        headers_frame[0] = @intCast((headers_len >> 16) & 0xFF);
        headers_frame[1] = @intCast((headers_len >> 8) & 0xFF);
        headers_frame[2] = @intCast(headers_len & 0xFF);
        headers_frame[3] = 0x1; // HEADERS type
        headers_frame[4] = 0x4; // END_HEADERS flag
        std.mem.writeInt(u32, headers_frame[5..9], stream_id, .big);
        @memcpy(headers_frame[9 .. 9 + headers_len], headers_payload[0..headers_len]);

        // Create DATA frame with response body
        var data_frame: [9 + 8192]u8 = undefined; // Support up to 8KB response
        const body_len: u32 = @intCast(@min(body.len, 8192 - 9));

        data_frame[0] = @intCast((body_len >> 16) & 0xFF);
        data_frame[1] = @intCast((body_len >> 8) & 0xFF);
        data_frame[2] = @intCast(body_len & 0xFF);
        data_frame[3] = 0x0; // DATA type
        data_frame[4] = if (request_end_stream) 0x1 else 0x0; // END_STREAM flag
        std.mem.writeInt(u32, data_frame[5..9], stream_id, .big);
        @memcpy(data_frame[9 .. 9 + body_len], body[0..body_len]);

        // Send frames
        std.log.debug("Sending HEADERS frame: {any}", .{headers_frame[0 .. 9 + headers_len]});
        std.log.debug("Sending DATA frame with {} bytes body", .{body_len});
        try self.writeData(headers_frame[0 .. 9 + headers_len]);
        try self.writeData(data_frame[0 .. 9 + body_len]);

        // Update stream state
        if (request_end_stream) {
            try self.active_streams.put(stream_id, .closed);
            std.log.debug("Stream {} closed after response", .{stream_id});
        } else {
            try self.active_streams.put(stream_id, .half_closed_local);
            std.log.debug("Stream {} half-closed (local)", .{stream_id});
        }

        // Update stats
        _ = self.server.stats.requests_processed.fetchAdd(1, .monotonic);
    }

    /// Send response from handler system
    fn sendHandlerResponse(self: *Self, stream_id: u32, response: handler.Response, request_end_stream: bool) !void {
        std.log.debug("Sending handler response for stream {} (status={}, body_len={})", .{ stream_id, @intFromEnum(response.status), response.body.len });

        // Create HEADERS frame with status and content-type
        var headers_payload: [256]u8 = undefined;
        var headers_len: usize = 0;

        // Add :status header (HPACK encoded)
        const status_code = @intFromEnum(response.status);
        if (status_code == 200) {
            headers_payload[headers_len] = 0x88; // :status: 200 (indexed)
            headers_len += 1;
        } else {
            // For other status codes, would need proper HPACK encoding
            headers_payload[headers_len] = 0x88; // Default to 200 for now
            headers_len += 1;
        }

        // Add content-type header - default to text/html for now
        const content_type = "text/html";
        // Simple literal header field encoding for content-type
        headers_payload[headers_len] = 0x0f; // content-type literal index
        headers_len += 1;
        headers_payload[headers_len] = @intCast(content_type.len);
        headers_len += 1;
        @memcpy(headers_payload[headers_len .. headers_len + content_type.len], content_type);
        headers_len += content_type.len;

        // Create HEADERS frame
        var headers_frame: [9 + 256]u8 = undefined;
        headers_frame[0] = @intCast((headers_len >> 16) & 0xFF);
        headers_frame[1] = @intCast((headers_len >> 8) & 0xFF);
        headers_frame[2] = @intCast(headers_len & 0xFF);
        headers_frame[3] = 0x1; // HEADERS type
        headers_frame[4] = 0x4; // END_HEADERS flag
        std.mem.writeInt(u32, headers_frame[5..9], stream_id, .big);
        @memcpy(headers_frame[9 .. 9 + headers_len], headers_payload[0..headers_len]);

        // Create DATA frame with response body
        const body = response.body;
        var data_frame: [9 + 8192]u8 = undefined; // Support up to 8KB response
        const body_len: u32 = @intCast(@min(body.len, 8192 - 9));

        data_frame[0] = @intCast((body_len >> 16) & 0xFF);
        data_frame[1] = @intCast((body_len >> 8) & 0xFF);
        data_frame[2] = @intCast(body_len & 0xFF);
        data_frame[3] = 0x0; // DATA type
        data_frame[4] = if (request_end_stream) 0x1 else 0x0; // END_STREAM flag
        std.mem.writeInt(u32, data_frame[5..9], stream_id, .big);
        @memcpy(data_frame[9 .. 9 + body_len], body[0..body_len]);

        // Send frames
        std.log.debug("Sending HEADERS frame: {any}", .{headers_frame[0 .. 9 + headers_len]});
        std.log.debug("Sending DATA frame with {} bytes body", .{body_len});
        try self.writeData(headers_frame[0 .. 9 + headers_len]);
        try self.writeData(data_frame[0 .. 9 + body_len]);

        // Update stream state
        if (request_end_stream) {
            try self.active_streams.put(stream_id, .closed);
            std.log.debug("Stream {} closed after response", .{stream_id});
        } else {
            try self.active_streams.put(stream_id, .half_closed_local);
            std.log.debug("Stream {} half-closed (local)", .{stream_id});
        }

        // Update stats
        _ = self.server.stats.requests_processed.fetchAdd(1, .monotonic);
    }

    /// Send error response
    fn sendErrorResponse(self: *Self, stream_id: u32, status_code: u16, message: []const u8, request_end_stream: bool) !void {
        // Simple error response with hardcoded HPACK
        const headers_payload = "\x8c"; // :status: 500 (would need proper encoding for different codes)

        var headers_frame: [9 + 1]u8 = undefined;
        headers_frame[0] = 0;
        headers_frame[1] = 0;
        headers_frame[2] = 1; // length = 1
        headers_frame[3] = 0x1; // HEADERS type
        headers_frame[4] = 0x4; // END_HEADERS flag
        std.mem.writeInt(u32, headers_frame[5..9], stream_id, .big);
        headers_frame[9] = headers_payload[0];

        var data_frame: [9 + 256]u8 = undefined;
        const msg_len: u32 = @intCast(@min(message.len, 256));
        data_frame[0] = @intCast((msg_len >> 16) & 0xFF);
        data_frame[1] = @intCast((msg_len >> 8) & 0xFF);
        data_frame[2] = @intCast(msg_len & 0xFF);
        data_frame[3] = 0x0; // DATA type
        data_frame[4] = if (request_end_stream) 0x1 else 0x0; // END_STREAM flag
        std.mem.writeInt(u32, data_frame[5..9], stream_id, .big);
        @memcpy(data_frame[9 .. 9 + msg_len], message[0..msg_len]);

        try self.writeData(&headers_frame);
        try self.writeData(data_frame[0 .. 9 + msg_len]);

        _ = status_code; // Suppress unused warning for now
    }

    fn handleSettingsFrame(self: *Self, frame_data: []u8) !void {
        const frame_length = (@as(u32, frame_data[0]) << 16) |
            (@as(u32, frame_data[1]) << 8) |
            @as(u32, frame_data[2]);
        const flags = frame_data[4];
        const is_ack = (flags & 0x1) != 0;

        std.log.debug("Handling SETTINGS frame (length={}, ack={})", .{ frame_length, is_ack });

        if (is_ack) {
            // Settings ACK - no action needed
            return;
        }

        // Parse SETTINGS frame and send ACK
        const settings_ack = "\x00\x00\x00\x04\x01\x00\x00\x00\x00"; // Empty SETTINGS with ACK flag
        try self.writeData(settings_ack);
    }

    fn handleWindowUpdateFrame(self: *Self, frame_data: []u8) !void {
        _ = self;
        _ = frame_data;
        std.log.debug("Handling WINDOW_UPDATE frame", .{});
    }

    /// Send HTTP/2 response with proper stream lifecycle management
    fn sendStreamResponse(self: *Self, stream_id: u32, request_end_stream: bool) !void {
        std.log.debug("Sending stream response for stream {} (request_end_stream={})", .{ stream_id, request_end_stream });

        // Create proper HTTP/2 HEADERS frame with :status: 200
        // Simple HPACK: 0x88 = :status: 200 (indexed from static table entry 8)
        const headers_payload = "\x88"; // Just :status: 200
        const headers_length = headers_payload.len;

        var headers_frame: [9 + headers_payload.len]u8 = undefined;
        // Length (24 bits)
        headers_frame[0] = @intCast((headers_length >> 16) & 0xFF);
        headers_frame[1] = @intCast((headers_length >> 8) & 0xFF);
        headers_frame[2] = @intCast(headers_length & 0xFF);
        // Type (HEADERS = 0x1)
        headers_frame[3] = 0x1;
        // Flags (END_HEADERS = 0x4) - do NOT set END_STREAM here, only on final DATA frame
        headers_frame[4] = 0x4;
        // Stream ID
        std.mem.writeInt(u32, headers_frame[5..9], stream_id, .big);
        // Payload
        @memcpy(headers_frame[9..], headers_payload);

        // Create DATA frame with "Hello, World!"
        const data_payload = "Hello, World!";
        const data_length = data_payload.len;

        var data_frame: [9 + data_payload.len]u8 = undefined;
        // Length
        data_frame[0] = @intCast((data_length >> 16) & 0xFF);
        data_frame[1] = @intCast((data_length >> 8) & 0xFF);
        data_frame[2] = @intCast(data_length & 0xFF);
        // Type (DATA = 0x0)
        data_frame[3] = 0x0;
        // Flags - Only set END_STREAM if the request was end_stream
        data_frame[4] = if (request_end_stream) 0x1 else 0x0;
        // Stream ID
        std.mem.writeInt(u32, data_frame[5..9], stream_id, .big);
        // Payload
        @memcpy(data_frame[9..], data_payload);

        // Send frames
        std.log.debug("Sending HEADERS frame: {any}", .{headers_frame});
        std.log.debug("Sending DATA frame: {any}", .{data_frame});
        try self.writeData(&headers_frame);
        try self.writeData(&data_frame);

        // Update stream state properly
        if (request_end_stream) {
            // If request ended the stream, close it after our response
            try self.active_streams.put(stream_id, .closed);
            std.log.debug("Stream {} closed after response", .{stream_id});
        } else {
            // Stream remains open for potential additional requests/responses
            try self.active_streams.put(stream_id, .half_closed_local);
            std.log.debug("Stream {} half-closed (local), ready for more data", .{stream_id});
        }

        // Update stats
        _ = self.server.stats.requests_processed.fetchAdd(1, .monotonic);
    }

    /// Process HTTP/1.1 request
    fn processHttp11(self: *Self) !void {
        // Parse HTTP/1.1 request from buffer
        const read_start: usize = @intCast(self.read_start);
        const read_pos: usize = @intCast(self.read_pos);
        const request_data = self.read_buffer[read_start..read_pos];

        // Look for end of HTTP headers (double CRLF)
        const header_end = std.mem.indexOf(u8, request_data, "\r\n\r\n") orelse {
            // Incomplete request, wait for more data
            if (request_data.len > 8192) {
                // Request too large
                try self.sendHttp11Error(400, "Bad Request");
                return;
            }
            return; // Wait for more data
        };

        // Parse request line
        const header_section = request_data[0..header_end];
        var lines = std.mem.splitSequence(u8, header_section, "\r\n");
        const request_line = lines.next() orelse {
            try self.sendHttp11Error(400, "Bad Request");
            return;
        };

        // Parse method and path
        var parts = std.mem.splitSequence(u8, request_line, " ");
        const method_str = parts.next() orelse {
            try self.sendHttp11Error(400, "Bad Request");
            return;
        };
        const path = parts.next() orelse {
            try self.sendHttp11Error(400, "Bad Request");
            return;
        };

        // Convert method string to enum
        const method = if (std.mem.eql(u8, method_str, "GET"))
            handler.Method.get
        else if (std.mem.eql(u8, method_str, "POST"))
            handler.Method.post
        else if (std.mem.eql(u8, method_str, "PUT"))
            handler.Method.put
        else if (std.mem.eql(u8, method_str, "DELETE"))
            handler.Method.delete
        else {
            try self.sendHttp11Error(405, "Method Not Allowed");
            return;
        };

        std.log.info("HTTP/1.1 {} {s}", .{ method, path });

        // Find handler
        const handler_fn = self.server.router.findHandler(method, path);
        if (handler_fn) |handler_func| {
            // Create request context
            const context = handler.Context.init(
                self.server.allocator,
                method,
                path,
                "", // No query parsing for now
                "", // No body for now
            );

            // Call handler
            var response = handler_func(&context) catch {
                try self.sendHttp11Error(500, "Internal Server Error");
                return;
            };
            defer response.deinit();

            // Send HTTP/1.1 response
            try self.sendHttp11Response(&response);
        } else {
            try self.sendHttp11Error(404, "Not Found");
        }

        // Clear processed data from buffer
        const total_request_size = header_end + 4; // Include the \r\n\r\n
        self.read_start += @intCast(total_request_size);
        if (self.read_start == self.read_pos) {
            self.read_start = 0;
            self.read_pos = 0;
        } else {
            std.debug.assert(self.read_start < self.read_pos);
        }
    }

    /// Send HTTP/1.1 response
    fn sendHttp11Response(self: *Self, response: *const handler.Response) !void {
        var response_buffer: [8192]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&response_buffer);

        // Status line
        const status_text = switch (response.status) {
            .ok => "200 OK",
            .not_found => "404 Not Found",
            .internal_server_error => "500 Internal Server Error",
            else => "200 OK",
        };

        try writer.print("HTTP/1.1 {s}\r\n", .{status_text});

        // Headers
        for (response.headers.items) |header| {
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // Content-Length if not already present
        var has_content_length = false;
        for (response.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
                has_content_length = true;
                break;
            }
        }

        if (!has_content_length) {
            try writer.print("Content-Length: {}\r\n", .{response.body.len});
        }

        // Connection close for simplicity
        try writer.print("Connection: close\r\n", .{});

        // End of headers
        try writer.print("\r\n", .{});

        // Body
        try writer.writeAll(response.body);

        // Write to connection
        const response_data = writer.buffered();
        if (self.write_pos + response_data.len > self.write_buffer.len) {
            return error.WriteBufferFull;
        }

        @memcpy(self.write_buffer[self.write_pos .. self.write_pos + response_data.len], response_data);
        self.write_pos += @intCast(response_data.len);

        // Trigger write
        self.startWriting();

        // Close connection after response (HTTP/1.1 without keep-alive)
        self.active = false;
    }

    /// Send HTTP/1.1 error response
    fn sendHttp11Error(self: *Self, status_code: u16, status_text: []const u8) !void {
        var response_buffer: [1024]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&response_buffer);

        const body = try std.fmt.allocPrint(self.server.allocator, "<html><body><h1>{} {s}</h1></body></html>", .{ status_code, status_text });
        defer self.server.allocator.free(body);

        try writer.print("HTTP/1.1 {} {s}\r\n", .{ status_code, status_text });
        try writer.print("Content-Type: text/html\r\n", .{});
        try writer.print("Content-Length: {}\r\n", .{body.len});
        try writer.print("Connection: close\r\n", .{});
        try writer.print("\r\n", .{});
        try writer.writeAll(body);

        const response_data = writer.buffered();
        if (self.write_pos + response_data.len > self.write_buffer.len) {
            return error.WriteBufferFull;
        }

        @memcpy(self.write_buffer[self.write_pos .. self.write_pos + response_data.len], response_data);
        self.write_pos += @intCast(response_data.len);

        self.startWriting();
        self.active = false;
    }

    /// Start reading from connection using libxev
    pub fn startReading(self: *Self) void {
        // Assert connection validity and buffer bounds
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(self.read_buffer.len > 0);
        std.debug.assert(self.read_start <= self.read_pos);
        std.debug.assert(self.read_pos <= self.read_buffer.len);

        if (!self.active) return;

        // Check if read is already active to prevent double submission
        if (self.read_active.swap(true, .acquire)) {
            return; // Read already in progress
        }

        // Use ping-pong completion pattern with bounds checking
        const completion_idx = self.current_read_completion.fetchAdd(1, .monotonic) % 2;
        std.debug.assert(completion_idx < 2);

        const completion = &self.read_completions[completion_idx];
        completion.* = .{};

        if (self.read_start == self.read_pos) {
            self.read_start = 0;
            self.read_pos = 0;
        } else if (self.read_pos == self.read_buffer.len) {
            self.compactReadBuffer();
        }

        std.debug.assert(self.read_pos < self.read_buffer.len);

        // Use appropriate callback based on TLS status
        if (self.server.tls_ctx) |_| {
            // For TLS-enabled servers, use TLS callback
            self.tcp.read(
                self.server.loop,
                completion,
                .{ .slice = self.read_buffer[self.read_pos..] },
                Connection,
                self,
                readCallbackSimpleTLS,
            );
        } else {
            self.tcp.read(
                self.server.loop,
                completion,
                .{ .slice = self.read_buffer[self.read_pos..] },
                Connection,
                self,
                readCallback,
            );
        }
    }

    /// Start writing to connection using libxev
    pub fn startWriting(self: *Self) void {
        // Assert connection validity and buffer bounds
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(self.write_buffer.len > 0);
        std.debug.assert(self.write_start <= self.write_pos);
        std.debug.assert(self.write_pos <= self.write_buffer.len);

        if (!self.active) return;

        if (self.write_start == self.write_pos) {
            self.write_start = 0;
            self.write_pos = 0;
            return;
        }

        // Check if write is already active to prevent double submission
        if (self.write_active.swap(true, .acquire)) {
            std.log.debug("Write already in progress - queuing data (write_pos: {})", .{self.write_pos});
            return; // Write already in progress
        }

        std.log.debug("Starting new write operation - {} bytes", .{self.writeBytesBuffered()});

        // Use ping-pong completion pattern with bounds checking
        const completion_idx = self.current_write_completion.fetchAdd(1, .monotonic) % 2;
        std.debug.assert(completion_idx < 2);

        const completion = &self.write_completions[completion_idx];
        completion.* = .{};

        std.debug.assert(self.writeBytesBuffered() > 0);

        self.tcp.write(
            self.server.loop,
            completion,
            .{ .slice = self.write_buffer[self.write_start..self.write_pos] },
            Connection,
            self,
            writeCallback,
        );
    }

    /// Write frame header to output buffer
    pub fn writeFrameHeader(self: *Self, frame_type: FrameType, flags: u8, stream_id: u32, length: u32) !void {
        var header: [9]u8 = undefined;

        header[0] = @intCast((length >> 16) & 0xFF);
        header[1] = @intCast((length >> 8) & 0xFF);
        header[2] = @intCast(length & 0xFF);
        header[3] = @intFromEnum(frame_type);
        header[4] = flags;
        std.mem.writeInt(u32, header[5..9], stream_id, .big);

        try self.writeData(&header);
    }

    /// Write data to output buffer - handles both TLS and cleartext
    pub fn writeData(self: *Self, data: []const u8) !void {
        std.debug.assert(self.active);
        std.debug.assert(data.len > 0);

        // For TLS connections, use the serialized write queue
        if (self.tls_conn) |_| {
            try self.stageTLSPlaintext(data);
            return;
        }

        if (self.write_pos + data.len > self.write_buffer.len) {
            if (!self.write_active.load(.acquire)) {
                self.compactWriteBuffer();
            }
        }

        if (self.write_pos + data.len > self.write_buffer.len) {
            return error.WriteBufferFull;
        }

        @memcpy(self.write_buffer[self.write_pos .. self.write_pos + data.len], data);
        self.write_pos += @intCast(data.len);

        std.debug.assert(self.write_pos <= self.write_buffer.len);
    }

    fn tlsPlaintextBytesPending(self: *const Self) u32 {
        std.debug.assert(self.tls_plaintext_read_pos <= self.tls_plaintext_write_pos);
        return self.tls_plaintext_write_pos - self.tls_plaintext_read_pos;
    }

    fn tlsHasBufferedWrites(self: *const Self) bool {
        if (self.tlsPlaintextBytesPending() > 0) {
            return true;
        }

        if (self.writeBytesBuffered() > 0) {
            return true;
        }

        if (self.tls_conn) |tls_connection| {
            return tls_connection.hasEncryptedDataToSend();
        }

        return false;
    }

    fn compactTLSPlaintext(self: *Self) void {
        const staged_bytes = self.tlsPlaintextBytesPending();
        if (staged_bytes == 0) {
            self.tls_plaintext_read_pos = 0;
            self.tls_plaintext_write_pos = 0;
            return;
        }

        const staged_len: usize = @intCast(staged_bytes);
        const read_pos: usize = @intCast(self.tls_plaintext_read_pos);
        const write_pos: usize = @intCast(self.tls_plaintext_write_pos);
        std.mem.copyForwards(
            u8,
            self.tls_plaintext_buffer[0..staged_len],
            self.tls_plaintext_buffer[read_pos..write_pos],
        );
        self.tls_plaintext_read_pos = 0;
        self.tls_plaintext_write_pos = staged_bytes;
    }

    fn stageTLSPlaintext(self: *Self, data: []const u8) !void {
        std.debug.assert(self.tls_conn != null);
        std.debug.assert(data.len > 0);
        std.debug.assert(data.len <= self.tls_plaintext_buffer.len);

        const data_len: u32 = @intCast(data.len);
        const capacity_bytes: u32 = @intCast(self.tls_plaintext_buffer.len);
        const staged_bytes = self.tlsPlaintextBytesPending();

        std.debug.assert(staged_bytes <= capacity_bytes);
        if (data_len > capacity_bytes - staged_bytes) {
            return error.WriteBufferFull;
        }

        if (self.tls_plaintext_write_pos + data_len > capacity_bytes) {
            self.compactTLSPlaintext();
        }

        std.debug.assert(self.tls_plaintext_write_pos + data_len <= capacity_bytes);

        const write_pos: usize = @intCast(self.tls_plaintext_write_pos);
        @memcpy(self.tls_plaintext_buffer[write_pos .. write_pos + data.len], data);
        self.tls_plaintext_write_pos += data_len;

        if (self.tls_handshake_complete) {
            self.flushTLSPlaintext();
        }
    }

    fn flushTLSPlaintext(self: *Self) void {
        if (!self.active) {
            return;
        }
        if (!self.tls_handshake_complete) {
            return;
        }

        const tls_connection = self.tls_conn orelse return;
        if (self.write_active.load(.acquire)) {
            return;
        }

        if (tls_connection.hasEncryptedDataToSend()) {
            self.drainTLSEncryptedDataAsync(tls_connection);
            if (self.write_active.load(.acquire)) {
                return;
            }
        }

        const max_tls_writes: u32 = 8;
        var tls_writes: u32 = 0;
        while (self.tlsPlaintextBytesPending() > 0 and tls_writes < max_tls_writes) {
            const read_pos: usize = @intCast(self.tls_plaintext_read_pos);
            const write_pos: usize = @intCast(self.tls_plaintext_write_pos);
            const staged_data = self.tls_plaintext_buffer[read_pos..write_pos];

            const bytes_written = tls_connection.writeApplicationData(staged_data) catch |err| switch (err) {
                error.WouldBlock => {
                    self.drainTLSEncryptedDataAsync(tls_connection);
                    return;
                },
                else => {
                    std.log.err("TLS plaintext write failed: {}", .{err});
                    self.server.closeConnection(self);
                    return;
                },
            };

            std.debug.assert(bytes_written > 0);
            std.debug.assert(bytes_written <= staged_data.len);

            self.tls_plaintext_read_pos += @intCast(bytes_written);
            if (self.tls_plaintext_read_pos == self.tls_plaintext_write_pos) {
                self.tls_plaintext_read_pos = 0;
                self.tls_plaintext_write_pos = 0;
            }

            self.drainTLSEncryptedDataAsync(tls_connection);
            if (self.write_active.load(.acquire)) {
                return;
            }

            tls_writes += 1;
        }

        if (self.close_after_write and !self.tlsHasBufferedWrites()) {
            self.beginGracefulCloseAfterWrite();
        }
    }

    /// Callback for read operations
    fn readCallback(
        self_opt: ?*Connection,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        buffer: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;
        _ = buffer;

        const self = self_opt.?;

        // Assert connection validity before processing
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(self.read_start <= self.read_pos);
        std.debug.assert(self.read_pos <= self.read_buffer.len);

        // Mark read as completed
        self.read_active.store(false, .release);

        const bytes_read = result catch |err| {
            switch (err) {
                error.EOF => {
                    // Normal connection close
                    self.server.closeConnection(self);
                    return .disarm;
                },
                else => {
                    self.server.closeConnection(self);
                    return .disarm;
                },
            }
        };

        if (bytes_read == 0) {
            // Connection closed
            self.server.closeConnection(self);
            return .disarm;
        }

        // Update read position with bounds checking
        const bytes_read_u32: u32 = @intCast(bytes_read);
        std.debug.assert(self.read_pos + bytes_read_u32 <= self.read_buffer.len);

        self.read_pos += bytes_read_u32;

        // Try to initialize HTTP/2 connection (handles preface asynchronously)
        self.initHttp2Connection() catch |err| switch (err) {
            // If we need more data, just continue reading
            else => {
                std.log.err("Failed to initialize HTTP/2 connection: {}", .{err});
                self.active = false;
                self.server.closeConnection(self);
                return .disarm;
            },
        };

        if (self.awaiting_peer_close) {
            self.discardBufferedInput();
        } else {
            // Process through simplified HTTP/2 protocol handling
            self.processHttp2() catch |err| {
                std.log.err("HTTP/2 protocol error: {}", .{err});
                self.active = false;
                self.server.closeConnection(self);
                return .disarm;
            };
        }

        if (self.close_after_write) {
            self.scheduleAsyncClose();
        } else {
            self.startReading();
        }
        return .disarm;
    }

    fn handleTLSReadError(self: *Connection, err: anyerror) void {
        switch (err) {
            error.EOF => {
                std.log.info("Connection {} closed by client (TLS handshake complete: {})", .{ self.tcp.fd, self.tls_handshake_complete });
            },
            else => {
                std.log.warn("TLS read error on connection {}: {}", .{ self.tcp.fd, err });
            },
        }
        self.server.closeConnection(self);
    }

    fn initializeTLSConnection(self: *Connection) !void {
        std.debug.assert(self.server.tls_ctx != null);
        std.debug.assert(self.tls_conn == null);
        std.debug.assert(self.read_buffer.len > 0);

        const socket_fd = self.tcp.fd;
        var tls_connection = try self.server.tls_ctx.?.createAsyncConnection(
            socket_fd,
            .{ .bio_capacity_bytes = self.read_buffer.len },
        );

        const tls_conn_ptr = self.server.allocator.create(tls.TlsServerConnection) catch |err| {
            tls_connection.deinit();
            return err;
        };
        tls_conn_ptr.* = tls_connection;
        self.tls_conn = tls_conn_ptr;
    }

    fn handleTLSHandshake(self: *Connection, tls_connection: *tls.TlsServerConnection) xev.CallbackAction {
        self.tls_handshake_attempts += 1;
        if (self.tls_handshake_attempts > 50) {
            std.log.warn("TLS handshake timeout after {} attempts on connection {}", .{ self.tls_handshake_attempts, self.tcp.fd });
            self.server.closeConnection(self);
            return .disarm;
        }

        const handshake_state = tls_connection.doAsyncHandshake();
        return self.processTLSHandshakeState(tls_connection, handshake_state);
    }

    fn processTLSHandshakeState(self: *Connection, tls_connection: *tls.TlsServerConnection, handshake_state: anytype) xev.CallbackAction {
        switch (handshake_state) {
            .want_read => {
                if (tls_connection.hasEncryptedDataToSend()) {
                    self.drainTLSEncryptedData(tls_connection);
                }
                self.startReading();
                return .disarm;
            },
            .want_write => {
                if (tls_connection.hasEncryptedDataToSend()) {
                    self.drainTLSEncryptedData(tls_connection);
                }
                return .disarm;
            },
            .complete => {
                self.completeTLSHandshake(tls_connection);
                return .disarm;
            },
            .failed => {
                std.log.err("TLS handshake failed", .{});
                self.server.closeConnection(self);
                return .disarm;
            },
            .need_handshake => {
                self.startReading();
                return .disarm;
            },
        }
    }

    fn completeTLSHandshake(self: *Connection, tls_connection: *tls.TlsServerConnection) void {
        self.tls_handshake_complete = true;

        if (tls_connection.getNegotiatedProtocol()) |protocol| {
            self.negotiated_protocol = protocol;

            if (std.mem.eql(u8, protocol, "http/1.1")) {
                std.log.debug("HTTP/1.1 negotiated via ALPN", .{});
            } else if (std.mem.eql(u8, protocol, "h2")) {
                std.log.debug("HTTP/2 negotiated via ALPN", .{});
            } else {
                std.log.warn("Unknown protocol negotiated: {s}", .{protocol});
            }
        } else {
            std.log.debug("No ALPN protocol negotiated, defaulting to HTTP/1.1", .{});
            self.negotiated_protocol = "http/1.1";
        }

        if (tls_connection.hasEncryptedDataToSend()) {
            self.drainTLSEncryptedData(tls_connection);
        }
        self.flushTLSPlaintext();

        // Critical: Start reading to receive HTTP/2 frames after handshake completion
        std.log.debug("TLS handshake complete, starting to read HTTP/2 data", .{});
        self.startReading();
    }

    fn readTLSApplicationData(self: *Connection, tls_connection: *tls.TlsServerConnection) !void {
        std.debug.assert(self.read_start <= self.read_pos);
        std.debug.assert(self.read_pos <= self.read_buffer.len);

        if (self.read_pos == self.read_buffer.len and self.read_start > 0) {
            self.compactReadBuffer();
        }

        while (self.read_pos < self.read_buffer.len) {
            const bytes_read = try tls_connection.readApplicationData(
                self.read_buffer[self.read_pos..self.read_buffer.len],
            );
            if (bytes_read == 0) {
                return;
            }

            self.read_pos += @intCast(bytes_read);
            std.log.debug("Read {} bytes from TLS, read_pos now: {}", .{
                bytes_read,
                self.readBytesAvailable(),
            });

            if (self.read_pos == self.read_buffer.len and self.read_start > 0) {
                self.compactReadBuffer();
            }
        }
    }

    fn feedTLSEncryptedDataAll(
        self: *Connection,
        tls_connection: *tls.TlsServerConnection,
        network_data: []const u8,
    ) !void {
        _ = self;

        var network_offset: usize = 0;
        while (network_offset < network_data.len) {
            const bytes_written = try tls_connection.feedEncryptedData(
                network_data[network_offset..],
            );
            std.debug.assert(bytes_written > 0);
            network_offset += bytes_written;
        }
    }

    fn readCallbackSimpleTLS(
        self_opt: ?*Connection,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        buffer: xev.ReadBuffer,
        result: xev.ReadError!usize,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;

        const self = self_opt.?;
        self.read_active.store(false, .release);

        const raw_bytes_read = result catch |err| {
            self.handleTLSReadError(err);
            return .disarm;
        };

        if (raw_bytes_read == 0) {
            self.server.closeConnection(self);
            return .disarm;
        }

        if (self.server.tls_ctx != null and self.tls_conn == null) {
            self.initializeTLSConnection() catch |err| {
                std.log.err("Failed to create TLS connection: {}", .{err});
                self.server.closeConnection(self);
                return .disarm;
            };
        }

        // Handle TLS operations with BIO pairs
        if (self.tls_conn) |tls_connection| {
            // Feed raw network data to TLS engine
            if (raw_bytes_read > 0) {
                const network_data = buffer.slice[0..raw_bytes_read];
                self.feedTLSEncryptedDataAll(tls_connection, network_data) catch |err| {
                    std.log.err("Failed to feed encrypted data: {}", .{err});
                    self.server.closeConnection(self);
                    return .disarm;
                };
            }

            if (!self.tls_handshake_complete) {
                _ = self.handleTLSHandshake(tls_connection);
                if (!self.tls_handshake_complete) {
                    return .disarm;
                }
            }

            // Try to read decrypted application data (only after handshake is complete)
            if (self.tls_handshake_complete) {
                self.readTLSApplicationData(tls_connection) catch {
                    std.log.err("TLS application data read error: {s}", .{@tagName(tls_connection.lastReadStatus())});
                    self.server.closeConnection(self);
                    return .disarm;
                };

                switch (tls_connection.lastReadStatus()) {
                    .would_block => {
                        if (tls_connection.hasEncryptedDataToSend()) {
                            std.log.debug("Draining encrypted data before continuing read", .{});
                            self.drainTLSEncryptedData(tls_connection);
                        }
                        if (self.readBytesAvailable() == 0) {
                            std.log.debug("No buffered data, starting next read operation after TLS WouldBlock", .{});
                            self.startReading();
                            return .disarm;
                        }
                    },
                    .connection_closed => {
                        std.log.debug("TLS connection closed by client", .{});

                        if (self.readBytesAvailable() == 0) {
                            if (self.write_active.load(.acquire)) {
                                std.log.debug("Deferring connection close - write still active", .{});
                                self.active = false;
                                return .disarm;
                            }

                            self.server.closeConnection(self);
                            return .disarm;
                        }
                    },
                    else => {},
                }

                // Process any available data in the read buffer (either newly read or previously buffered)
                if (self.readBytesAvailable() > 0) {
                    if (self.awaiting_peer_close) {
                        self.discardBufferedInput();
                    } else {
                    std.log.debug("Processing {} bytes of available data", .{self.readBytesAvailable()});

                    // Handle based on negotiated protocol
                    if (self.negotiated_protocol) |protocol| {
                        if (std.mem.eql(u8, protocol, "h2")) {
                            // Try to initialize HTTP/2 connection (handles preface asynchronously)
                            self.initHttp2Connection() catch |err| switch (err) {
                                // If we need more data, just continue reading
                                else => {
                                    std.log.err("Failed to initialize HTTP/2 connection: {}", .{err});
                                    self.server.closeConnection(self);
                                    return .disarm;
                                },
                            };

                            // Process through simplified HTTP/2 protocol handling
                            self.processHttp2() catch |err| {
                                std.log.err("HTTP/2 protocol error: {}", .{err});
                                self.server.closeConnection(self);
                                return .disarm;
                            };

                            // Connection state is now managed directly in the connection object
                        } else {
                            // Handle HTTP/1.1 request
                            self.processHttp11() catch |err| {
                                std.log.err("HTTP/1.1 processing error: {}", .{err});
                                self.server.closeConnection(self);
                                return .disarm;
                            };
                        }
                    } else {
                        // Default to HTTP/1.1 if no protocol negotiated
                        self.processHttp11() catch |err| {
                            std.log.err("HTTP/1.1 processing error: {}", .{err});
                            self.server.closeConnection(self);
                            return .disarm;
                        };
                    }

                    // After processing, drain any encrypted response data
                    if (tls_connection.hasEncryptedDataToSend()) {
                        self.drainTLSEncryptedData(tls_connection);
                    }

                    std.log.debug("Processed available data, read_pos now: {}, active: {}", .{
                        self.readBytesAvailable(),
                        self.active,
                    });
                    }
                }
            }
        }

        // Continue reading if connection is still active
        if (self.active and !self.close_after_write) {
            std.log.debug("Connection still active, starting next read operation", .{});
            self.startReading();
        } else {
            std.log.debug("Connection no longer active, scheduling async close", .{});
            // Schedule async close to avoid blocking other connections
            self.scheduleAsyncClose();
        }
        return .disarm;
    }

    /// Schedule async close to avoid blocking other connections
    fn scheduleAsyncClose(self: *Self) void {
        if (self.awaiting_peer_close) {
            return;
        }

        const has_pending_writes = self.write_active.load(.acquire) or
            self.tlsHasBufferedWrites();

        if (has_pending_writes) {
            std.log.debug("Deferring close until writes complete (write_buffered: {}, write_active: {}, tls_pending: {})", .{
                self.writeBytesBuffered(),
                self.write_active.load(.acquire),
                self.tlsPlaintextBytesPending(),
            });
            self.close_after_write = true;
            return;
        }

        if (self.shouldShutdownWriteSideAfterGoaway()) {
            self.beginGracefulCloseAfterWrite();
            return;
        }

        // No pending writes, close immediately
        std.log.debug("No pending writes, closing connection immediately", .{});
        self.server.closeConnection(self);
    }

    /// Drain encrypted data from TLS engine to write buffer (legacy synchronous version)
    fn drainTLSEncryptedData(self: *Connection, tls_connection: *tls.TlsServerConnection) void {
        while (tls_connection.hasEncryptedDataToSend()) {
            if (self.write_pos == self.write_buffer.len) {
                self.compactWriteBuffer();
            }
            if (self.write_pos == self.write_buffer.len) {
                std.log.warn("Write buffer full, stopping TLS drain", .{});
                break;
            }

            const encrypted_bytes = tls_connection.readEncryptedData(
                self.write_buffer[self.write_pos..],
            ) catch |err| {
                std.log.err("Failed to read encrypted data: {}", .{err});
                break;
            };
            if (encrypted_bytes == 0) {
                break;
            }

            self.write_pos += @intCast(encrypted_bytes);
        }

        // Start writing if we have data
        if (self.writeBytesBuffered() > 0) {
            self.startWriting();
        }
    }

    /// Async version of TLS encrypted data draining - prevents blocking
    fn drainTLSEncryptedDataAsync(self: *Connection, tls_connection: *tls.TlsServerConnection) void {
        // Check if we already have a write operation in progress
        if (self.write_active.load(.acquire)) {
            std.log.debug("Write operation already in progress, deferring TLS drain", .{});
            return;
        }

        var total_drained: usize = 0;
        var chunks_processed: u32 = 0;
        const max_chunks = 4; // Limit processing to prevent blocking

        while (tls_connection.hasEncryptedDataToSend() and chunks_processed < max_chunks) {
            if (self.write_pos == self.write_buffer.len) {
                self.compactWriteBuffer();
            }
            if (self.write_pos == self.write_buffer.len) {
                std.log.warn("Write buffer full, stopping TLS drain", .{});
                break;
            }

            const encrypted_bytes = tls_connection.readEncryptedData(
                self.write_buffer[self.write_pos..],
            ) catch |err| {
                std.log.err("Failed to read encrypted data: {}", .{err});
                break;
            };
            if (encrypted_bytes == 0) {
                break;
            }

            self.write_pos += @intCast(encrypted_bytes);
            total_drained += encrypted_bytes;
            chunks_processed += 1;
        }

        std.log.debug("Async TLS drain: {} bytes in {} chunks", .{ total_drained, chunks_processed });

        // Start writing if we have data and no write is active
        if (self.writeBytesBuffered() > 0 and !self.write_active.load(.acquire)) {
            self.startWriting();
        }
    }

    /// Callback for write operations
    fn writeCallback(
        self_opt: ?*Connection,
        loop: *xev.Loop,
        completion: *xev.Completion,
        tcp: xev.TCP,
        buffer: xev.WriteBuffer,
        result: xev.WriteError!usize,
    ) xev.CallbackAction {
        _ = loop;
        _ = completion;
        _ = tcp;
        _ = buffer;

        const self = self_opt.?;

        // Assert connection validity before processing
        std.debug.assert(@intFromPtr(self) != 0);
        std.debug.assert(self.write_start <= self.write_pos);
        std.debug.assert(self.write_pos <= self.write_buffer.len);

        const bytes_written = result catch |err| {
            self.write_active.store(false, .release);
            std.log.err("Write failed with error: {} - closing connection", .{err});
            self.server.closeConnection(self);
            return .disarm;
        };

        // Mark write as completed
        self.write_active.store(false, .release);
        std.log.debug("Write completed - {} bytes written, write_active now false", .{bytes_written});

        // Handle write buffer management
        const buffered_bytes = self.writeBytesBuffered();
        const bytes_written_u32: u32 = @intCast(bytes_written);
        std.debug.assert(bytes_written_u32 <= buffered_bytes);

        if (bytes_written_u32 < buffered_bytes) {
            self.write_start += bytes_written_u32;
            self.startWriting();
        } else {
            self.write_start = 0;
            self.write_pos = 0;

            if (self.close_after_write and !self.tlsHasBufferedWrites()) {
                std.log.debug("Write completed with deferred close pending", .{});
                self.beginGracefulCloseAfterWrite();
                return .disarm;
            }
        }

        if (self.active and self.tls_conn != null) {
            if (!self.tls_handshake_complete) {
                self.startReading();
                return .disarm;
            }

            const tls_connection = self.tls_conn.?;
            if (tls_connection.hasEncryptedDataToSend()) {
                self.drainTLSEncryptedDataAsync(tls_connection);
                if (self.write_active.load(.acquire)) {
                    return .disarm;
                }
            }
            if (self.tlsPlaintextBytesPending() > 0) {
                self.flushTLSPlaintext();
            }
        }

        // If connection is no longer active, trigger cleanup
        if (!self.active) {
            std.log.debug("Connection marked inactive - triggering cleanup after write completion", .{});
            self.server.closeConnection(self);
            return .disarm;
        }

        return .disarm;
    }
};

/// Connection pool for efficient memory management
const ConnectionPool = struct {
    pool: []Connection,
    buffers: []u8,
    free_list: std.ArrayList(u32),
    allocator: std.mem.Allocator,
    buffer_size: u32,

    pub fn init(allocator: std.mem.Allocator, max_connections: u32, buffer_size: u32) !ConnectionPool {
        const pool = try allocator.alloc(Connection, max_connections);
        // Allocate all buffers in one contiguous block
        const total_buffer_size = max_connections * buffer_size * 3; // read + write + TLS plaintext
        const buffers = try allocator.alloc(u8, total_buffer_size);

        // Set up buffer slices for each connection and initialize to safe defaults
        for (pool, 0..) |*connection_slot, pool_index| {
            // Assert pool index is within bounds
            std.debug.assert(pool_index < max_connections);

            const buffer_offset = pool_index * buffer_size * 3;
            connection_slot.* = Connection{
                .server = undefined, // Will be set when acquired
                .tcp = undefined, // Will be set when acquired
                .tls_conn = null, // No TLS connection initially
                .read_buffer = buffers[buffer_offset .. buffer_offset + buffer_size],
                .write_buffer = buffers[buffer_offset + buffer_size .. buffer_offset + buffer_size * 2],
                .tls_plaintext_buffer = buffers[buffer_offset + buffer_size * 2 .. buffer_offset + buffer_size * 3],
                .read_start = 0,
                .read_pos = 0,
                .write_start = 0,
                .write_pos = 0,
                .h2_conn = null,
                .h2_reader = undefined,
                .h2_writer = undefined,
                .active = false,
                .http2_initialized = false,
                .tls_handshake_complete = false,
                .tls_handshake_attempts = 0,
                .close_after_write = false,
                .negotiated_protocol = null,
                .next_stream_id = 1,
                .active_streams = std.AutoHashMap(u32, StreamState).init(allocator),
                .read_completions = [2]xev.Completion{ .{}, .{} },
                .write_completions = [2]xev.Completion{ .{}, .{} },
                .shutdown_completion = .{},
                .close_completion = .{},
                .current_read_completion = std.atomic.Value(u8).init(0),
                .current_write_completion = std.atomic.Value(u8).init(0),
                .read_active = std.atomic.Value(bool).init(false),
                .write_active = std.atomic.Value(bool).init(false),
                .tls_plaintext_read_pos = 0,
                .tls_plaintext_write_pos = 0,
                .write_side_shutdown = false,
                .awaiting_peer_close = false,
            };

            connection_slot.h2_reader = Connection.IoAdapters.Reader.init(connection_slot);
            connection_slot.h2_writer = Connection.IoAdapters.Writer.init(connection_slot);
        }

        var free_list = try std.ArrayList(u32).initCapacity(allocator, max_connections);
        for (0..max_connections) |pool_index_usize| {
            const pool_index: u32 = @intCast(pool_index_usize);
            std.debug.assert(pool_index < max_connections);
            free_list.appendAssumeCapacity(pool_index);
        }

        return ConnectionPool{
            .pool = pool,
            .buffers = buffers,
            .free_list = free_list,
            .allocator = allocator,
            .buffer_size = buffer_size,
        };
    }

    pub fn deinit(self: *ConnectionPool) void {
        self.allocator.free(self.buffers);
        self.allocator.free(self.pool);
        self.free_list.deinit(self.allocator);
    }

    pub fn acquire(self: *ConnectionPool) ?*Connection {
        // Assert pool has available connections
        if (self.free_list.items.len == 0) return null;

        const pool_index = self.free_list.items[self.free_list.items.len - 1];
        std.debug.assert(pool_index < self.pool.len);
        std.debug.assert(pool_index < std.math.maxInt(u32));
        self.free_list.items.len -= 1;

        const acquired_connection = &self.pool[pool_index];
        std.debug.assert(!acquired_connection.active);
        return acquired_connection;
    }

    pub fn release(self: *ConnectionPool, released_connection: *Connection) void {
        // Assert connection pointer is valid
        std.debug.assert(@intFromPtr(released_connection) >= @intFromPtr(self.pool.ptr));
        std.debug.assert(@intFromPtr(released_connection) < @intFromPtr(self.pool.ptr) + self.pool.len * @sizeOf(Connection));

        // Validate the connection pointer before calculating index
        if (@intFromPtr(released_connection) < @intFromPtr(self.pool.ptr) or
            @intFromPtr(released_connection) >= @intFromPtr(self.pool.ptr) + self.pool.len * @sizeOf(Connection))
        {
            return;
        }

        const pool_index_usize = (@intFromPtr(released_connection) - @intFromPtr(self.pool.ptr)) / @sizeOf(Connection);
        std.debug.assert(pool_index_usize < self.pool.len);
        std.debug.assert(pool_index_usize <= std.math.maxInt(u32));

        if (pool_index_usize >= self.pool.len) {
            return;
        }

        const pool_index: u32 = @intCast(pool_index_usize);

        // Clear connection state before returning to pool
        released_connection.active = false;
        released_connection.http2_initialized = false;
        released_connection.close_after_write = false;
        released_connection.write_side_shutdown = false;
        released_connection.awaiting_peer_close = false;
        released_connection.read_start = 0;
        released_connection.read_pos = 0;
        released_connection.write_start = 0;
        released_connection.write_pos = 0;
        released_connection.read_active.store(false, .release);
        released_connection.write_active.store(false, .release);

        // Clean up stream state - avoid HashMap operations to prevent alignment issues
        // Simply reset the stream ID counter; streams will be properly managed on next use
        released_connection.next_stream_id = 1;
        released_connection.h2_conn = null;
        released_connection.tls_plaintext_read_pos = 0;
        released_connection.tls_plaintext_write_pos = 0;

        // Clean up TLS connection if it exists (thread-safe)
        if (released_connection.tls_conn) |tls_conn| {
            // Atomically clear the pointer first to prevent double-cleanup
            released_connection.tls_conn = null;

            // TLS cleanup is handled by tls_conn.deinit()

            tls_conn.deinit();
            released_connection.server.allocator.destroy(tls_conn);
        }

        // Reset all TLS-related state
        released_connection.tls_handshake_complete = false;
        released_connection.tls_handshake_attempts = 0;
        released_connection.h2_reader = Connection.IoAdapters.Reader.init(released_connection);
        released_connection.h2_writer = Connection.IoAdapters.Writer.init(released_connection);

        self.free_list.append(self.allocator, pool_index) catch {};
    }
};

// Import for compatibility
const ServerStats = @import("http2.zig").ServerStats;
