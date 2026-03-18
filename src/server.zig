//! HTTP/2 server transport built on the Zig standard library I/O stack.
//!
//! The default build uses `std.Io.Threaded`.
//! On Linux, the experimental `std.Io.Evented` backend can be enabled with
//! `-Devented=true` once the toolchain backend is known to compile cleanly.

const builtin = @import("builtin");
const std = @import("std");
const build_options = @import("build_options");

const connection_module = @import("connection.zig");
const handler = @import("handler.zig");
const tls = @import("tls.zig");

const Connection = connection_module.Connection;
const ServerStats = @import("http2.zig").ServerStats;
const log = std.log.scoped(.server);
const broken_linux_evented_zig =
    std.SemanticVersion.parse("0.16.0-dev.2905+5d71e3051") catch unreachable;

comptime {
    if (build_options.use_evented_backend and builtin.os.tag == .linux and
        builtin.zig_version.order(broken_linux_evented_zig) == .eq)
    {
        @compileError(
            "`-Devented=true` is unsupported on Linux with Zig " ++
                builtin.zig_version_string ++
                " because std.Io.Evented is broken in this toolchain snapshot. " ++
                "Use the default threaded backend or upgrade the pinned Zig version before re-enabling it.",
        );
    }
}

const backend_uses_evented = if (build_options.use_evented_backend)
    builtin.os.tag == .linux and std.Io.Evented != void
else
    false;

const Backend = if (backend_uses_evented)
    struct {
        evented: std.Io.Evented,

        fn init(target: *Backend, allocator: std.mem.Allocator) !void {
            target.* = undefined;
            try target.evented.init(allocator, .{
                .argv0 = .empty,
                .environ = .empty,
                .backing_allocator_needs_mutex = true,
            });
        }

        fn deinit(self: *Backend) void {
            self.evented.deinit();
        }

        fn io(self: *Backend) std.Io {
            return self.evented.io();
        }
    }
else
    struct {
        threaded: std.Io.Threaded,

        fn init(target: *Backend, allocator: std.mem.Allocator) !void {
            target.* = .{
                .threaded = std.Io.Threaded.init(allocator, .{
                    .argv0 = .empty,
                    .environ = .empty,
                }),
            };
        }

        fn deinit(self: *Backend) void {
            self.threaded.deinit();
        }

        fn io(self: *Backend) std.Io {
            return self.threaded.io();
        }
    };

pub const Server = struct {
    allocator: std.mem.Allocator,
    backend: Backend,
    config: Config,
    connection_slots: []ConnectionSlot,
    io_buffer_storage: []u8,
    tls_ctx: ?*tls.TlsServerContext,
    running: std.atomic.Value(bool),
    bound_port: std.atomic.Value(u16),
    listener_closed: std.atomic.Value(bool),
    listener: ?std.Io.net.Server,
    connection_group: std.Io.Group,
    next_connection_slot: std.atomic.Value(u32),
    stats: Stats,

    const Self = @This();

    pub const Config = struct {
        address: std.Io.net.IpAddress,
        router: *handler.Router,
        max_connections: u32 = 1000,
        buffer_size: u32 = 32 * 1024,
    };

    const ConnectionSlot = struct {
        in_use: std.atomic.Value(bool),
        read_buffer: []u8,
        write_buffer: []u8,
        stream_storage: Connection.StreamStorage,
    };

    const Stats = struct {
        total_connections: std.atomic.Value(u64),
        active_connections: std.atomic.Value(u32),
        requests_processed: std.atomic.Value(u64),

        fn init() Stats {
            return .{
                .total_connections = .init(0),
                .active_connections = .init(0),
                .requests_processed = .init(0),
            };
        }
    };

    fn initWithOptionalTls(
        allocator: std.mem.Allocator,
        config: Config,
        tls_ctx: ?*tls.TlsServerContext,
    ) !Self {
        assertConfig(config);

        var backend: Backend = undefined;
        try Backend.init(&backend, allocator);
        errdefer backend.deinit();

        const io_buffer_storage = try allocator.alloc(u8, totalIoBufferBytes(config));
        errdefer allocator.free(io_buffer_storage);

        const connection_slots = try allocator.alloc(
            ConnectionSlot,
            @as(usize, @intCast(config.max_connections)),
        );
        errdefer allocator.free(connection_slots);

        initConnectionSlots(connection_slots, io_buffer_storage, config.buffer_size);

        return .{
            .allocator = allocator,
            .backend = backend,
            .config = config,
            .connection_slots = connection_slots,
            .io_buffer_storage = io_buffer_storage,
            .tls_ctx = tls_ctx,
            .running = .init(false),
            .bound_port = .init(0),
            .listener_closed = .init(true),
            .listener = null,
            .connection_group = .init,
            .next_connection_slot = .init(0),
            .stats = Stats.init(),
        };
    }

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        return initWithOptionalTls(allocator, config, null);
    }

    pub fn initWithTLS(
        allocator: std.mem.Allocator,
        config: Config,
        tls_ctx: *tls.TlsServerContext,
    ) !Self {
        std.debug.assert(@intFromPtr(tls_ctx) != 0);
        return initWithOptionalTls(allocator, config, tls_ctx);
    }

    pub fn deinit(self: *Self) void {
        const io = self.backend.io();

        if (self.running.load(.acquire)) {
            self.stop();
        }

        if (self.listener != null) {
            self.cleanupListener(io);
        }

        self.allocator.free(self.connection_slots);
        self.allocator.free(self.io_buffer_storage);
        self.backend.deinit();
    }

    pub fn run(self: *Self) !void {
        const io = self.backend.io();

        std.debug.assert(self.listener == null);
        std.debug.assert(!self.running.load(.acquire));

        self.listener = try self.config.address.listen(io, .{
            .kernel_backlog = 4096,
            .reuse_address = true,
            .mode = .stream,
            .protocol = .tcp,
        });
        self.bound_port.store(self.listener.?.socket.address.getPort(), .release);
        self.listener_closed.store(false, .release);
        self.running.store(true, .release);

        defer {
            self.running.store(false, .release);
            self.cleanupListener(io);
        }

        logListening(self);
        const accept_result = self.runAcceptLoop(io);
        self.running.store(false, .release);
        self.connection_group.cancel(io);
        try accept_result;
    }

    pub fn stop(self: *Self) void {
        self.running.store(false, .release);

        if (self.listener == null) {
            return;
        }
        if (self.listener_closed.swap(true, .acq_rel)) {
            return;
        }

        self.listener.?.socket.close(self.backend.io());
    }

    pub fn getStats(self: *const Self) ServerStats {
        return .{
            .total_connections = self.stats.total_connections.load(.acquire),
            .active_connections = self.stats.active_connections.load(.acquire),
            .requests_processed = self.stats.requests_processed.load(.acquire),
        };
    }

    pub fn listeningPort(self: *const Self) u16 {
        return self.bound_port.load(.acquire);
    }

    fn runAcceptLoop(self: *Self, io: std.Io) !void {
        while (self.running.load(.acquire)) {
            var stream = self.listener.?.accept(io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                error.SocketNotListening => break,
                error.Canceled => break,
                else => return err,
            };

            const connection_slot = self.acquireConnectionSlot() orelse {
                stream.close(io);
                continue;
            };

            self.spawnConnectionTask(io, stream, connection_slot) catch |err| {
                stream.close(io);
                self.releaseConnectionSlot(connection_slot);
                return err;
            };
        }
    }

    fn spawnConnectionTask(
        self: *Self,
        io: std.Io,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) !void {
        if (backend_uses_evented) {
            self.connection_group.async(io, serveConnectionTask, .{
                self,
                stream,
                connection_slot,
            });
            return;
        }

        // The threaded backend consumes a worker while a connection blocks in
        // TLS or socket I/O, so a connection task requires concurrency rather
        // than mere asynchrony.
        try self.connection_group.concurrent(io, serveConnectionTask, .{
            self,
            stream,
            connection_slot,
        });
    }

    fn acquireConnectionSlot(self: *Self) ?*ConnectionSlot {
        const slot_count: u32 = @intCast(self.connection_slots.len);
        var attempt_count: u32 = 0;

        while (attempt_count < slot_count) : (attempt_count += 1) {
            const current_index = self.next_connection_slot.load(.acquire);
            const next_index = if (current_index + 1 < slot_count)
                current_index + 1
            else
                0;

            if (self.next_connection_slot.cmpxchgWeak(
                current_index,
                next_index,
                .acq_rel,
                .acquire,
            ) != null) {
                continue;
            }

            const connection_slot = &self.connection_slots[@as(usize, @intCast(current_index))];
            if (connection_slot.in_use.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) {
                continue;
            }

            _ = self.stats.active_connections.fetchAdd(1, .acq_rel);
            _ = self.stats.total_connections.fetchAdd(1, .acq_rel);
            return connection_slot;
        }

        return null;
    }

    fn releaseConnectionSlot(self: *Self, connection_slot: *ConnectionSlot) void {
        connection_slot.in_use.store(false, .release);
        _ = self.stats.active_connections.fetchSub(1, .acq_rel);
    }

    fn cleanupListener(self: *Self, io: std.Io) void {
        if (self.listener) |*listener| {
            if (!self.listener_closed.swap(true, .acq_rel)) {
                listener.deinit(io);
            }
            self.listener = null;
        }

        self.bound_port.store(0, .release);
    }

    fn serveConnectionTask(
        self: *Self,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) std.Io.Cancelable!void {
        const io = self.backend.io();

        defer {
            var stream_copy = stream;
            stream_copy.close(io);
            self.releaseConnectionSlot(connection_slot);
        }

        self.serveAcceptedStream(io, stream, connection_slot) catch |err| {
            logConnectionError(err);
        };
    }

    fn serveAcceptedStream(
        self: *Self,
        io: std.Io,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) !void {
        if (self.tls_ctx) |tls_ctx| {
            return self.serveTlsConnection(tls_ctx, stream, connection_slot);
        }
        return self.servePlainConnection(io, stream, connection_slot);
    }

    fn servePlainConnection(
        self: *Self,
        io: std.Io,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) !void {
        var reader = stream.reader(io, connection_slot.read_buffer);
        var writer = stream.writer(io, connection_slot.write_buffer);
        try self.runHttp2Connection(&reader.interface, &writer.interface, connection_slot);
    }

    fn serveTlsConnection(
        self: *Self,
        tls_ctx: *tls.TlsServerContext,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) !void {
        var tls_connection = try tls_ctx.accept(stream.socket.handle);
        defer tls_connection.deinit();

        try self.runHttp2Connection(
            tls_connection.reader(),
            tls_connection.writer(),
            connection_slot,
        );
    }

    fn runHttp2Connection(
        self: *Self,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        connection_slot: *ConnectionSlot,
    ) !void {
        var h2_connection: Connection = undefined;
        try Connection.initServerInPlace(
            &h2_connection,
            &connection_slot.stream_storage,
            self.allocator,
            reader,
            writer,
        );
        defer {
            self.recordCompletedResponses(&h2_connection);
            h2_connection.deinit();
        }

        try h2_connection.handle_connection();
    }

    fn recordCompletedResponses(self: *Self, h2_connection: *Connection) void {
        const completed_responses = h2_connection.takeCompletedResponses();

        if (completed_responses == 0) {
            return;
        }

        _ = self.stats.requests_processed.fetchAdd(completed_responses, .acq_rel);
    }
};

fn assertConfig(config: Server.Config) void {
    std.debug.assert(@intFromPtr(config.router) != 0);
    std.debug.assert(config.max_connections > 0);
    std.debug.assert(config.max_connections <= 10000);
    std.debug.assert(config.buffer_size >= 1024);
    std.debug.assert(config.buffer_size <= 1024 * 1024);
}

fn totalIoBufferBytes(config: Server.Config) usize {
    const connection_count = @as(usize, @intCast(config.max_connections));
    const buffer_size_bytes = @as(usize, @intCast(config.buffer_size));
    const per_connection_bytes = buffer_size_bytes * 2;

    std.debug.assert(connection_count > 0);
    std.debug.assert(buffer_size_bytes > 0);
    std.debug.assert(per_connection_bytes >= buffer_size_bytes);

    return connection_count * per_connection_bytes;
}

fn initConnectionSlots(
    connection_slots: []Server.ConnectionSlot,
    io_buffer_storage: []u8,
    buffer_size_u32: u32,
) void {
    const buffer_size_bytes = @as(usize, @intCast(buffer_size_u32));
    const io_bytes_per_connection = buffer_size_bytes * 2;

    std.debug.assert(connection_slots.len > 0);
    std.debug.assert(buffer_size_bytes > 0);
    std.debug.assert(io_buffer_storage.len == connection_slots.len * io_bytes_per_connection);

    var io_buffer_offset: usize = 0;
    for (connection_slots) |*connection_slot| {
        const read_buffer = io_buffer_storage[io_buffer_offset .. io_buffer_offset + buffer_size_bytes];
        io_buffer_offset += buffer_size_bytes;

        const write_buffer = io_buffer_storage[io_buffer_offset .. io_buffer_offset + buffer_size_bytes];
        io_buffer_offset += buffer_size_bytes;

        connection_slot.* = .{
            .in_use = .init(false),
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .stream_storage = undefined,
        };
    }

    std.debug.assert(io_buffer_offset == io_buffer_storage.len);
}

fn logListening(self: *const Server) void {
    const label = backendLabel();

    if (self.tls_ctx) |_| {
        log.info("HTTP/2 over TLS listening on {f} via {s}", .{
            self.listener.?.socket.address,
            label,
        });
        return;
    }

    log.info("HTTP/2 listening on {f} via {s}", .{
        self.listener.?.socket.address,
        label,
    });
}

fn backendLabel() []const u8 {
    if (!backend_uses_evented) {
        return "std.Io.Threaded";
    }

    return switch (builtin.os.tag) {
        .linux => "std.Io.Evented (io_uring)",
        .dragonfly, .freebsd, .netbsd, .openbsd => "std.Io.Evented (kqueue)",
        .driverkit,
        .ios,
        .maccatalyst,
        .macos,
        .tvos,
        .visionos,
        .watchos,
        => "std.Io.Evented (Dispatch)",
        else => "std.Io.Evented",
    };
}

fn logConnectionError(err: anyerror) void {
    switch (err) {
        error.Canceled,
        error.ConnectionReset,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.ReadFailed,
        error.UnexpectedEOF,
        error.EndOfStream,
        => log.debug("Connection closed: {s}", .{@errorName(err)}),
        error.InvalidPreface => log.debug("Rejected non-HTTP/2 preface", .{}),
        else => log.warn("Connection failed: {s}", .{@errorName(err)}),
    }
}

const ServerRunContext = struct {
    server: *Server,
    err: ?anyerror = null,

    fn run(context: *ServerRunContext) void {
        context.server.run() catch |err| {
            context.err = err;
        };
    }
};

fn waitForServerPort(server: *const Server) !u16 {
    var spin_count: u32 = 0;

    while (true) : (spin_count += 1) {
        const port = server.listeningPort();
        if (port != 0) {
            return port;
        }

        try std.testing.expect(spin_count < 10_000);
        std.Thread.yield() catch {};
    }
}

fn waitForActiveConnection(server: *const Server) !void {
    var spin_count: u32 = 0;

    while (true) : (spin_count += 1) {
        if (server.getStats().active_connections != 0) {
            return;
        }

        try std.testing.expect(spin_count < 10_000);
        std.Thread.yield() catch {};
    }
}

test "server initialization keeps stats at zero" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var router = handler.Router.init(allocator);
    defer router.deinit();

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .router = &router,
    });
    defer server.deinit();

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_connections);
    try std.testing.expectEqual(@as(u32, 0), stats.active_connections);
    try std.testing.expectEqual(@as(u64, 0), stats.requests_processed);
}

test "stop cancels idle async connections" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var router = handler.Router.init(allocator);
    defer router.deinit();

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .router = &router,
        .max_connections = 8,
        .buffer_size = 16 * 1024,
    });
    defer server.deinit();

    var run_context = ServerRunContext{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunContext.run, .{&run_context});
    var server_thread_joined = false;
    defer if (!server_thread_joined) {
        server.stop();
        server_thread.join();
    };

    const port = try waitForServerPort(&server);
    const io = std.Io.Threaded.global_single_threaded.io();
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const client_stream = try address.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    });
    var client_stream_open = true;
    defer if (client_stream_open) {
        client_stream.close(io);
    };

    try waitForActiveConnection(&server);

    server.stop();
    server_thread.join();
    server_thread_joined = true;

    client_stream.close(io);
    client_stream_open = false;

    try std.testing.expect(run_context.err == null);
    try std.testing.expectEqual(@as(u32, 0), server.getStats().active_connections);
    try std.testing.expectEqual(@as(u64, 1), server.getStats().total_connections);
}
