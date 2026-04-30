//! HTTP/2 server transport built on the Zig standard library I/O stack.

const std = @import("std");

const connection_module = @import("connection.zig");
const handler = @import("handler.zig");
const transport = @import("transport.zig");
const http2 = @import("http2.zig");
// Local fork of `std.Io.Kqueue` patched to compile against the current
// `std.Io.VTable` shape. See `src/io/Kqueue.zig` for the rationale.
const Kqueue = http2.Kqueue;

const Connection = connection_module.Connection;
const ServerStats = @import("http2.zig").ServerStats;
const log = std.log.scoped(.server);

const Backend = if (http2.has_kqueue_backend) struct {
    allocator: std.mem.Allocator,
    evented: ?*Kqueue,

    fn init(allocator: std.mem.Allocator) Backend {
        return .{
            .allocator = allocator,
            .evented = null,
        };
    }

    fn start(self: *Backend) !void {
        std.debug.assert(self.evented == null);

        const evented = try self.allocator.create(Kqueue);
        errdefer self.allocator.destroy(evented);

        try evented.init(self.allocator, .{
            .n_threads = null,
        });
        errdefer evented.deinit();

        self.evented = evented;
    }

    fn deinit(self: *Backend) void {
        const evented = self.evented orelse return;

        evented.deinit();
        self.allocator.destroy(evented);
        self.evented = null;
    }

    fn io(self: *Backend) std.Io {
        return self.evented.?.io();
    }
} else struct {
    fn init(_: std.mem.Allocator) Backend {
        return .{};
    }

    fn start(_: *Backend) !void {}

    fn deinit(_: *Backend) void {}

    fn io(_: *Backend) std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    backend: Backend,
    config: Config,
    connection_slots: []ConnectionSlot,
    io_buffer_storage: []u8,
    running: std.atomic.Value(bool),
    bound_port: std.atomic.Value(u16),
    listener_closed: std.atomic.Value(bool),
    listener: ?std.Io.net.Server,
    connection_group: std.Io.Group,
    next_connection_slot: u32,
    stats: Stats,

    const Self = @This();

    pub const Config = struct {
        address: std.Io.net.IpAddress,
        dispatcher: handler.RequestDispatcher,
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

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        assertConfig(config);

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
            .backend = Backend.init(allocator),
            .config = config,
            .connection_slots = connection_slots,
            .io_buffer_storage = io_buffer_storage,
            .running = .init(false),
            .bound_port = .init(0),
            .listener_closed = .init(true),
            .listener = null,
            .connection_group = .init,
            .next_connection_slot = 0,
            .stats = Stats.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.running.load(.acquire)) {
            self.stop();
        }

        if (self.listener != null) {
            const io = self.backend.io();
            self.cleanupListener(io);
        }

        self.allocator.free(self.connection_slots);
        self.allocator.free(self.io_buffer_storage);
        self.backend.deinit();
    }

    pub fn run(self: *Self) !void {
        try self.backend.start();
        defer self.backend.deinit();

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
            var stream = self.listener.?.accept(io) catch |err| {
                if (!self.running.load(.acquire) or self.listener_closed.load(.acquire)) {
                    break;
                }

                switch (err) {
                    error.ConnectionAborted => continue,
                    error.SocketNotListening => break,
                    error.Canceled => break,
                    else => return err,
                }
            };

            setTcpNoDelay(stream.socket.handle);

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
        // Use grouped concurrency so each accepted connection has independent
        // cancellation and completion accounting inside the evented backend.
        try self.connection_group.concurrent(io, serveConnectionTask, .{
            self,
            stream,
            connection_slot,
        });
    }

    fn acquireConnectionSlot(self: *Self) ?*ConnectionSlot {
        const slot_count: u32 = @intCast(self.connection_slots.len);
        std.debug.assert(slot_count > 0);

        var probe_count: u32 = 0;
        while (probe_count < slot_count) : (probe_count += 1) {
            const slot_index = self.next_connection_slot;
            self.next_connection_slot = if (slot_index + 1 < slot_count)
                slot_index + 1
            else
                0;

            const connection_slot = &self.connection_slots[@as(usize, @intCast(slot_index))];
            if (connection_slot.in_use.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) {
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

        self.servePlainConnection(io, stream, connection_slot) catch |err| {
            logConnectionError(err);
        };
    }

    fn servePlainConnection(
        self: *Self,
        io: std.Io,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) !void {
        var reader = stream.reader(io, connection_slot.read_buffer);
        var writer = stream.writer(io, connection_slot.write_buffer);

        var completed_responses: u32 = 0;
        defer self.recordCompletedResponses(completed_responses);

        _ = try transport.serveConnection(
            self.allocator,
            &reader.interface,
            &writer.interface,
            .{
                .dispatcher = self.config.dispatcher,
                .stream_storage = &connection_slot.stream_storage,
                .completed_responses_out = &completed_responses,
            },
        );
    }

    fn recordCompletedResponses(self: *Self, completed_responses: u32) void {
        if (completed_responses != 0) {
            _ = self.stats.requests_processed.fetchAdd(completed_responses, .acq_rel);
        }
    }
};

fn assertConfig(config: Server.Config) void {
    _ = config.dispatcher;
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

    log.info("HTTP/2 listening on {f} via {s}", .{
        self.listener.?.socket.address,
        label,
    });
}

fn backendLabel() []const u8 {
    return "Kqueue";
}

fn setTcpNoDelay(fd: std.posix.fd_t) void {
    const value: c_int = 1;
    _ = std.posix.setsockopt(
        fd,
        std.posix.IPPROTO.TCP,
        std.posix.TCP.NODELAY,
        std.mem.asBytes(&value),
    ) catch {};
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
    for (0..5 * std.time.ms_per_s) |_| {
        const port = server.listeningPort();
        if (port != 0) {
            return port;
        }

        sleepOneMs();
    }

    return error.TestUnexpectedResult;
}

fn waitForAcceptedConnection(server: *const Server) !void {
    for (0..5 * std.time.ms_per_s) |_| {
        if (server.getStats().total_connections != 0) {
            return;
        }

        sleepOneMs();
    }

    return error.TestUnexpectedResult;
}

fn sleepOneMs() void {
    var remaining: std.posix.timespec = .{
        .sec = 0,
        .nsec = std.time.ns_per_ms,
    };

    while (true) {
        switch (std.posix.errno(std.posix.system.nanosleep(&remaining, &remaining))) {
            .SUCCESS => return,
            .INTR => continue,
            else => return,
        }
    }
}

fn testRequestHandler(ctx: *const handler.Context) !handler.Response {
    return ctx.response.text(.ok, "test");
}

test "server initialization keeps stats at zero" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .dispatcher = handler.RequestDispatcher.fromHandler(testRequestHandler),
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

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .dispatcher = handler.RequestDispatcher.fromHandler(testRequestHandler),
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

    try waitForAcceptedConnection(&server);

    server.stop();
    server_thread.join();
    server_thread_joined = true;

    client_stream.close(io);
    client_stream_open = false;

    try std.testing.expect(run_context.err == null);
    try std.testing.expectEqual(@as(u32, 0), server.getStats().active_connections);
    try std.testing.expectEqual(@as(u64, 1), server.getStats().total_connections);
}
