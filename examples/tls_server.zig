const std = @import("std");
const boring = @import("boring");
const http2 = @import("http2");
const http2_boring = @import("http2-boring");

const log = std.log.scoped(.tls_server);
const adapter_io_buffer_size: u32 = @intCast(@max(
    http2_boring.TcpBufferSize,
    http2_boring.TlsBufferSize,
));
const listener_handle_none = std.math.maxInt(usize);

const RunState = enum(u8) {
    stopped,
    starting,
    running,
    stopping,
};

comptime {
    if (adapter_io_buffer_size > http2.MemBudget.max_io_buffer_size_bytes) {
        @compileError("http2-boring I/O buffers exceed the HTTP/2 memory budget");
    }
}

pub const Config = struct {
    address: std.Io.net.IpAddress,
    dispatcher: http2.RequestDispatcher,
    cert_file: [:0]const u8 = "cert.pem",
    key_file: [:0]const u8 = "key.pem",
    max_connections: u32 = http2.MemBudget.max_connections,
    worker_count: u16 = http2.MemBudget.worker_count,
};

pub const Server = struct {
    startup_allocator: std.mem.Allocator,
    backend: Backend,
    config: Config,
    acceptor: http2_boring.Acceptor,
    connection_slots: []ConnectionSlot,
    connection_group: std.Io.Group,
    run_state: std.atomic.Value(RunState),
    listener_mutex: std.atomic.Mutex,
    listener_handle: usize,
    bound_port: std.atomic.Value(u16),
    listener: ?std.Io.net.Server,
    next_connection_slot: u32,
    stats: Stats,
    runtime_plan: http2.memory_budget.RuntimePlan,

    const Self = @This();

    const Backend = if (http2.has_event_loop_backend) struct {
        allocator: std.mem.Allocator,
        evented: *http2.EventLoop,

        fn init(
            allocator: std.mem.Allocator,
            runtime_plan: http2.memory_budget.RuntimePlan,
        ) !Backend {
            const evented = try allocator.create(http2.EventLoop);
            errdefer allocator.destroy(evented);

            try evented.init(allocator, .{
                .n_threads = @intCast(runtime_plan.worker_count),
                .max_concurrent_tasks = @intCast(runtime_plan.fiber_count),
                .max_wait_registrations_per_thread = @intCast(
                    runtime_plan.wait_registration_count_per_thread,
                ),
            });
            errdefer evented.deinit();

            return .{
                .allocator = allocator,
                .evented = evented,
            };
        }

        fn deinit(self: *Backend) void {
            self.evented.deinit();
            self.allocator.destroy(self.evented);
        }

        fn io(self: *Backend) std.Io {
            return self.evented.io();
        }

        fn attachCurrentThread(self: *Backend) !void {
            try self.evented.attachCurrentThread();
        }

        fn detachCurrentThread(self: *Backend) void {
            self.evented.detachCurrentThread();
        }

        fn interruptMainWait(self: *Backend, fd: std.posix.fd_t) void {
            self.evented.interruptMainWait(fd);
        }

        fn clearMainCancellation(self: *Backend) void {
            self.evented.clearMainCancellation();
        }
    } else struct {
        fn init(
            allocator: std.mem.Allocator,
            runtime_plan: http2.memory_budget.RuntimePlan,
        ) !Backend {
            _ = allocator;
            _ = runtime_plan;
            return error.StaticBackendUnavailable;
        }

        fn deinit(self: *Backend) void {
            _ = self;
            unreachable;
        }

        fn io(self: *Backend) std.Io {
            _ = self;
            unreachable;
        }

        fn attachCurrentThread(self: *Backend) !void {
            _ = self;
        }

        fn detachCurrentThread(self: *Backend) void {
            _ = self;
        }

        fn interruptMainWait(self: *Backend, fd: std.posix.fd_t) void {
            _ = self;
            _ = fd;
            unreachable;
        }

        fn clearMainCancellation(self: *Backend) void {
            _ = self;
            unreachable;
        }
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

    const ConnectionSlot = struct {
        in_use: std.atomic.Value(bool),
        tls_connection: http2_boring.Connection,
        stream_storage: http2.Connection.StreamStorage = undefined,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        if (!http2.memory_budget.isStaticAllocatorInitialized()) {
            return error.StaticAllocatorNotInitialized;
        }
        if (!http2.memory_budget.backingAllocatorMatches(allocator)) {
            return error.BackingAllocatorMismatch;
        }
        if (!http2.has_event_loop_backend) return error.StaticBackendUnavailable;
        const runtime_plan = try http2.memory_budget.RuntimePlan.init(
            config.max_connections,
            adapter_io_buffer_size,
            config.worker_count,
        );
        _ = try runtime_plan.totalMemoryBytesForSlots(
            @sizeOf(ConnectionSlot),
            0,
        );
        const static_allocator = http2.staticAllocator();

        boring.init();

        var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
        defer builder.deinit();

        try builder.setCertificateChainFile(config.cert_file);
        try builder.setPrivateKeyFile(config.key_file, .pem);
        try builder.checkPrivateKey();

        var acceptor = http2_boring.Acceptor.initWithBuilder(&builder);
        errdefer acceptor.deinit();

        const connection_slots = try static_allocator.alloc(
            ConnectionSlot,
            @as(usize, @intCast(config.max_connections)),
        );
        errdefer static_allocator.free(connection_slots);

        initConnectionSlots(connection_slots);

        var backend = try Backend.init(static_allocator, runtime_plan);
        errdefer backend.deinit();

        return .{
            .startup_allocator = static_allocator,
            .backend = backend,
            .config = config,
            .acceptor = acceptor,
            .connection_slots = connection_slots,
            .connection_group = .init,
            .run_state = .init(.stopped),
            .listener_mutex = .unlocked,
            .listener_handle = listener_handle_none,
            .bound_port = .init(0),
            .listener = null,
            .next_connection_slot = 0,
            .stats = Stats.init(),
            .runtime_plan = runtime_plan,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.run_state.load(.acquire) != .stopped) {
            @panic("TLS Server.deinit requires run() to return after stop()");
        }
        if (self.stats.active_connections.load(.acquire) != 0) {
            @panic("TLS Server.deinit found active connection tasks");
        }
        if (self.listener != null) {
            @panic("TLS Server.deinit found a live listener");
        }
        if (self.listener_handle != listener_handle_none) {
            @panic("TLS Server.deinit found a published listener handle");
        }

        http2.beginDeinit();
        self.backend.deinit();
        self.startup_allocator.free(self.connection_slots);
        self.acceptor.deinit();
        self.* = undefined;
    }

    pub fn run(self: *Self) !void {
        if (self.run_state.cmpxchgStrong(
            .stopped,
            .starting,
            .acq_rel,
            .acquire,
        ) != null) return error.ServerAlreadyRunning;
        defer self.run_state.store(.stopped, .release);

        try self.backend.attachCurrentThread();
        defer self.backend.detachCurrentThread();

        http2.freezeIfNeeded();
        const memory_at_runtime_start = http2.memory_budget.allocatorSnapshot();
        const io = self.backend.io();

        std.debug.assert(self.listener == null);
        std.debug.assert(self.listener_handle == listener_handle_none);

        self.listener = try self.config.address.listen(io, .{
            .kernel_backlog = 4096,
            .reuse_address = true,
            .mode = .stream,
            .protocol = .tcp,
        });
        const listener_handle: usize = @intCast(self.listener.?.socket.handle);
        self.publishListenerHandle(listener_handle);

        defer {
            self.cleanupListener(io);
        }

        const start_result = self.run_state.cmpxchgStrong(
            .starting,
            .running,
            .acq_rel,
            .acquire,
        );
        if (start_result) |observed_state| {
            if (observed_state != .stopping) {
                @panic("TLS Server entered an invalid startup state");
            }
        } else {
            self.bound_port.store(self.listener.?.socket.address.getPort(), .release);
            log.info("HTTP/2 TLS listening on {f}", .{self.listener.?.socket.address});
        }

        const accept_result = if (start_result == null) self.runAcceptLoop(io) else {};
        self.connection_group.cancel(io);
        assertRuntimeMemoryUnchanged(memory_at_runtime_start);
        accept_result catch |err| {
            if (self.run_state.load(.acquire) == .stopping) return;
            return err;
        };
    }

    pub fn stop(self: *Self) void {
        self.lockListener();
        defer self.listener_mutex.unlock();
        if (!requestStop(&self.run_state)) return;
        if (self.listener_handle == listener_handle_none) return;
        self.backend.interruptMainWait(@intCast(self.listener_handle));
    }

    pub fn getStats(self: *const Self) http2.ServerStats {
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
        while (self.run_state.load(.acquire) == .running) {
            const stream = self.listener.?.accept(io) catch |err| {
                if (self.run_state.load(.acquire) != .running) {
                    break;
                }
                switch (err) {
                    error.ConnectionAborted => continue,
                    error.SocketNotListening => break,
                    error.Canceled => break,
                    else => return err,
                }
            };

            const connection_slot = self.acquireConnectionSlot() orelse {
                var stream_copy = stream;
                stream_copy.close(io);
                continue;
            };
            self.spawnConnectionTask(io, stream, connection_slot) catch |err| {
                var stream_copy = stream;
                stream_copy.close(io);
                self.releaseConnectionSlot(connection_slot);
                if (err == error.ConcurrencyUnavailable) continue;
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
        const raw_handle = self.unpublishListenerHandle();
        if (self.listener) |*listener| {
            if (raw_handle != @as(usize, @intCast(listener.socket.handle))) {
                @panic("TLS listener handle changed while published");
            }
            listener.deinit(io);
        } else {
            @panic("TLS Server lost its published listener");
        }
        self.listener = null;
        self.backend.clearMainCancellation();
        self.bound_port.store(0, .release);
    }

    fn publishListenerHandle(self: *Self, raw_handle: usize) void {
        self.lockListener();
        defer self.listener_mutex.unlock();
        if (self.listener_handle != listener_handle_none) {
            @panic("TLS listener published twice");
        }
        self.listener_handle = raw_handle;
    }

    fn unpublishListenerHandle(self: *Self) usize {
        self.lockListener();
        defer self.listener_mutex.unlock();
        if (self.listener_handle == listener_handle_none) {
            @panic("TLS Server lost its published listener handle");
        }
        const raw_handle = self.listener_handle;
        self.listener_handle = listener_handle_none;
        return raw_handle;
    }

    fn lockListener(self: *Self) void {
        while (!self.listener_mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn recordCompletedResponses(self: *Self, completed_responses: u32) void {
        if (completed_responses == 0) return;
        _ = self.stats.requests_processed.fetchAdd(completed_responses, .acq_rel);
    }

    fn serveConnectionTask(
        server: *Self,
        stream: std.Io.net.Stream,
        connection_slot: *ConnectionSlot,
    ) std.Io.Cancelable!void {
        const io = server.backend.io();

        defer {
            server.releaseConnectionSlot(connection_slot);
        }

        const connection = &connection_slot.tls_connection;
        connection.* = .{};
        defer connection.deinit(io);

        server.acceptor.accept(connection, io, stream) catch |err| {
            logConnectionError(err);
            return;
        };

        var completed_responses: u32 = 0;
        defer server.recordCompletedResponses(completed_responses);

        _ = http2.serveConnection(
            connection.reader(),
            connection.writer(),
            .{
                .dispatcher = server.config.dispatcher,
                .stream_storage = &connection_slot.stream_storage,
                .completed_responses_out = &completed_responses,
            },
        ) catch |err| {
            logConnectionError(err);
            return;
        };
    }
};

fn requestStop(run_state: *std.atomic.Value(RunState)) bool {
    while (true) {
        const current = run_state.load(.acquire);
        switch (current) {
            .stopped => return false,
            .stopping => return true,
            .starting, .running => {},
        }
        if (run_state.cmpxchgWeak(
            current,
            .stopping,
            .acq_rel,
            .acquire,
        ) == null) return true;
    }
}

pub const static_memory_ceiling_bytes: usize = blk: {
    const maximum_plan = http2.memory_budget.RuntimePlan.init(
        http2.MemBudget.max_connections,
        adapter_io_buffer_size,
        http2.MemBudget.worker_count_max,
    ) catch |err| @compileError(@errorName(err));
    break :blk maximum_plan.totalMemoryBytesForSlots(
        @sizeOf(Server.ConnectionSlot),
        0,
    ) catch |err| @compileError(@errorName(err));
};

fn assertRuntimeMemoryUnchanged(start: http2.memory_budget.AllocatorSnapshot) void {
    const finish = http2.memory_budget.allocatorSnapshot();
    if (finish.allocations_live != start.allocations_live) {
        @panic("TLS runtime changed the static allocation count");
    }
    if (finish.bytes_live != start.bytes_live) {
        @panic("TLS runtime changed the static byte count");
    }
    if (finish.bytes_reserved != start.bytes_reserved) {
        @panic("TLS runtime changed the reserved byte count");
    }
    if (finish.state != .static) {
        @panic("TLS runtime left the static allocation phase");
    }
}

fn initConnectionSlots(connection_slots: []Server.ConnectionSlot) void {
    std.debug.assert(connection_slots.len > 0);

    for (connection_slots) |*connection_slot| {
        connection_slot.* = .{
            .in_use = .init(false),
            .tls_connection = .{},
        };
        connection_slot.stream_storage.init();
    }
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
        error.NoApplicationProtocol => log.debug("Rejected TLS connection without ALPN h2", .{}),
        error.InvalidPreface => log.debug("Rejected non-HTTP/2 preface", .{}),
        else => log.warn("Connection failed: {s}", .{@errorName(err)}),
    }
}
