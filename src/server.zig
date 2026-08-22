//! HTTP/2 server transport built on the Zig standard library I/O stack.

const std = @import("std");

const connection_module = @import("connection.zig");
const handler = @import("handler.zig");
const transport = @import("transport.zig");
const http2 = @import("http2.zig");
const memory_budget = @import("memory_budget.zig");
// Local fork of `std.Io.Kqueue` patched to compile against the current
// `std.Io.VTable` shape. See `src/io/Kqueue.zig` for the rationale.
const Kqueue = http2.Kqueue;

const Connection = connection_module.Connection;
const ServerStats = @import("http2.zig").ServerStats;
const log = std.log.scoped(.server);
const listener_handle_none = std.math.maxInt(usize);

const RunState = enum(u8) {
    stopped,
    starting,
    running,
    stopping,
};

const Backend = if (http2.has_kqueue_backend) struct {
    allocator: std.mem.Allocator,
    evented: *Kqueue,

    fn init(
        allocator: std.mem.Allocator,
        runtime_plan: memory_budget.RuntimePlan,
    ) !Backend {
        const evented = try allocator.create(Kqueue);
        errdefer allocator.destroy(evented);

        try evented.init(allocator, .{
            .n_threads = runtime_plan.worker_count,
            .max_concurrent_tasks = runtime_plan.fiber_count,
            .max_wait_registrations_per_thread = runtime_plan.wait_registration_count_per_thread,
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
        self.* = undefined;
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
        runtime_plan: memory_budget.RuntimePlan,
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

pub const Server = struct {
    startup_allocator: std.mem.Allocator,
    backend: Backend,
    config: Config,
    runtime_plan: memory_budget.RuntimePlan,
    connection_slots: []ConnectionSlot,
    io_buffer_storage: []u8,
    run_state: std.atomic.Value(RunState),
    listener_mutex: std.atomic.Mutex,
    listener_handle: usize,
    bound_port: std.atomic.Value(u16),
    listener: ?std.Io.net.Server,
    connection_group: std.Io.Group,
    next_connection_slot: u32,
    stats: Stats,

    const Self = @This();

    pub const Config = struct {
        address: std.Io.net.IpAddress,
        dispatcher: handler.RequestDispatcher,
        max_connections: u32 = memory_budget.MemBudget.max_connections,
        buffer_size: u32 = 32 * 1024,
        worker_count: u16 = memory_budget.MemBudget.worker_count,
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
        if (!memory_budget.isStaticAllocatorInitialized()) {
            return error.StaticAllocatorNotInitialized;
        }
        if (!memory_budget.backingAllocatorMatches(allocator)) {
            return error.BackingAllocatorMismatch;
        }
        if (!http2.has_kqueue_backend) return error.StaticBackendUnavailable;
        const runtime_plan = try memory_budget.RuntimePlan.init(
            config.max_connections,
            config.buffer_size,
            config.worker_count,
        );
        _ = try runtime_plan.totalMemoryBytesForSlots(
            @sizeOf(ConnectionSlot),
            runtime_plan.io_buffer_bytes,
        );
        const startup_allocator = http2.staticAllocator();

        const io_buffer_storage = try startup_allocator.alloc(
            u8,
            runtime_plan.io_buffer_bytes,
        );
        errdefer startup_allocator.free(io_buffer_storage);

        const connection_slots = try startup_allocator.alloc(
            ConnectionSlot,
            @as(usize, @intCast(config.max_connections)),
        );
        errdefer startup_allocator.free(connection_slots);

        initConnectionSlots(connection_slots, io_buffer_storage, config.buffer_size);
        const backend = try Backend.init(startup_allocator, runtime_plan);

        return .{
            .startup_allocator = startup_allocator,
            .backend = backend,
            .config = config,
            .runtime_plan = runtime_plan,
            .connection_slots = connection_slots,
            .io_buffer_storage = io_buffer_storage,
            .run_state = .init(.stopped),
            .listener_mutex = .unlocked,
            .listener_handle = listener_handle_none,
            .bound_port = .init(0),
            .listener = null,
            .connection_group = .init,
            .next_connection_slot = 0,
            .stats = Stats.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.run_state.load(.acquire) != .stopped) {
            @panic("Server.deinit requires run() to return after stop()");
        }
        if (self.stats.active_connections.load(.acquire) != 0) {
            @panic("Server.deinit found active connection tasks");
        }
        if (self.listener != null) {
            @panic("Server.deinit found a live listener");
        }
        if (self.listener_handle != listener_handle_none) {
            @panic("Server.deinit found a published listener handle");
        }

        http2.beginDeinit();
        self.backend.deinit();
        self.startup_allocator.free(self.connection_slots);
        self.startup_allocator.free(self.io_buffer_storage);
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

        http2.freezeIfNeeded();
        const memory_at_runtime_start = memory_budget.allocatorSnapshot();
        try self.backend.attachCurrentThread();
        defer self.backend.detachCurrentThread();
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
                @panic("Server entered an invalid startup state");
            }
        } else {
            self.bound_port.store(self.listener.?.socket.address.getPort(), .release);
            logListening(self);
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
        while (self.run_state.load(.acquire) == .running) {
            var stream = self.listener.?.accept(io) catch |err| {
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

            setTcpNoDelay(stream.socket.handle);

            const connection_slot = self.acquireConnectionSlot() orelse {
                stream.close(io);
                continue;
            };

            self.spawnConnectionTask(io, stream, connection_slot) catch |err| {
                stream.close(io);
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
        const raw_handle = self.unpublishListenerHandle();
        if (self.listener) |*listener| {
            if (raw_handle != @as(usize, @intCast(listener.socket.handle))) {
                @panic("Server listener handle changed while published");
            }
            listener.deinit(io);
        } else {
            @panic("Server lost its published listener");
        }
        self.listener = null;
        self.backend.clearMainCancellation();
        self.bound_port.store(0, .release);
    }

    fn publishListenerHandle(self: *Self, raw_handle: usize) void {
        self.lockListener();
        defer self.listener_mutex.unlock();
        if (self.listener_handle != listener_handle_none) {
            @panic("Server listener published twice");
        }
        self.listener_handle = raw_handle;
    }

    fn unpublishListenerHandle(self: *Self) usize {
        self.lockListener();
        defer self.listener_mutex.unlock();
        if (self.listener_handle == listener_handle_none) {
            @panic("Server lost its published listener handle");
        }
        const raw_handle = self.listener_handle;
        self.listener_handle = listener_handle_none;
        return raw_handle;
    }

    fn lockListener(self: *Self) void {
        while (!self.listener_mutex.tryLock()) std.Thread.yield() catch {};
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

test "stop requested during startup is retained" {
    var run_state: std.atomic.Value(RunState) = .init(.starting);

    try std.testing.expect(requestStop(&run_state));
    try std.testing.expectEqual(.stopping, run_state.load(.acquire));
    try std.testing.expect(requestStop(&run_state));

    run_state.store(.stopped, .release);
    try std.testing.expect(!requestStop(&run_state));
}

comptime {
    if (@sizeOf(Connection.StreamStorage) > memory_budget.MemBudget.stream_storage_bytes) {
        @compileError("StreamStorage exceeds its static memory budget");
    }
    if (@sizeOf(Server.ConnectionSlot) > memory_budget.MemBudget.connection_slot_bytes) {
        @compileError("ConnectionSlot exceeds its static memory budget");
    }
    if (http2.has_kqueue_backend and
        Kqueue.fiber_allocation_size > memory_budget.MemBudget.event_loop_fiber_bytes_max)
    {
        @compileError("Kqueue fiber exceeds its static memory budget");
    }
    if (http2.has_kqueue_backend and
        Kqueue.worker_stack_reservation_bytes_max >
            memory_budget.MemBudget.worker_stack_reservation_bytes_max)
    {
        @compileError("Kqueue worker stack exceeds its static memory budget");
    }
    if (http2.has_kqueue_backend and
        Kqueue.wait_registration_bytes_max >
            memory_budget.MemBudget.wait_registration_bytes_max)
    {
        @compileError("Kqueue wait registration exceeds its static memory budget");
    }
    if (http2.has_kqueue_backend and
        Kqueue.wait_map_fixed_bytes_max > memory_budget.MemBudget.wait_map_fixed_bytes_max)
    {
        @compileError("Kqueue wait map exceeds its static memory budget");
    }
}

fn assertRuntimeMemoryUnchanged(start: memory_budget.AllocatorSnapshot) void {
    const finish = memory_budget.allocatorSnapshot();
    if (finish.allocations_live != start.allocations_live) {
        @panic("HTTP/2 runtime changed the static allocation count");
    }
    if (finish.bytes_live != start.bytes_live) {
        @panic("HTTP/2 runtime changed the static byte count");
    }
    if (finish.bytes_reserved != start.bytes_reserved) {
        @panic("HTTP/2 runtime changed the reserved byte count");
    }
    if (finish.state != .static) {
        @panic("HTTP/2 runtime left the static allocation phase");
    }
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
        const read_buffer_end = io_buffer_offset + buffer_size_bytes;
        const read_buffer = io_buffer_storage[io_buffer_offset..read_buffer_end];
        io_buffer_offset += buffer_size_bytes;

        const write_buffer_end = io_buffer_offset + buffer_size_bytes;
        const write_buffer = io_buffer_storage[io_buffer_offset..write_buffer_end];
        io_buffer_offset += buffer_size_bytes;

        connection_slot.* = .{
            .in_use = .init(false),
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
            .stream_storage = undefined,
        };
        connection_slot.stream_storage.init();
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

fn runAndStopServer(server: *Server) !void {
    var run_context = ServerRunContext{ .server = server };
    const server_thread = try std.Thread.spawn(.{}, ServerRunContext.run, .{&run_context});
    var server_thread_joined = false;
    defer if (!server_thread_joined) {
        server.stop();
        server_thread.join();
    };

    _ = try waitForServerPort(server);
    server.stop();
    server_thread.join();
    server_thread_joined = true;

    try std.testing.expect(run_context.err == null);
    try std.testing.expectEqual(@as(u16, 0), server.listeningPort());
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

    try http2.init(allocator);
    defer http2.deinit();

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .dispatcher = handler.RequestDispatcher.fromHandler(testRequestHandler),
        .max_connections = 2,
    });
    defer server.deinit();

    const stats = server.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.total_connections);
    try std.testing.expectEqual(@as(u32, 0), stats.active_connections);
    try std.testing.expectEqual(@as(u64, 0), stats.requests_processed);
}

test "connection slots reject excess work and reuse released capacity" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try http2.init(allocator);
    defer http2.deinit();

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .dispatcher = handler.RequestDispatcher.fromHandler(testRequestHandler),
        .max_connections = 2,
    });
    defer server.deinit();

    const first = server.acquireConnectionSlot().?;
    const second = server.acquireConnectionSlot().?;
    try std.testing.expect(server.acquireConnectionSlot() == null);

    server.releaseConnectionSlot(first);
    const reused = server.acquireConnectionSlot().?;
    try std.testing.expect(reused == first);

    server.releaseConnectionSlot(reused);
    server.releaseConnectionSlot(second);
    try std.testing.expectEqual(@as(u32, 0), server.getStats().active_connections);
}

test "server listener can stop and restart without stale cancellation" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try http2.init(allocator);
    defer http2.deinit();

    var server = try Server.init(allocator, .{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 0),
        .dispatcher = handler.RequestDispatcher.fromHandler(testRequestHandler),
        .max_connections = 2,
    });
    defer server.deinit();

    try runAndStopServer(&server);
    try runAndStopServer(&server);
}

test "stop cancels idle async connections" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try http2.init(allocator);
    defer http2.deinit();

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
