const std = @import("std");
const boring = @import("boring");
const http2 = @import("http2");
const http2_boring = @import("http2-boring");

const log = std.log.scoped(.tls_server);

pub const Config = struct {
    address: std.Io.net.IpAddress,
    dispatcher: http2.RequestDispatcher,
    cert_file: [:0]const u8 = "cert.pem",
    key_file: [:0]const u8 = "key.pem",
    max_connections: u32 = 1000,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    backend: Backend,
    config: Config,
    acceptor: http2_boring.Acceptor,
    connection_slots: []ConnectionSlot,
    connection_group: std.Io.Group,
    running: std.atomic.Value(bool),
    bound_port: std.atomic.Value(u16),
    next_connection_slot: u32,
    stats: Stats,

    const Self = @This();

    const Backend = if (http2.has_kqueue_backend) struct {
        allocator: std.mem.Allocator,
        evented: ?*http2.Kqueue,

        fn init(allocator: std.mem.Allocator) Backend {
            return .{
                .allocator = allocator,
                .evented = null,
            };
        }

        fn start(self: *Backend) !void {
            std.debug.assert(self.evented == null);

            const evented = try self.allocator.create(http2.Kqueue);
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
        stream_storage: http2.Connection.StreamStorage = undefined,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        std.debug.assert(config.max_connections > 0);
        std.debug.assert(config.max_connections <= 10000);

        boring.init();

        var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
        defer builder.deinit();

        try builder.setCertificateChainFile(config.cert_file);
        try builder.setPrivateKeyFile(config.key_file, .pem);
        try builder.checkPrivateKey();

        var acceptor = http2_boring.Acceptor.initWithBuilder(&builder);
        errdefer acceptor.deinit();

        const connection_slots = try allocator.alloc(
            ConnectionSlot,
            @as(usize, @intCast(config.max_connections)),
        );
        errdefer allocator.free(connection_slots);

        initConnectionSlots(connection_slots);

        return .{
            .allocator = allocator,
            .backend = Backend.init(allocator),
            .config = config,
            .acceptor = acceptor,
            .connection_slots = connection_slots,
            .connection_group = .init,
            .running = .init(false),
            .bound_port = .init(0),
            .next_connection_slot = 0,
            .stats = Stats.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        self.backend.deinit();
        self.allocator.free(self.connection_slots);
        self.acceptor.deinit();
    }

    pub fn run(self: *Self) !void {
        try self.backend.start();
        defer self.backend.deinit();

        const io = self.backend.io();

        var listener = try self.config.address.listen(io, .{
            .kernel_backlog = 4096,
            .reuse_address = true,
            .mode = .stream,
            .protocol = .tcp,
        });
        defer listener.deinit(io);
        defer self.connection_group.cancel(io);

        self.bound_port.store(listener.socket.address.getPort(), .release);
        self.running.store(true, .release);
        defer {
            self.running.store(false, .release);
            self.bound_port.store(0, .release);
        }

        log.info("HTTP/2 TLS listening on {f}", .{listener.socket.address});

        while (self.running.load(.acquire)) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.ConnectionAborted => continue,
                error.SocketNotListening => break,
                error.Canceled => break,
                else => return err,
            };

            const connection_slot = self.acquireConnectionSlot() orelse {
                var stream_copy = stream;
                stream_copy.close(io);
                continue;
            };

            self.connection_group.concurrent(io, serveConnectionTask, .{
                self,
                stream,
                connection_slot,
            }) catch |err| {
                var stream_copy = stream;
                stream_copy.close(io);
                self.releaseConnectionSlot(connection_slot);
                return err;
            };
        }
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

        var connection: http2_boring.Connection = .{};
        defer connection.deinit(io);

        server.acceptor.accept(&connection, io, stream) catch |err| {
            logConnectionError(err);
            return;
        };

        var completed_responses: u32 = 0;
        defer server.recordCompletedResponses(completed_responses);

        _ = http2.serveConnection(
            server.allocator,
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

fn initConnectionSlots(connection_slots: []Server.ConnectionSlot) void {
    std.debug.assert(connection_slots.len > 0);

    for (connection_slots) |*connection_slot| {
        connection_slot.* = .{
            .in_use = .init(false),
        };
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
