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
    threaded: std.Io.Threaded,
    config: Config,
    acceptor: http2_boring.Acceptor,
    connection_group: std.Io.Group,
    running: std.atomic.Value(bool),
    bound_port: std.atomic.Value(u16),
    stats: Stats,

    const Self = @This();

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

    const ConnectionTask = struct {
        server: *Self,
        stream: std.Io.net.Stream,
        stream_storage: http2.Connection.StreamStorage = undefined,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        std.debug.assert(config.max_connections > 0);

        boring.init();

        var threaded = std.Io.Threaded.init(allocator, .{
            .argv0 = .empty,
            .environ = .empty,
        });
        errdefer threaded.deinit();

        var builder = try boring.ssl.ContextBuilder.init(boring.ssl.Method.tls());
        defer builder.deinit();

        try builder.setCertificateChainFile(config.cert_file);
        try builder.setPrivateKeyFile(config.key_file, .pem);
        try builder.checkPrivateKey();

        var acceptor = http2_boring.Acceptor.initWithBuilder(&builder);
        errdefer acceptor.deinit();

        return .{
            .allocator = allocator,
            .threaded = threaded,
            .config = config,
            .acceptor = acceptor,
            .connection_group = .init,
            .running = .init(false),
            .bound_port = .init(0),
            .stats = Stats.init(),
        };
    }

    pub fn deinit(self: *Self) void {
        self.acceptor.deinit();
        self.threaded.deinit();
    }

    pub fn run(self: *Self) !void {
        const io = self.threaded.io();

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

            if (!self.reserveConnectionSlot()) {
                var stream_copy = stream;
                stream_copy.close(io);
                continue;
            }

            const task = self.allocator.create(ConnectionTask) catch |err| {
                var stream_copy = stream;
                stream_copy.close(io);
                self.releaseConnectionSlot();
                return err;
            };
            task.* = .{
                .server = self,
                .stream = stream,
            };

            self.connection_group.concurrent(io, serveConnectionTask, .{task}) catch |err| {
                var stream_copy = stream;
                stream_copy.close(io);
                self.releaseConnectionSlot();
                self.allocator.destroy(task);
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

    fn reserveConnectionSlot(self: *Self) bool {
        const previous_active = self.stats.active_connections.fetchAdd(1, .acq_rel);
        if (previous_active >= self.config.max_connections) {
            _ = self.stats.active_connections.fetchSub(1, .acq_rel);
            return false;
        }

        _ = self.stats.total_connections.fetchAdd(1, .acq_rel);
        return true;
    }

    fn releaseConnectionSlot(self: *Self) void {
        _ = self.stats.active_connections.fetchSub(1, .acq_rel);
    }

    fn recordCompletedResponses(self: *Self, completed_responses: u32) void {
        if (completed_responses == 0) return;
        _ = self.stats.requests_processed.fetchAdd(completed_responses, .acq_rel);
    }

    fn serveConnectionTask(task: *ConnectionTask) std.Io.Cancelable!void {
        const server = task.server;
        const io = server.threaded.io();

        defer {
            server.releaseConnectionSlot();
            server.allocator.destroy(task);
        }

        var connection: http2_boring.Connection = .{};
        defer connection.deinit(io);

        server.acceptor.accept(&connection, io, task.stream) catch |err| {
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
                .stream_storage = &task.stream_storage,
                .completed_responses_out = &completed_responses,
            },
        ) catch |err| {
            logConnectionError(err);
            return;
        };
    }
};

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
