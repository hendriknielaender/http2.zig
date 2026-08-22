const std = @import("std");
const http2 = @import("http2");
const tls_server = @import("tls-server");
const log = std.log.scoped(.benchmark);

pub const std_options: std.Options = .{
    .log_level = .warn,
};

/// Simple request dispatcher for benchmarking.
fn benchmarkHandler(ctx: *const http2.Context) !http2.Response {
    if (ctx.method == .get) {
        if (std.mem.eql(u8, ctx.path, "/")) {
            return ctx.response.text(.ok, "Hello, World!");
        }
        if (std.mem.startsWith(u8, ctx.path, "/baseline2")) {
            return baseline2Handler(ctx);
        }
    }

    return ctx.response.text(.not_found, "Not Found");
}

/// HttpArena baseline-h2 contract: GET /baseline2?a=<i64>&b=<i64> -> sum.
fn baseline2Handler(ctx: *const http2.Context) !http2.Response {
    var a: i64 = 0;
    var b: i64 = 0;

    var query_iter = std.mem.splitScalar(u8, ctx.query, '&');
    while (query_iter.next()) |param| {
        if (param.len < 3) {
            continue;
        }
        if (param[1] != '=') {
            continue;
        }

        const value = std.fmt.parseInt(i64, param[2..], 10) catch 0;
        switch (param[0]) {
            'a' => a = value,
            'b' => b = value,
            else => {},
        }
    }

    const written = try std.fmt.bufPrint(ctx.response_body_buffer, "{d}", .{a + b});
    return ctx.response.text(.ok, written);
}

/// Listen port, from `PORT` when set.
fn resolvePort() u16 {
    const port_env = if (std.c.getenv("PORT")) |value| std.mem.span(value) else null;
    const env_val = port_env orelse return 8443;
    return std.fmt.parseInt(u16, env_val, 10) catch 8443;
}

/// Sizes the event loop to the machine, as the pre-static-allocation build
/// did, bounded by the static worker ceiling.
fn resolveWorkerCount() u16 {
    const cpu_count = std.Thread.getCpuCount() catch 1;
    return @intCast(@min(@max(cpu_count, 1), http2.MemBudget.worker_count_max));
}

/// High-performance HTTP/2 over TLS benchmark server.
pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    // Open the startup allocation phase.
    try http2.init(allocator);
    defer http2.deinit();

    const port = resolvePort();
    const worker_count = resolveWorkerCount();

    // Bound every HTTP/2 resource before the runtime phase.
    const config = tls_server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", port),
        .dispatcher = http2.RequestDispatcher.fromHandlerWithoutHeaders(benchmarkHandler),
        .max_connections = http2.memory_budget.MemBudget.max_connections,
        .worker_count = worker_count,
    };

    var server = try tls_server.Server.init(allocator, config);
    defer server.deinit();

    log.info("HTTP/2 over TLS benchmark server ready on port {}", .{port});
    log.info("BoringSSL TLS is provided by http2-boring", .{});

    // The monitor thread is a startup resource and must exist before freeze.
    const MonitorContext = struct {
        server: *tls_server.Server,
        initialized: std.atomic.Value(bool),
        ready: std.atomic.Value(bool),
        running: std.atomic.Value(bool),
    };

    var monitor_ctx = MonitorContext{
        .server = &server,
        .initialized = std.atomic.Value(bool).init(false),
        .ready = std.atomic.Value(bool).init(false),
        .running = std.atomic.Value(bool).init(true),
    };

    // Start performance monitoring with synchronization.
    const monitor_thread = try std.Thread.spawn(.{}, monitorPerformance, .{&monitor_ctx});
    defer {
        monitor_ctx.running.store(false, .release);
        monitor_thread.join();
    }

    while (!monitor_ctx.initialized.load(.acquire)) {
        std.Thread.yield() catch {};
    }

    // All Zig-owned server pools, backend workers, and support threads now exist.
    http2.freeze();

    // Signal that the monitor may inspect the live server.
    monitor_ctx.ready.store(true, .release);
    server.run() catch |err| {
        log.err("Benchmark server failed: {}", .{err});
        return err;
    };
}

fn monitorPerformance(ctx: *const anyopaque) void {
    const MonitorContext = struct {
        server: *tls_server.Server,
        initialized: std.atomic.Value(bool),
        ready: std.atomic.Value(bool),
        running: std.atomic.Value(bool),
    };

    const monitor_ctx = @as(*MonitorContext, @ptrCast(@alignCast(@constCast(ctx))));
    const io = std.Io.Threaded.global_single_threaded.io();
    monitor_ctx.initialized.store(true, .release);

    // Wait for server to be ready
    while (!monitor_ctx.ready.load(.acquire)) {
        sleepFor(10 * std.time.ns_per_ms);
    }

    var last_total: u64 = 0;
    var last_requests: u64 = 0;
    var last_time = std.Io.Clock.Timestamp.now(io, .awake);
    var peak_rps: u64 = 0;
    var peak_conn_rps: u64 = 0;

    while (monitor_ctx.running.load(.acquire)) {
        sleepFor(2 * std.time.ns_per_s);

        const stats = monitor_ctx.server.getStats();
        const current_time = std.Io.Clock.Timestamp.now(io, .awake);
        const time_diff_ms = last_time.durationTo(current_time).raw.toMilliseconds();

        if (time_diff_ms > 0) {
            const conn_diff = stats.total_connections - last_total;
            const req_diff = stats.requests_processed - last_requests;

            const conn_rps = (conn_diff * 1000) / @as(u64, @intCast(time_diff_ms));
            const req_rps = (req_diff * 1000) / @as(u64, @intCast(time_diff_ms));

            if (conn_rps > peak_conn_rps) peak_conn_rps = conn_rps;
            if (req_rps > peak_rps) peak_rps = req_rps;

            log.info(
                "[HTTP/2] {} active | {} req/s ({} conn/s) | " ++
                    "{} total reqs | Peak: {} req/s",
                .{
                    stats.active_connections,
                    req_rps,
                    conn_rps,
                    stats.requests_processed,
                    peak_rps,
                },
            );

            last_total = stats.total_connections;
            last_requests = stats.requests_processed;
            last_time = current_time;
        }
    }
}

fn sleepFor(duration_ns: u64) void {
    const io = std.Io.Threaded.global_single_threaded.io();
    io.sleep(.fromNanoseconds(duration_ns), .awake) catch unreachable;
}
