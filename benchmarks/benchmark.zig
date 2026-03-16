const std = @import("std");
const http2 = @import("http2");
const log = std.log.scoped(.benchmark);

pub const std_options: std.Options = .{
    .log_level = .warn,
};

/// Simple Hello World handler for benchmarking
fn helloHandler(ctx: *const http2.Context) !http2.Response {
    return ctx.response.text(.ok, "Hello, World!");
}

/// High-performance HTTP/2 over HTTPS benchmark server
pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize http2 system
    try http2.init(allocator);
    defer http2.deinit();

    // Get port and TLS mode from environment
    const port_env = if (std.c.getenv("PORT")) |value| std.mem.span(value) else null;
    const tls_env = if (std.c.getenv("TLS")) |value| std.mem.span(value) else null;
    const use_tls = if (tls_env) |env_val|
        std.mem.eql(u8, env_val, "1") or std.mem.eql(u8, env_val, "true")
    else
        true;

    const port: u16 = if (port_env) |env_val|
        std.fmt.parseInt(u16, env_val, 10) catch
            (if (use_tls) @as(u16, 8443) else @as(u16, 3000))
    else
        (if (use_tls) @as(u16, 8443) else @as(u16, 3000));

    // Set up simple router for benchmarking
    var router = http2.Router.init(allocator);
    defer router.deinit();

    try router.get("/", helloHandler);

    // Configure server for benchmarking with high concurrency
    const config = http2.Server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", port),
        .router = &router,
        .max_connections = http2.memory_budget.MemBudget.max_conns,
        .buffer_size = 32 * 1024,
    };

    // Initialize TLS context if needed
    var tls_ctx: ?http2.tls.TlsServerContext = if (use_tls)
        try http2.tls.TlsServerContext.init(allocator, "cert.pem", "key.pem")
    else
        null;
    defer if (tls_ctx) |*ctx| ctx.deinit();

    var server = if (use_tls and tls_ctx != null)
        try http2.Server.initWithTLS(allocator, config, &tls_ctx.?)
    else
        try http2.Server.init(allocator, config);

    defer server.deinit();

    if (use_tls) {
        log.info("HTTP/2 over HTTPS benchmark server ready on port {}", .{port});
        log.info("TLS with ALPN h2 negotiation enabled for performance testing", .{});
    } else {
        log.info("HTTP/2 benchmark server ready on port {}", .{port});
    }
    log.info("Event-driven architecture with Zig std.Io backend", .{});

    // Create a context for the monitor thread
    const MonitorContext = struct {
        server: *http2.Server,
        ready: std.atomic.Value(bool),
        running: std.atomic.Value(bool),
    };

    var monitor_ctx = MonitorContext{
        .server = &server,
        .ready = std.atomic.Value(bool).init(false),
        .running = std.atomic.Value(bool).init(true),
    };

    // Start performance monitoring with synchronization
    const monitor_thread = try std.Thread.spawn(.{}, monitorPerformance, .{&monitor_ctx});
    defer {
        monitor_ctx.running.store(false, .release);
        monitor_thread.join();
    }

    // Signal that server is ready before running
    monitor_ctx.ready.store(true, .release);
    server.run() catch |err| {
        log.err("Benchmark server failed: {}", .{err});
        return err;
    };
}

fn monitorPerformance(ctx: *const anyopaque) void {
    const MonitorContext = struct {
        server: *http2.Server,
        ready: std.atomic.Value(bool),
        running: std.atomic.Value(bool),
    };

    const monitor_ctx = @as(*MonitorContext, @ptrCast(@alignCast(@constCast(ctx))));
    const io = std.Io.Threaded.global_single_threaded.io();

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

            log.info("[HTTP/2] {} active | {} req/s ({} conn/s) | {} total reqs | Peak: {} req/s", .{
                stats.active_connections,
                req_rps,
                conn_rps,
                stats.requests_processed,
                peak_rps,
            });

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
