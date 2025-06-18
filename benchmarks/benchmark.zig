const std = @import("std");
const http2 = @import("http2");

/// Simple Hello World handler for benchmarking
fn helloHandler(ctx: *const http2.Context) !http2.Response {
    return ctx.response.text(.ok, "Hello, World!");
}

/// High-performance HTTP/2 over HTTPS benchmark server
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize http2 system
    try http2.init(allocator);
    defer http2.deinit();

    // Get port and TLS mode from environment
    const port_env = std.posix.getenv("PORT");
    const tls_env = std.posix.getenv("TLS");
    const use_tls = if (tls_env) |env_val| std.mem.eql(u8, env_val, "1") or std.mem.eql(u8, env_val, "true") else true;
    
    const port: u16 = if (port_env) |env_val|
        std.fmt.parseInt(u16, env_val, 10) catch (if (use_tls) @as(u16, 8443) else @as(u16, 3000))
    else
        (if (use_tls) @as(u16, 8443) else @as(u16, 3000));

    // Set up simple router for benchmarking
    var router = http2.Router.init(allocator);
    defer router.deinit();
    
    try router.get("/", helloHandler);

    // Configure server for benchmarking with high concurrency
    const config = http2.Server.Config{
        .address = try std.net.Address.resolveIp("127.0.0.1", port),
        .router = &router,
        .max_connections = 100, // Reduced concurrency to avoid libxev completion reuse issues
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
        std.log.info("HTTP/2 over HTTPS benchmark server ready on port {}", .{port});
        std.log.info("TLS with ALPN h2 negotiation enabled for performance testing", .{});
    } else {
        std.log.info("HTTP/2 benchmark server ready on port {}", .{port});
    }
    std.log.info("Event-driven architecture with libxev (cross-platform)", .{});

    // Create a context for the monitor thread
    const MonitorContext = struct {
        server: *http2.Server,
        ready: std.atomic.Value(bool),
    };
    
    var monitor_ctx = MonitorContext{
        .server = &server,
        .ready = std.atomic.Value(bool).init(false),
    };
    
    // Start performance monitoring with synchronization
    const monitor_thread = try std.Thread.spawn(.{}, monitorPerformance, .{&monitor_ctx});
    defer monitor_thread.join();
    
    // Signal that server is ready before running
    monitor_ctx.ready.store(true, .release);
    try server.run();
}

fn monitorPerformance(ctx: *const anyopaque) void {
    const MonitorContext = struct {
        server: *http2.Server,
        ready: std.atomic.Value(bool),
    };
    
    const monitor_ctx = @as(*MonitorContext, @ptrCast(@alignCast(@constCast(ctx))));
    
    // Wait for server to be ready
    while (!monitor_ctx.ready.load(.acquire)) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }
    
    var last_total: u64 = 0;
    var last_requests: u64 = 0;
    var last_time = std.time.milliTimestamp();
    var peak_rps: u64 = 0;
    var peak_conn_rps: u64 = 0;

    while (true) {
        std.time.sleep(2 * std.time.ns_per_s);
        
        const stats = monitor_ctx.server.getStats();
        const current_time = std.time.milliTimestamp();
        const time_diff_ms = current_time - last_time;
        
        if (time_diff_ms > 0) {
            const conn_diff = stats.total_connections - last_total;
            const req_diff = stats.requests_processed - last_requests;
            
            const conn_rps = (conn_diff * 1000) / @as(u64, @intCast(time_diff_ms));
            const req_rps = (req_diff * 1000) / @as(u64, @intCast(time_diff_ms));
            
            if (conn_rps > peak_conn_rps) peak_conn_rps = conn_rps;
            if (req_rps > peak_rps) peak_rps = req_rps;

            std.log.info("[HTTP/2] {} active | {} req/s ({} conn/s) | {} total reqs | Peak: {} req/s", .{
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