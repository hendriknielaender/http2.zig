const std = @import("std");
const http2 = @import("http2");
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    // Read port from environment variable, default to 3000
    const port_str = std.process.getEnvVarOwned(allocator, "PORT") catch "3000";
    defer allocator.free(port_str);
    const port = std.fmt.parseInt(u16, port_str, 10) catch 3000;
    std.debug.print("Starting HTTP/2 benchmark server on port {}...\n", .{port});
    try runServer(allocator, port);
}
fn runServer(allocator: std.mem.Allocator, port: u16) !void {
    var memory_pool = try http2.memory_budget.StaticMemoryPool.init(allocator);
    defer memory_pool.deinit();
    var worker_pool = try http2.worker_pool.WorkerPool.init(allocator, &memory_pool);
    defer worker_pool.deinit();
    // Start the worker pool
    try worker_pool.start();
    defer worker_pool.stop();
    // Set up network listener
    const address = try std.net.Address.resolveIp("127.0.0.1", port);
    var listener = try address.listen(.{ 
        .reuse_address = true,
        .reuse_port = true,
    });
    defer listener.deinit();
    std.debug.print("HTTP/2 benchmark server listening on 127.0.0.1:{} with worker pool\n", .{port});
    var active_connections: u32 = 0;
    const max_connections: u32 = 512; // Reasonable limit to prevent memory exhaustion
    // Accept loop with bounded connection processing
    while (true) {
        const conn = listener.accept() catch |err| {
            std.debug.print("Accept failed: {any}\n", .{err});
            continue;
        };
        if (active_connections >= max_connections) {
            std.debug.print("Connection limit reached ({}), rejecting new connection\n", .{max_connections});
            conn.stream.close();
            continue;
        }
        active_connections += 1;
        const reader = conn.stream.reader().any();
        const writer = conn.stream.writer().any();
        // Use a limited-scope allocator to prevent memory growth
        var connection_arena = std.heap.ArenaAllocator.init(allocator);
        defer {
            connection_arena.deinit(); // Always clean up the arena
            active_connections -= 1;   // Always decrement counter
        }
        const connection_allocator = connection_arena.allocator();
        const http2_conn = connection_allocator.create(http2.Connection(std.io.AnyReader, std.io.AnyWriter)) catch |err| {
            std.debug.print("Failed to allocate connection: {any}\n", .{err});
            conn.stream.close();
            continue;
        };
        http2_conn.* = http2.Connection(std.io.AnyReader, std.io.AnyWriter).init(connection_allocator, reader, writer, true) catch |err| {
            std.debug.print("Connection init failed: {any}\n", .{err});
            conn.stream.close();
            continue;
        };
        // Process connection synchronously to ensure cleanup happens
        worker_pool.submitConnectionWork(http2_conn) catch |err| {
            std.debug.print("Failed to submit work to pool: {any}\n", .{err});
            http2_conn.deinit();
            conn.stream.close();
        };
    }
}
pub const ConnectionContext = struct {
    http2_conn: *http2.Connection(std.io.AnyReader, std.io.AnyWriter),
    arena: std.heap.ArenaAllocator,
    active_connections: *u32,
};