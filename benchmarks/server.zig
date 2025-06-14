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
        
        // Submit connection to async worker pool  
        worker_pool.submitAsyncConnection(conn.stream.handle, true) catch |err| {
            std.debug.print("Failed to submit async connection: {s}\n", .{@errorName(err)});
            conn.stream.close();
            active_connections -= 1;
            continue;
        };
        
        std.debug.print("Submitted connection to async worker pool (active: {})\n", .{active_connections});
    }
}
pub const ConnectionContext = struct {
    http2_conn: *http2.Connection(std.io.AnyReader, std.io.AnyWriter),
    arena: std.heap.ArenaAllocator,
    active_connections: *u32,
};
