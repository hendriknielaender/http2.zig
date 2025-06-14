//! Async HTTP/2 Benchmark Server
//!
//! Proper async server implementation using libxev event loops

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
    
    std.debug.print("Starting async HTTP/2 benchmark server on port {}...\n", .{port});
    try runAsyncServer(allocator, port);
}

fn runAsyncServer(allocator: std.mem.Allocator, port: u16) !void {
    // Initialize memory budget system
    try http2.memory_budget.initGlobalMemoryPool(allocator);
    defer http2.memory_budget.deinitGlobalMemoryPool();
    
    var memory_pool = try http2.memory_budget.StaticMemoryPool.init(allocator);
    defer memory_pool.deinit();
    
    // For now, fall back to synchronous server with worker pool
    // until we can properly implement async socket acceptance
    var worker_pool = try http2.worker_pool.WorkerPool.init(allocator, &memory_pool);
    defer worker_pool.deinit();
    
    std.debug.print("Starting synchronous HTTP/2 server (async coming soon)\n", .{});
    
    // Set up network listener
    const address = try std.net.Address.resolveIp("127.0.0.1", port);
    var listener = try address.listen(.{
        .reuse_address = true,
        .reuse_port = true,
    });
    defer listener.deinit();
    
    std.debug.print("HTTP/2 benchmark server listening on 127.0.0.1:{}\n", .{port});
    
    var active_connections: u32 = 0;
    const max_connections: u32 = 1000;
    
    // Simple synchronous accept loop for now
    while (true) {
        const conn = listener.accept() catch |err| {
            std.debug.print("Accept failed: {s}\n", .{@errorName(err)});
            continue;
        };
        
        if (active_connections >= max_connections) {
            conn.stream.close();
            continue;
        }
        
        active_connections += 1;
        
        // Create a thread for each connection for now
        const thread = std.Thread.spawn(.{}, handleConnection, .{ allocator, conn.stream, &active_connections }) catch |err| {
            std.debug.print("Failed to spawn connection thread: {s}\n", .{@errorName(err)});
            conn.stream.close();
            active_connections -= 1;
            continue;
        };
        thread.detach();
    }
}

fn handleConnection(allocator: std.mem.Allocator, stream: std.net.Stream, active_connections: *u32) void {
    defer {
        stream.close();
        _ = @atomicRmw(u32, active_connections, .Sub, 1, .seq_cst);
    }
    
    var connection_arena = std.heap.ArenaAllocator.init(allocator);
    defer connection_arena.deinit();
    
    const connection_allocator = connection_arena.allocator();
    const reader = stream.reader().any();
    const writer = stream.writer().any();
    
    var http2_conn = http2.Connection(std.io.AnyReader, std.io.AnyWriter).init(
        connection_allocator,
        reader,
        writer,
        true
    ) catch |err| {
        std.debug.print("Connection init failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer http2_conn.deinit();
    
    http2_conn.handle_connection() catch |err| {
        // Expected errors for high-load testing
        switch (err) {
            error.BrokenPipe, error.ConnectionResetByPeer, error.UnexpectedEOF => return,
            error.InvalidPreface => return,
            else => std.debug.print("Connection error: {s}\n", .{@errorName(err)}),
        }
    };
}