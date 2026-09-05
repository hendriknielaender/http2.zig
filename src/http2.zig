//! High-performance HTTP/2 implementation with Zig's native I/O backends.
//!
//! Features:
//! - Cross-platform async I/O via Zig `std.Io` backends
//! - Static memory allocation with compile-time budgets
//! - Zero-copy operations where possible
//! - Lock-free atomic operations
//! - HTTP/2 per RFC 9113 (obsoletes RFC 7540), with RFC 9218 prioritization
//! - 190k+ requests per second performance

const std = @import("std");
const builtin = @import("builtin");
pub const protocol = @import("protocol.zig");

// Statically allocating event loop (see `src/io/EventLoop.zig`), derived from
// `std.Io.Kqueue` and reworked to preallocate fibers, worker stacks, and wait
// registrations before the freeze boundary. The native `std.Io` backends
// allocate a fiber per task at runtime, which a sealed allocator rejects.
// Re-exported so out-of-tree modules (e.g. `examples/tls_server.zig`) consume
// the same backend as the in-tree HTTP/2 server.
//
// Readiness polling is per platform: kqueue on the BSDs, epoll on Linux.
pub const has_event_loop_backend = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .linux => true,
    else => false,
};

pub const EventLoop = if (has_event_loop_backend) @import("io/EventLoop.zig") else opaque {};

// Core HTTP/2 Protocol Components
pub const Connection = @import("connection.zig").Connection;
pub const Stream = @import("stream.zig").Stream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameType = @import("frame.zig").FrameType;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const Hpack = @import("hpack.zig").Hpack;
pub const Priority = @import("http_priority.zig").Priority;

// Memory Management
pub const memory_budget = @import("memory_budget.zig");
pub const budget_assertions = @import("budget_assertions.zig");
pub const MemBudget = @import("memory_budget.zig").MemBudget;

// Error Types
pub const error_types = @import("error.zig");
pub const Http2Error = error_types.Http2Error;

// Transport integration
pub const transport = @import("transport.zig");
pub const ServeConnectionOptions = transport.ServeConnectionOptions;
pub const serveConnection = transport.serveConnection;

// Request-target path normalization.
pub const path = @import("path.zig");

// HTTP field-name and field-value validation (RFC 9113 § 8.2.1, § 8.3.1).
pub const field = @import("field.zig");

// Per-connection stream slot storage with O(1) lookup.
pub const stream_storage = @import("stream_storage.zig");

// Handler API
pub const handler = @import("handler.zig");
pub const Context = handler.Context;
pub const Response = handler.Response;
pub const StreamReadResult = handler.StreamReadResult;
pub const StreamResponseConfig = handler.StreamResponseConfig;
pub const RequestDispatcher = handler.RequestDispatcher;
pub const Status = handler.Status;
pub const Mime = handler.Mime;
pub const Method = handler.Method;

// Protocol Constants
pub const EndpointRole = protocol.EndpointRole;
pub const max_frame_size_default = protocol.frame_payload_size_default;
pub const max_header_list_size_default = 8192;
pub const initial_window_size_default = protocol.flow_control_window_size_default;

pub const Server = @import("server.zig").Server;

/// Server statistics
pub const ServerStats = struct {
    /// Total connections accepted
    total_connections: u64,
    /// Currently active connections
    active_connections: u32,
    /// Requests processed (for benchmarking)
    requests_processed: u64 = 0,
};

/// Begin the HTTP/2 startup phase.
///
/// Every server, client connection pool, and transport adapter must allocate
/// its bounded storage through `staticAllocator()` before `freeze()`.
pub fn init(allocator: std.mem.Allocator) !void {
    try memory_budget.initStaticAllocator(allocator);
}

/// Return the startup-only allocator.
pub fn staticAllocator() std.mem.Allocator {
    return memory_budget.staticAllocatorPtr().allocator();
}

/// Seal startup memory. Runtime allocation, resize, remap, and free operations
/// become unconditional safety failures in every optimization mode.
pub fn freeze() void {
    memory_budget.freezeStaticAllocator();
}

/// Seal startup memory if the application did not call `freeze()` explicitly.
/// Server run loops call this immediately before accepting traffic.
pub fn freezeIfNeeded() void {
    const snapshot = memory_budget.allocatorSnapshot();
    switch (snapshot.state) {
        .init => freeze(),
        .static => {},
        .deinit => @panic("HTTP/2 runtime started during teardown"),
    }
}

/// Enter teardown before any startup-owned pool is freed.
pub fn beginDeinit() void {
    memory_budget.beginStaticAllocatorDeinit();
}

/// Finish teardown after all startup-owned pools have been freed.
pub fn deinit() void {
    memory_budget.deinitStaticAllocator();
}

// Compile-time validation and assertions for design integrity
comptime {
    budget_assertions.validateAll();

    // Assert HTTP/2 protocol constant relationships
    std.debug.assert(max_frame_size_default >= protocol.frame_payload_size_default);
    std.debug.assert(max_frame_size_default <= protocol.frame_payload_size_max);
    std.debug.assert(initial_window_size_default >= 0);
    std.debug.assert(initial_window_size_default <= protocol.flow_control_window_size_max);
    std.debug.assert(max_header_list_size_default > 0);

    // Assert memory layout assumptions
    std.debug.assert(@sizeOf(ServerStats) <= 32); // Keep stats structure compact
    std.debug.assert(@alignOf(ServerStats) >= 8); // Ensure proper alignment
}

test "HTTP/2 server creation" {
    // The bundled server requires the static event-loop backend.
    if (!has_event_loop_backend) return error.SkipZigTest;
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try init(allocator);
    defer deinit();

    const test_handler: handler.HandlerFn = struct {
        fn handler(ctx: *const Context) !Response {
            return ctx.response.text(.ok, "test");
        }
    }.handler;

    const config = Server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 3000),
        .dispatcher = RequestDispatcher.fromHandler(test_handler),
        .max_connections = 2,
    };

    var server = try Server.init(allocator, config);
    defer server.deinit();

    const stats = server.getStats();
    try std.testing.expect(stats.active_connections == 0);
}

test {
    std.testing.refAllDecls(@This());
}
