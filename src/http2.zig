//! High-performance HTTP/2 implementation with Zig's native I/O backends.
//!
//! Features:
//! - Cross-platform async I/O via Zig `std.Io` backends
//! - Static memory allocation with compile-time budgets
//! - Zero-copy operations where possible
//! - Lock-free atomic operations
//! - Full HTTP/2 RFC 7540 compliance
//! - 190k+ requests per second performance

const std = @import("std");
const builtin = @import("builtin");

// Local fork of `std.Io.Kqueue` (see `src/io/Kqueue.zig`). Re-exported so
// out-of-tree modules (e.g. `examples/tls_server.zig`) consume the same
// patched backend as the in-tree HTTP/2 server.
pub const has_kqueue_backend = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

pub const Kqueue = if (has_kqueue_backend) @import("io/Kqueue.zig") else opaque {};

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

// Handler API
pub const handler = @import("handler.zig");
pub const Context = handler.Context;
pub const Response = handler.Response;
pub const RequestDispatcher = handler.RequestDispatcher;
pub const Status = handler.Status;
pub const Mime = handler.Mime;
pub const Method = handler.Method;

// Protocol Constants
pub const max_frame_size_default = 16384;
pub const max_header_list_size_default = 8192;
pub const initial_window_size_default = 65535;

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

/// Initialize the HTTP/2 system.
/// Wraps the caller's allocator in a phase-gated StaticAllocator so that
/// all heap work can be frozen before the event loop starts.
pub fn init(allocator: std.mem.Allocator) !void {
    try memory_budget.initStaticAllocator(allocator);
}

/// Return the phase-gated allocator.  All server init should use this so that
/// `freeze()` can prevent accidental runtime allocations.
pub fn staticAllocator() std.mem.Allocator {
    return memory_budget.staticAllocatorPtr().allocator();
}

/// Freeze allocations.  Any alloc/resize after this will assert-fail.
pub fn freeze() void {
    memory_budget.freezeStaticAllocator();
}

/// Deinitialize the HTTP/2 system.  Unfreezes the allocator and frees all
/// tracked memory.
pub fn deinit() void {
    memory_budget.deinitStaticAllocator();
}

// Compile-time validation and assertions for design integrity
comptime {
    budget_assertions.validateAll();

    // Assert HTTP/2 protocol constant relationships
    std.debug.assert(max_frame_size_default >= 16384); // RFC 7540 minimum
    std.debug.assert(max_frame_size_default <= 16777215); // RFC 7540 maximum
    std.debug.assert(initial_window_size_default >= 0);
    std.debug.assert(initial_window_size_default <= 2147483647); // RFC 7540 maximum
    std.debug.assert(max_header_list_size_default > 0);

    // Assert memory layout assumptions
    std.debug.assert(@sizeOf(ServerStats) <= 32); // Keep stats structure compact
    std.debug.assert(@alignOf(ServerStats) >= 8); // Ensure proper alignment
}

test "HTTP/2 server creation" {
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
    };

    var server = try Server.init(allocator, config);
    defer server.deinit();

    const stats = server.getStats();
    try std.testing.expect(stats.active_connections == 0);
}

test {
    std.testing.refAllDecls(@This());
}
