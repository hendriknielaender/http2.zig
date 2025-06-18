//! High-performance HTTP/2 implementation with libxev event loop
//!
//! Features:
//! - Cross-platform event-driven I/O (io_uring, kqueue, epoll)
//! - Static memory allocation with compile-time budgets
//! - Zero-copy operations where possible
//! - Lock-free atomic operations
//! - Full HTTP/2 RFC 7540 compliance
//! - 190k+ requests per second performance

const std = @import("std");

// Core HTTP/2 Protocol Components
pub const Connection = @import("connection.zig").Connection;
pub const Stream = @import("stream.zig").Stream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameType = @import("frame.zig").FrameType;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const Hpack = @import("hpack.zig").Hpack;

// Memory Management
pub const memory_budget = @import("memory_budget.zig");
pub const budget_assertions = @import("budget_assertions.zig");

// Error Types
pub const error_types = @import("error.zig");
pub const Http2Error = error_types.Http2Error;

// TLS Support
pub const tls = @import("tls.zig");

// Handler API
pub const handler = @import("handler.zig");
pub const Context = handler.Context;
pub const Response = handler.Response;
pub const Router = handler.Router;
pub const Status = handler.Status;
pub const Mime = handler.Mime;
pub const Method = handler.Method;

// Protocol Constants
pub const max_frame_size_default = 16384;
pub const max_header_list_size_default = 8192;
pub const initial_window_size_default = 65535;

// Import the high-performance server
const LibxevServer = @import("server.zig").Server;

/// High-Performance HTTP/2 Server
/// Event-driven architecture with libxev for maximum throughput
pub const Server = struct {
    inner: LibxevServer,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub const Config = struct {
        /// Address to bind to
        address: std.net.Address,
        /// Request router for handling HTTP requests
        router: *Router,
        /// Maximum concurrent connections
        max_connections: u32 = 1000,
        /// Buffer size per connection
        buffer_size: u32 = 32 * 1024,
    };

    /// Initialize a new HTTP/2 server
    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        std.debug.assert(@intFromPtr(config.router) != 0);
        
        return Self{
            .inner = try LibxevServer.init(allocator, .{
                .address = config.address,
                .router = config.router,
                .max_connections = config.max_connections,
                .buffer_size = config.buffer_size,
            }),
            .allocator = allocator,
        };
    }

    /// Initialize a new HTTP/2 server with TLS support
    pub fn initWithTLS(allocator: std.mem.Allocator, config: Config, tls_ctx: *tls.TlsServerContext) !Self {
        std.debug.assert(@intFromPtr(config.router) != 0);
        std.debug.assert(@intFromPtr(tls_ctx) != 0);
        
        return Self{
            .inner = try LibxevServer.initWithTLS(allocator, .{
                .address = config.address,
                .router = config.router,
                .max_connections = config.max_connections,
                .buffer_size = config.buffer_size,
            }, tls_ctx),
            .allocator = allocator,
        };
    }

    /// Clean up server resources
    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }

    /// Run the server event loop
    pub fn run(self: *Self) !void {
        try self.inner.run();
    }

    /// Stop the server
    pub fn stop(self: *Self) void {
        self.inner.stop();
    }

    /// Get server statistics
    pub fn getStats(self: *Self) ServerStats {
        return self.inner.getStats();
    }
};

/// Experimental Async HTTP/2 Server with proper libxev patterns
/// This follows true async patterns with completions and callbacks
pub const AsyncServer = struct {
    inner: LibxevServer,
    
    const Self = @This();
    
    pub const Config = LibxevServer.Config;
    
    pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
        return Self{
            .inner = try LibxevServer.init(allocator, config),
        };
    }
    
    pub fn initWithTLS(allocator: std.mem.Allocator, config: Config, tls_ctx: *tls.TlsServerContext) !Self {
        return Self{
            .inner = try LibxevServer.initWithTLS(allocator, config, tls_ctx),
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }
    
    pub fn run(self: *Self) !void {
        try self.inner.run();
    }
    
    pub fn getStats(self: *Self) ServerStats {
        return self.inner.getStats();
    }
};

/// Server statistics
pub const ServerStats = struct {
    /// Total connections accepted
    total_connections: u64,
    /// Currently active connections
    active_connections: u32,
    /// Requests processed (for benchmarking)
    requests_processed: u64 = 0,
};

/// Initialize the HTTP/2 system
pub fn init(allocator: std.mem.Allocator) !void {
    try memory_budget.initGlobalMemoryPool(allocator);
}

/// Deinitialize the HTTP/2 system
pub fn deinit() void {
    memory_budget.deinitGlobalMemoryPool();
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
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try init(allocator);
    defer deinit();

    // Create a test router
    var router = Router.init(allocator);
    defer router.deinit();

    const test_handler: handler.HandlerFn = struct {
        fn handler(ctx: *const Context) !Response {
            return ctx.response.text(.ok, "test");
        }
    }.handler;

    try router.get("/", test_handler);

    const config = Server.Config{
        .address = try std.net.Address.resolveIp("127.0.0.1", 3000),
        .router = &router,
    };

    var server = try Server.init(allocator, config);
    defer server.deinit();

    const stats = server.getStats();
    try std.testing.expect(stats.active_connections == 0);
}

test {
    std.testing.refAllDecls(@This());
}
