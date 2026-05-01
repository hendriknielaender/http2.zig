//! Compile-time memory budgeting that prevents runtime OOM by sizing every
//! allocation against worst-case calculations known before the server starts.
//!
//! The budget constants serve as the single source of truth for maximum
//! resource counts.  Every module that pre-allocates storage (connection
//! slots, stream buffers, header fragments) binds its array lengths to these
//! constants so that a budget change one place flows through the entire build.
//!
//! A phase-gated allocator (StaticAllocator) wraps the caller's allocator so
//! that all heap work happens during init and is frozen before the event loop
//! starts.  Any accidental runtime allocation triggers an assertion failure.
const std = @import("std");

pub const KiB = 1024;
pub const MiB = 1024 * KiB;
pub const GiB = 1024 * MiB;

/// Compile-time resource budget; every capacity choice lives here so that
/// a single edit propagates to every consumer without leaving any array
/// unbounded.
pub const MemBudget = struct {
    /// Maximum concurrent connections.  Must match `server.Config.max_connections`
    /// default so that budget calculations are coherent with deployed code.
    pub const max_connections = 1000;

    /// Maximum concurrent streams inside a single connection.
    /// RFC 7540 §5.1.1 notes the peer MAY advertise fewer via SETTINGS;
    /// this is the worst-case local reservation.
    pub const max_streams_per_connection = 100;

    /// Per-connection receive-window ceiling in bytes.
    pub const bytes_per_connection = 64 * KiB;

    /// Largest frame payload we accept (RFC 7540 §4.2 minimum is 16384).
    pub const max_frame_size_bytes = 16 * KiB;

    /// Maximum uncompressed header block size.  RFC 7540 §10.3 recommends
    /// at least 8KB capacity; HPACK dynamic-table entries may occupy this.
    pub const max_header_size_bytes = 8 * KiB;

    /// Per-stream data buffer (minimum 16KB per RFC 7540 §6.9.2).
    pub const max_data_buffer_bytes = 16 * KiB;

    /// Worker threads spun up for request processing.
    pub const worker_count = 2;

    /// Minimum stack allocation per worker thread.
    pub const stack_bytes_per_thread = 128 * KiB;

    // -----------------------------------------------------------------------
    //  Derived sizes – kept manually in sync with StreamInstance inline
    //  buffers so that the budget is always the ceiling.
    // -----------------------------------------------------------------------

    pub const stream_header_fragments_bytes = max_header_size_bytes;
    pub const stream_headers_storage_bytes = max_header_size_bytes;
    pub const stream_request_body_bytes = max_data_buffer_bytes;
    pub const stream_response_body_bytes = 256;
    pub const stream_headers_array_bytes = 64 * @sizeOf(struct { name: []const u8, value: []const u8 });
    pub const stream_metadata_bytes = 512;

    pub const stream_instance_bytes =
        stream_header_fragments_bytes +
        stream_headers_storage_bytes +
        stream_request_body_bytes +
        stream_response_body_bytes +
        stream_headers_array_bytes +
        stream_metadata_bytes;

    pub const stream_storage_lookup_bytes =
        256 * (@sizeOf(u32) + @sizeOf(u8)) +
        max_streams_per_connection * (@sizeOf(u32) + @sizeOf(bool));

    pub const stream_storage_bytes =
        max_streams_per_connection * stream_instance_bytes + stream_storage_lookup_bytes;

    pub const connection_slot_overhead_bytes = 64;
    pub const connection_slot_bytes = stream_storage_bytes + connection_slot_overhead_bytes;

    pub const server_overhead_bytes = 16 * KiB;

    pub const stream_memory_per_connection =
        max_streams_per_connection * stream_instance_bytes;

    pub const connection_memory_bytes = max_connections * connection_slot_bytes;
    pub const worker_memory_bytes = worker_count * stack_bytes_per_thread;
    pub const total_required_bytes = connection_memory_bytes +
        worker_memory_bytes + server_overhead_bytes;

    comptime {
        const system_limit_bytes = 8 * GiB;
        if (total_required_bytes > system_limit_bytes) {
            @compileError("Memory budget exceeds system limit: " ++
                std.fmt.comptimePrint("{d}MB required > {d}MB limit", .{
                    total_required_bytes / MiB, system_limit_bytes / MiB,
                }));
        }
        if (worker_count == 0 or worker_count > 128) {
            @compileError("Invalid worker count: must be between 1-128");
        }
    }

    /// Print the budget to the log so operators can sanity-check sizing
    /// before deployment.
    pub fn printBudget() void {
        std.log.info("Memory Budget:", .{});
        std.log.info("  Max Connections: {d}", .{max_connections});
        std.log.info("  Max Streams/Conn: {d}", .{max_streams_per_connection});
        std.log.info("  Stream Instance: {d}KB", .{stream_instance_bytes / KiB});
        std.log.info("  StreamStorage/Conn: {d}KB", .{stream_storage_bytes / KiB});
        std.log.info("  Connection Slots: {d}MB", .{connection_memory_bytes / MiB});
        std.log.info("  Worker Threads: {d}", .{worker_count});
        std.log.info("  Worker Memory: {d}MB", .{worker_memory_bytes / MiB});
        std.log.info("  Server Overhead: {d}MB", .{server_overhead_bytes / MiB});
        std.log.info("  Total Required: {d}MB", .{total_required_bytes / MiB});
    }
};

const StaticAllocator = @import("static_allocator.zig");

/// Single phase-gated allocator wrapping the caller-supplied heap.
/// All server-level allocations flow through this; it is frozen before
/// the event loop starts so that any accidental runtime allocation
/// triggers an assertion failure.
var static_allocator_global: StaticAllocator = undefined;
var static_allocator_initialized: bool = false;

pub fn isStaticAllocatorInitialized() bool {
    return static_allocator_initialized;
}

/// Wrap the caller's allocator in a phase-gated StaticAllocator and print
/// the memory budget.  Safe to call multiple times (second call is a no-op)
/// so that both `http2.init()` and test suites can call it.
pub fn initStaticAllocator(backing_allocator: std.mem.Allocator) !void {
    if (static_allocator_initialized) return;

    static_allocator_global = StaticAllocator.init(backing_allocator);
    static_allocator_initialized = true;
    MemBudget.printBudget();
}

/// Return a pointer to the phase-gated allocator.
/// Precondition: `initStaticAllocator` must have been called.
pub fn staticAllocatorPtr() *StaticAllocator {
    std.debug.assert(static_allocator_initialized);
    return &static_allocator_global;
}

/// Freeze the phase-gated allocator so that any `alloc`, `resize`, or
/// `remap` call will assert-fail.  Call after all server init is complete.
pub fn freezeStaticAllocator() void {
    std.debug.assert(static_allocator_initialized);
    if (static_allocator_global.state == .init) {
        static_allocator_global.transition_from_init_to_static();
    }
}

/// Unfreeze for shutdown; allows `free` but not `alloc`.
/// State may already be `.deinit` if resources were freed via errdefer
/// before the explicit shutdown sequence.
pub fn unfreezeStaticAllocator() void {
    std.debug.assert(static_allocator_initialized);
    if (static_allocator_global.state == .static) {
        static_allocator_global.transition_from_static_to_deinit();
    }
}

/// Deinitialize the phase-gated allocator and mark it as uninitialized.
pub fn deinitStaticAllocator() void {
    if (!static_allocator_initialized) return;

    unfreezeStaticAllocator();
    static_allocator_global.deinit();
    static_allocator_initialized = false;
}

// -----------------------------------------------------------------------
//  Tests
// -----------------------------------------------------------------------

test "MemBudget constants are consistent" {
    try std.testing.expect(MemBudget.total_required_bytes > 0);
    try std.testing.expect(MemBudget.total_required_bytes < 8 * GiB);
    try std.testing.expect(MemBudget.worker_count > 0);
    try std.testing.expect(MemBudget.worker_count <= 128);

    // The stream instance must be at least large enough to hold the
    // mandatory inline buffers.
    const minimum_stream_bytes = MemBudget.stream_header_fragments_bytes +
        MemBudget.stream_request_body_bytes;
    try std.testing.expect(MemBudget.stream_instance_bytes >= minimum_stream_bytes);

    // Connection-level totals must exceed per-stream storage.
    try std.testing.expect(MemBudget.connection_memory_bytes > MemBudget.stream_memory_per_connection);
}

test "StaticAllocator init → freeze → unfreeze → deinit lifecycle" {
    const allocator = std.testing.allocator;

    try initStaticAllocator(allocator);
    defer deinitStaticAllocator();

    const alloc = staticAllocatorPtr().allocator();
    const mem = try alloc.alloc(u8, 64);

    freezeStaticAllocator();

    unfreezeStaticAllocator();
    alloc.free(mem);
}

test "StaticAllocator prevents alloc after freeze" {
    const allocator = std.testing.allocator;

    try initStaticAllocator(allocator);
    defer deinitStaticAllocator();

    const alloc = staticAllocatorPtr().allocator();
    const mem = try alloc.alloc(u8, 64);

    freezeStaticAllocator();
    // alloc after freeze would @panic; cannot test without process isolation.
    unfreezeStaticAllocator();
    alloc.free(mem);
}
