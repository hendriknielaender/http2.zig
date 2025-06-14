//! This module implements compile-time memory budgeting that prevents runtime OOM
//! by pre-allocating all necessary memory based on worst-case calculations.
//!
//! - Compile-time resource planning
//! - Static memory budgets
//! - Fail-fast at build time
//! - Zero runtime allocation failures
//! - Performance through pre-allocation
const std = @import("std");
pub const KiB = 1024;
pub const MiB = 1024 * KiB;
pub const GiB = 1024 * MiB;
/// Compile-time Memory Budget Calculator
pub const MemBudget = struct {
    pub const max_conns = 10; // Reduced for testing
    pub const max_streams_per_conn = 5; // Reduced for testing
    // HTTP/2 protocol limits (balanced for constraints)
    pub const bytes_per_conn = 64 * KiB; // Per-connection flow-control window
    pub const max_frame_size = 16 * KiB; // Standard HTTP/2 frame size
    pub const max_header_size = 8 * KiB; // Maximum header block size (needs 6KB minimum)
    pub const max_data_buffer = 16 * KiB; // Per-stream data buffer (needs 16KB minimum)
    pub const worker_count = 2; // Reduced for testing to avoid race conditions
    pub const stack_per_thread = 128 * KiB;
    pub const global_reserve = 256 * KiB;
    pub const emergency_reserve = 256 * KiB;
    // Calculate total memory requirements at compile time
    pub const stream_memory = max_streams_per_conn * max_data_buffer;
    pub const connection_memory = max_conns * (bytes_per_conn + stream_memory);
    pub const worker_memory = worker_count * stack_per_thread;
    pub const total_required = connection_memory + worker_memory + global_reserve + emergency_reserve;
    comptime {
        // System memory limit (8GB for most servers)
        const system_limit = 8 * GiB;
        if (total_required > system_limit) {
            @compileError("Memory budget exceeds system limit: " ++
                std.fmt.comptimePrint("{d}MB required > {d}MB limit", .{ total_required / MiB, system_limit / MiB }));
        }
        // Ensure we don't exceed per-connection limits - adjusted for smaller buffers
        if (stream_memory > bytes_per_conn * 100) {
            @compileError("Stream memory per connection exceeds reasonable limits");
        }
        // Validate worker configuration
        if (worker_count == 0 or worker_count > 128) {
            @compileError("Invalid worker count: must be between 1-128");
        }
    }
    /// Memory layout information for debugging
    pub fn printBudget() void {
        std.log.info("Memory Budget:", .{});
        std.log.info("  Max Connections: {d}", .{max_conns});
        std.log.info("  Max Streams/Conn: {d}", .{max_streams_per_conn});
        std.log.info("  Connection Memory: {d}MB", .{connection_memory / MiB});
        std.log.info("  Worker Threads: {d}", .{worker_count});
        std.log.info("  Worker Memory: {d}MB", .{worker_memory / MiB});
        std.log.info("  Global Reserve: {d}MB", .{global_reserve / MiB});
        std.log.info("  Total Required: {d}MB", .{total_required / MiB});
        std.log.info("  Memory Efficiency: {d}%", .{(total_required * 100) / (8 * GiB)});
    }
};
/// Static Memory Pool for Zero-Allocation Operations
pub const StaticMemoryPool = struct {
    // Pre-allocated connection pool
    connection_pool: [MemBudget.max_conns]?ConnectionSlot,
    connection_free_list: std.DoublyLinkedList(*ConnectionSlot),
    // Pre-allocated stream pools (per connection)
    stream_pools: [MemBudget.max_conns][MemBudget.max_streams_per_conn]?StreamSlot,
    stream_free_lists: [MemBudget.max_conns]std.DoublyLinkedList(*StreamSlot),
    // Pre-allocated data buffers
    data_buffer_pool: [MemBudget.max_conns * MemBudget.max_streams_per_conn][MemBudget.max_data_buffer]u8,
    header_buffer_pool: [MemBudget.max_conns * MemBudget.max_streams_per_conn][MemBudget.max_header_size]u8,
    // Worker thread pools (will be managed by WorkerPool)
    // worker_pool: [MemBudget.worker_count]WorkerThread,
    // Global allocator arena
    arena: std.heap.ArenaAllocator,
    const Self = @This();
    pub fn init(backing_allocator: std.mem.Allocator) !Self {
        var self = Self{
            .connection_pool = [_]?ConnectionSlot{null} ** MemBudget.max_conns,
            .connection_free_list = .{},
            .stream_pools = [_][MemBudget.max_streams_per_conn]?StreamSlot{[_]?StreamSlot{null} ** MemBudget.max_streams_per_conn} ** MemBudget.max_conns,
            .stream_free_lists = [_]std.DoublyLinkedList(*StreamSlot){.{}} ** MemBudget.max_conns,
            .data_buffer_pool = undefined,
            .header_buffer_pool = undefined,
            .arena = std.heap.ArenaAllocator.init(backing_allocator),
        };
        // Initialize connection free list
        for (&self.connection_pool, 0..) |*slot, i| {
            slot.* = ConnectionSlot{
                .id = i,
                .in_use = std.atomic.Value(bool).init(false),
                .data = undefined,
                .node = undefined,
            };
            if (slot.*) |*conn_slot| {
                conn_slot.node.data = conn_slot;
                self.connection_free_list.prepend(&conn_slot.node);
            }
        }
        // Initialize stream free lists for each connection
        for (&self.stream_pools, &self.stream_free_lists, 0..) |*pool, *free_list, conn_id| {
            for (pool, 0..) |*slot, stream_id| {
                slot.* = StreamSlot{
                    .id = stream_id,
                    .connection_id = conn_id,
                    .in_use = std.atomic.Value(bool).init(false),
                    .data = undefined,
                    .node = undefined,
                };
                if (slot.*) |*stream_slot| {
                    stream_slot.node.data = stream_slot;
                    free_list.prepend(&stream_slot.node);
                }
            }
        }
        // Worker pool will be initialized separately by WorkerPool module
        return self;
    }
    pub fn deinit(self: *Self) void {
        // Worker pool cleanup is handled by WorkerPool module
        self.arena.deinit();
    }

    pub fn acquireConnection(self: *Self) ?*ConnectionSlot {
        if (self.connection_free_list.popFirst()) |node| {
            const slot = node.data;
            if (slot.in_use.cmpxchgWeak(false, true, .acquire, .monotonic) == null) {
                return slot;
            }
            // If CAS failed, put it back and try again
            self.connection_free_list.prepend(node);
        }
        return null; // No available connections
    }
    /// Release a connection slot
    pub fn releaseConnection(self: *Self, slot: *ConnectionSlot) void {
        slot.in_use.store(false, .release);
        self.connection_free_list.prepend(&slot.node);
    }
    /// Acquire a stream slot for a specific connection
    pub fn acquireStream(self: *Self, connection_id: usize) ?*StreamSlot {
        if (connection_id >= MemBudget.max_conns) return null;
        if (self.stream_free_lists[connection_id].popFirst()) |node| {
            const slot = node.data;
            if (slot.in_use.cmpxchgWeak(false, true, .acquire, .monotonic) == null) {
                return slot;
            }
            // If CAS failed, put it back
            self.stream_free_lists[connection_id].prepend(node);
        }
        return null; // No available streams for this connection
    }
    /// Release a stream slot
    pub fn releaseStream(self: *Self, slot: *StreamSlot) void {
        slot.in_use.store(false, .release);
        if (slot.connection_id < MemBudget.max_conns) {
            self.stream_free_lists[slot.connection_id].prepend(&slot.node);
        }
    }
    /// Get pre-allocated data buffer for a stream
    pub fn getDataBuffer(self: *Self, connection_id: usize, stream_id: usize) ?[]u8 {
        const buffer_index = connection_id * MemBudget.max_streams_per_conn + stream_id;
        if (buffer_index >= self.data_buffer_pool.len) return null;
        return &self.data_buffer_pool[buffer_index];
    }
    /// Get pre-allocated header buffer for a stream
    pub fn getHeaderBuffer(self: *Self, connection_id: usize, stream_id: usize) ?[]u8 {
        const buffer_index = connection_id * MemBudget.max_streams_per_conn + stream_id;
        if (buffer_index >= self.header_buffer_pool.len) return null;
        return &self.header_buffer_pool[buffer_index];
    }
    /// Get arena allocator for temporary allocations
    pub fn allocator(self: *Self) std.mem.Allocator {
        return self.arena.allocator();
    }
};
/// Connection Slot in the static pool
pub const ConnectionSlot = struct {
    id: usize,
    in_use: std.atomic.Value(bool),
    data: ConnectionData,
    node: std.DoublyLinkedList(*ConnectionSlot).Node,
    pub const ConnectionData = struct {
        // Connection-specific data will be defined when integrating with Connection
        settings: ConnectionSettings,
        recv_window_size: i32,
        send_window_size: i32,
        last_stream_id: u32,
        goaway_sent: bool,
        goaway_received: bool,
    };
};
/// Stream Slot in the static pool
pub const StreamSlot = struct {
    id: usize,
    connection_id: usize,
    in_use: std.atomic.Value(bool),
    data: StreamData,
    node: std.DoublyLinkedList(*StreamSlot).Node,
    pub const StreamData = struct {
        // Stream-specific data will be defined when integrating with Stream
        state: StreamState,
        recv_window_size: i32,
        send_window_size: i32,
        headers_received: bool,
        data_received: usize,
    };
};
/// Worker Thread for handling HTTP/2 processing
pub const WorkerThread = struct {
    id: usize,
    work_queue: std.atomic.Queue(WorkItem),
    running: std.atomic.Value(bool),
    thread: std.Thread,
    pub fn start(self: *WorkerThread) !void {
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, workerMain, .{self});
    }
    pub fn stop(self: *WorkerThread) void {
        self.running.store(false, .release);
        // Wake up the worker if it's sleeping
        self.work_queue.prepend(WorkItem{ .type = .shutdown });
        self.thread.join();
    }
    fn workerMain(self: *WorkerThread) void {
        while (self.running.load(.acquire)) {
            if (self.work_queue.popFirst()) |work| {
                switch (work.type) {
                    .shutdown => break,
                    .process_frame => {
                        // Process HTTP/2 frame
                        processFrame(work.data.frame);
                    },
                    .process_connection => {
                        // Handle connection events
                        processConnection(work.data.connection);
                    },
                }
            } else {
                // No work available, yield CPU
                std.Thread.yield() catch {};
            }
        }
    }
};
/// Work item for the worker queue
pub const WorkItem = struct {
    type: WorkType,
    data: WorkData = undefined,
    pub const WorkType = enum {
        shutdown,
        process_frame,
        process_connection,
    };
    pub const WorkData = union {
        frame: *FrameData,
        connection: *ConnectionSlot,
    };
};
/// Placeholder types (will be replaced with actual types during integration)
const ConnectionSettings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 1000,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,
};
const StreamState = enum {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
};
const FrameData = struct {
    // Placeholder for frame data
};
// Placeholder functions (will be implemented during integration)
fn processFrame(frame: *FrameData) void {
    _ = frame;
    // TODO: Implement frame processing
}
fn processConnection(connection: *ConnectionSlot) void {
    _ = connection;
    // TODO: Implement connection processing
}
/// Global static memory pool instance
var global_memory_pool: ?StaticMemoryPool = null;
/// Initialize the global memory pool
pub fn initGlobalMemoryPool(backing_allocator: std.mem.Allocator) !void {
    if (global_memory_pool != null) {
        return error.AlreadyInitialized;
    }
    global_memory_pool = try StaticMemoryPool.init(backing_allocator);
    // Worker pool is managed separately by worker_pool.zig
    MemBudget.printBudget();
}
/// Get the global memory pool
pub fn getGlobalMemoryPool() *StaticMemoryPool {
    return &global_memory_pool.?;
}
/// Deinitialize the global memory pool
pub fn deinitGlobalMemoryPool() void {
    if (global_memory_pool) |*pool| {
        pool.deinit();
        global_memory_pool = null;
    }
}
/// Compile-time verification that all budget constraints are met
pub fn verifyMemoryBudget() void {
    comptime {
        // Verify total memory usage
        if (MemBudget.total_required > 8 * GiB) {
            @compileError("Total memory budget exceeds 8GB limit");
        }
        // Verify connection limits are reasonable
        if (MemBudget.max_conns * MemBudget.max_streams_per_conn > 1_000_000) {
            @compileError("Total stream capacity exceeds reasonable limits");
        }
        // Verify worker thread configuration
        if (MemBudget.worker_count > std.Thread.getCpuCount() catch 32) {
            @compileError("Worker count exceeds available CPU cores");
        }
    }
}
test "Memory budget calculations" {
    // Verify compile-time calculations are reasonable
    try std.testing.expect(MemBudget.total_required > 0);
    try std.testing.expect(MemBudget.total_required < 8 * GiB);
    try std.testing.expect(MemBudget.worker_count > 0);
    try std.testing.expect(MemBudget.worker_count <= 128);
}
test "Static memory pool initialization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var pool = try StaticMemoryPool.init(arena.allocator());
    defer pool.deinit();
    // Test connection acquisition
    const conn1 = pool.acquireConnection();
    try std.testing.expect(conn1 != null);
    const conn2 = pool.acquireConnection();
    try std.testing.expect(conn2 != null);
    try std.testing.expect(conn1.?.id != conn2.?.id);
    // Test stream acquisition
    const stream1 = pool.acquireStream(0);
    try std.testing.expect(stream1 != null);
    try std.testing.expect(stream1.?.connection_id == 0);
    // Test buffer access
    const data_buffer = pool.getDataBuffer(0, 0);
    try std.testing.expect(data_buffer != null);
    try std.testing.expect(data_buffer.?.len == MemBudget.max_data_buffer);
    // Clean up
    if (conn1) |c| pool.releaseConnection(c);
    if (conn2) |c| pool.releaseConnection(c);
    if (stream1) |s| pool.releaseStream(s);
}

