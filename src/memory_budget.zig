//! HTTP/2 resource limits and startup-only allocator authority.
//!
//! The server computes its concrete pool counts from `RuntimePlan`, allocates
//! those pools during initialization, and seals `StaticAllocator` before
//! accepting traffic. Capacity exhaustion is handled as protocol overload;
//! it never falls back to growing a heap allocation during runtime.

const std = @import("std");
const builtin = @import("builtin");
const StaticAllocator = @import("static_allocator.zig");
const Hpack = @import("hpack.zig").Hpack;

// Kept in sync with `http2.has_event_loop_backend`; importing it here would
// be circular, since `http2.zig` imports this module.
const has_event_loop_backend = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .linux => true,
    else => false,
};
const EventLoop = if (has_event_loop_backend) @import("io/EventLoop.zig") else opaque {};

pub const KiB: usize = 1024;
pub const MiB: usize = 1024 * KiB;
pub const GiB: usize = 1024 * MiB;

pub const MemBudget = struct {
    pub const system_limit_bytes = 8 * GiB;
    pub const max_connections: u32 = 1000;
    pub const max_streams_per_connection: u32 = 100;
    pub const max_frame_size_bytes: usize = 16 * KiB;
    pub const max_header_size_bytes: usize = 8 * KiB;
    pub const max_data_buffer_bytes: usize = 16 * KiB;
    pub const max_io_buffer_size_bytes: u32 = 32 * KiB;

    pub const worker_count: u16 = 2;
    pub const worker_count_max: u16 = 128;

    pub const wait_registrations_per_connection: u32 = 2;
    pub const wait_registrations_listener: u32 = 1;
    pub const event_loop_fibers_per_connection: u32 = 1;
    pub const wait_registration_bytes_max: usize = 128;
    pub const wait_map_fixed_bytes_max: usize = 256;
    // Worker idle stack plus one guard page; see `event_loop_fiber_bytes_max`
    // for why the page size drives the worst case, and `idle_stack_size` in
    // `io/EventLoop.zig` for why the stack itself is one MiB.
    pub const worker_stack_reservation_bytes_max: usize = 1152 * KiB;
    pub const event_loop_control_memory_bytes_max: usize = 2 * MiB;

    pub const stream_header_fragments_bytes = max_header_size_bytes;
    pub const stream_headers_storage_bytes = max_header_size_bytes;
    pub const stream_request_body_bytes = max_data_buffer_bytes;
    pub const stream_response_body_capacity_bytes: usize = 256;
    pub const stream_response_body_bytes: usize = 272;
    pub const stream_headers_array_bytes = 64 * @sizeOf(struct {
        name: []const u8,
        value: []const u8,
    });
    pub const stream_metadata_bytes: usize = 2 * KiB;

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
        max_streams_per_connection * stream_instance_bytes +
        stream_storage_lookup_bytes;

    pub const connection_slot_overhead_bytes: usize = 64;
    pub const connection_slot_bytes =
        stream_storage_bytes + connection_slot_overhead_bytes;
    pub const stream_memory_per_connection =
        max_streams_per_connection * stream_instance_bytes;
    pub const connection_memory_bytes = max_connections * connection_slot_bytes;

    pub const io_buffer_memory_bytes =
        max_connections * max_io_buffer_size_bytes * 2;
    // One fiber allocation, rounded up to a page. The page size is the
    // platform variable here: 4 KiB on x86_64, 16 KiB on aarch64 macOS, and
    // 64 KiB on aarch64 Linux, which is the worst case this must cover.
    pub const event_loop_fiber_bytes_max: usize = 576 * KiB;
    pub const event_loop_fiber_count =
        max_connections * event_loop_fibers_per_connection;
    pub const wait_registration_count_per_thread_max =
        max_connections * wait_registrations_per_connection +
        wait_registrations_listener;
    pub const event_loop_allocator_memory_bytes_max =
        eventLoopAllocatorBytesMax(
            worker_count_max,
            event_loop_fiber_count,
            wait_registration_count_per_thread_max,
        ) catch @compileError("maximum event-loop allocator budget overflowed");
    pub const worker_memory_bytes_max = workerStackBytesMax(worker_count_max) catch
        @compileError("maximum worker stack budget overflowed");
    pub const hpack_thread_local_memory_bytes_max =
        worker_count_max * Hpack.scratch_buffer_size;
    pub const server_overhead_bytes: usize = 16 * KiB;

    pub const total_required_bytes =
        connection_memory_bytes +
        io_buffer_memory_bytes +
        event_loop_allocator_memory_bytes_max +
        worker_memory_bytes_max +
        hpack_thread_local_memory_bytes_max +
        server_overhead_bytes;

    comptime {
        if (total_required_bytes > system_limit_bytes) {
            @compileError("maximum HTTP/2 memory budget exceeds 8 GiB");
        }
        if (worker_count == 0) @compileError("worker_count must be positive");
        if (worker_count > worker_count_max) @compileError("worker_count exceeds ceiling");
    }

    pub fn printMaximum() void {
        std.log.info("HTTP/2 static memory ceiling: {d} MiB", .{
            total_required_bytes / MiB,
        });
        std.log.info("  connections: {d}", .{max_connections});
        std.log.info("  streams per connection: {d}", .{max_streams_per_connection});
        std.log.info("  event-loop fibers: {d}", .{event_loop_fiber_count});
        std.log.info("  event-loop threads maximum: {d}", .{worker_count_max});
    }
};

pub const RuntimePlan = struct {
    connection_count: u32,
    worker_count: u16,
    fiber_count: u32,
    wait_registration_count_per_thread: u32,
    wait_registration_count_total: usize,
    io_buffer_bytes: usize,
    event_loop_allocator_bytes_max: usize,
    worker_stack_bytes_max: usize,
    hpack_thread_local_bytes_max: usize,
    core_memory_bytes_max: usize,

    pub fn init(
        connection_count: u32,
        io_buffer_size: u32,
        worker_count: u16,
    ) !RuntimePlan {
        try validateCounts(connection_count, io_buffer_size, worker_count);

        const io_buffer_bytes = try multiply3(
            connection_count,
            io_buffer_size,
            2,
        );
        const wait_registration_count = std.math.mul(
            u32,
            connection_count,
            MemBudget.wait_registrations_per_connection,
        ) catch return error.MemoryBudgetOverflow;
        const wait_registration_count_per_thread = std.math.add(
            u32,
            wait_registration_count,
            MemBudget.wait_registrations_listener,
        ) catch return error.MemoryBudgetOverflow;
        const wait_registration_count_total = std.math.mul(
            usize,
            wait_registration_count_per_thread,
            worker_count,
        ) catch return error.MemoryBudgetOverflow;
        const event_loop_allocator_bytes_max = try eventLoopAllocatorBytesMax(
            worker_count,
            connection_count,
            wait_registration_count_per_thread,
        );
        const worker_stack_bytes_max = try workerStackBytesMax(worker_count);
        const hpack_thread_local_bytes_max = std.math.mul(
            usize,
            worker_count,
            Hpack.scratch_buffer_size,
        ) catch return error.MemoryBudgetOverflow;

        var plan: RuntimePlan = .{
            .connection_count = connection_count,
            .worker_count = worker_count,
            .fiber_count = connection_count,
            .wait_registration_count_per_thread = wait_registration_count_per_thread,
            .wait_registration_count_total = wait_registration_count_total,
            .io_buffer_bytes = io_buffer_bytes,
            .event_loop_allocator_bytes_max = event_loop_allocator_bytes_max,
            .worker_stack_bytes_max = worker_stack_bytes_max,
            .hpack_thread_local_bytes_max = hpack_thread_local_bytes_max,
            .core_memory_bytes_max = 0,
        };
        plan.core_memory_bytes_max = try plan.totalMemoryBytesForSlots(
            MemBudget.connection_slot_bytes,
            io_buffer_bytes,
        );
        return plan;
    }

    pub fn totalMemoryBytesForSlots(
        self: RuntimePlan,
        connection_slot_size: usize,
        separate_io_buffer_bytes: usize,
    ) !usize {
        const slot_bytes = std.math.mul(
            usize,
            self.connection_count,
            connection_slot_size,
        ) catch return error.MemoryBudgetOverflow;

        var total = try addBytes(slot_bytes, separate_io_buffer_bytes);
        total = try addBytes(total, self.event_loop_allocator_bytes_max);
        total = try addBytes(total, self.worker_stack_bytes_max);
        total = try addBytes(total, self.hpack_thread_local_bytes_max);
        total = try addBytes(total, MemBudget.server_overhead_bytes);
        if (total > MemBudget.system_limit_bytes) return error.MemoryBudgetExceedsSystemLimit;
        return total;
    }
};

pub const AllocatorSnapshot = struct {
    allocations_live: usize,
    bytes_live: usize,
    bytes_reserved: usize,
    state: StaticAllocator.State,
};

var static_allocator_global: StaticAllocator = undefined;
var static_allocator_initialized: bool = false;

pub fn initStaticAllocator(backing_allocator: std.mem.Allocator) !void {
    if (static_allocator_initialized) return error.StaticAllocatorAlreadyInitialized;

    static_allocator_global = StaticAllocator.init(backing_allocator);
    static_allocator_initialized = true;
    MemBudget.printMaximum();
}

pub fn isStaticAllocatorInitialized() bool {
    return static_allocator_initialized;
}

pub fn backingAllocatorMatches(candidate: std.mem.Allocator) bool {
    if (!static_allocator_initialized) return false;
    const static_allocator = staticAllocatorPtr();
    // Singleton allocators (`smp_allocator`, `page_allocator`) declare
    // `.ptr = undefined`, and ReleaseFast may materialize a different value at
    // each use, so the context pointer is not a usable identity here.
    return static_allocator.parent_allocator.vtable == candidate.vtable;
}

pub fn staticAllocatorPtr() *StaticAllocator {
    if (!static_allocator_initialized) @panic("http2.init() must run before allocation");
    return &static_allocator_global;
}

pub fn freezeStaticAllocator() void {
    staticAllocatorPtr().transition_from_init_to_static();
}

pub fn beginStaticAllocatorDeinit() void {
    const static_allocator = staticAllocatorPtr();
    switch (static_allocator.state) {
        .init => static_allocator.transition_from_init_to_deinit(),
        .static => static_allocator.transition_from_static_to_deinit(),
        .deinit => {},
    }
}

pub fn deinitStaticAllocator() void {
    if (!static_allocator_initialized) return;

    beginStaticAllocatorDeinit();
    static_allocator_global.deinit();
    static_allocator_initialized = false;
}

pub fn allocatorSnapshot() AllocatorSnapshot {
    const static_allocator = staticAllocatorPtr();
    return .{
        .allocations_live = static_allocator.allocations_live,
        .bytes_live = static_allocator.bytes_live,
        .bytes_reserved = static_allocator.bytes_reserved,
        .state = static_allocator.state,
    };
}

fn validateCounts(connection_count: u32, io_buffer_size: u32, worker_count: u16) !void {
    if (connection_count == 0) return error.InvalidConnectionCount;
    if (connection_count > MemBudget.max_connections) return error.ConnectionCountExceedsBudget;
    if (io_buffer_size < 1024) return error.InvalidIoBufferSize;
    if (io_buffer_size > MemBudget.max_io_buffer_size_bytes) {
        return error.IoBufferSizeExceedsBudget;
    }
    if (worker_count == 0) return error.InvalidWorkerCount;
    if (worker_count > MemBudget.worker_count_max) return error.WorkerCountExceedsBudget;
}

fn eventLoopAllocatorBytesMax(
    worker_count: u16,
    fiber_count: u32,
    wait_registration_count_per_thread: u32,
) !usize {
    if (comptime has_event_loop_backend) {
        return EventLoop.allocatorBytesMax(.{
            .n_threads = worker_count,
            .max_concurrent_tasks = fiber_count,
            .max_wait_registrations_per_thread = wait_registration_count_per_thread,
        }) catch |err| switch (err) {
            error.InvalidCapacity => error.InvalidWorkerCount,
            error.Overflow => error.MemoryBudgetOverflow,
        };
    }

    const fiber_bytes = std.math.mul(
        usize,
        fiber_count,
        MemBudget.event_loop_fiber_bytes_max,
    ) catch return error.MemoryBudgetOverflow;
    const registration_bytes = std.math.mul(
        usize,
        wait_registration_count_per_thread,
        MemBudget.wait_registration_bytes_max,
    ) catch return error.MemoryBudgetOverflow;
    const map_bytes = try addBytes(
        MemBudget.wait_map_fixed_bytes_max,
        registration_bytes,
    );
    const all_map_bytes = std.math.mul(
        usize,
        worker_count,
        map_bytes,
    ) catch return error.MemoryBudgetOverflow;
    const allocator_bytes = try addBytes(fiber_bytes, all_map_bytes);
    return addBytes(allocator_bytes, MemBudget.event_loop_control_memory_bytes_max);
}

fn workerStackBytesMax(worker_count: u16) !usize {
    if (worker_count == 0) return error.InvalidWorkerCount;
    const spawned_worker_count = worker_count - 1;
    const bytes_per_worker = if (has_event_loop_backend)
        EventLoop.worker_stack_reservation_bytes_max
    else
        MemBudget.worker_stack_reservation_bytes_max;
    return std.math.mul(usize, spawned_worker_count, bytes_per_worker) catch {
        return error.MemoryBudgetOverflow;
    };
}

fn addBytes(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b) catch error.MemoryBudgetOverflow;
}

fn multiply3(a: u32, b: u32, c: u32) !usize {
    const product_ab = std.math.mul(usize, a, b) catch {
        return error.MemoryBudgetOverflow;
    };
    return std.math.mul(usize, product_ab, c) catch {
        return error.MemoryBudgetOverflow;
    };
}

test "runtime plan bounds HTTP/2 resources" {
    const plan = try RuntimePlan.init(8, 16 * KiB, 2);

    try std.testing.expectEqual(@as(u32, 8), plan.connection_count);
    try std.testing.expectEqual(@as(u32, 8), plan.fiber_count);
    try std.testing.expectEqual(@as(u32, 17), plan.wait_registration_count_per_thread);
    try std.testing.expectEqual(@as(usize, 34), plan.wait_registration_count_total);
    try std.testing.expectEqual(@as(usize, 256 * KiB), plan.io_buffer_bytes);
    try std.testing.expect(plan.event_loop_allocator_bytes_max > 0);
    try std.testing.expectEqual(
        @as(usize, 2 * Hpack.scratch_buffer_size),
        plan.hpack_thread_local_bytes_max,
    );
    try std.testing.expect(plan.core_memory_bytes_max <= MemBudget.total_required_bytes);
}

test "maximum runtime plan is covered by the published ceiling" {
    const plan = try RuntimePlan.init(
        MemBudget.max_connections,
        MemBudget.max_io_buffer_size_bytes,
        MemBudget.worker_count_max,
    );

    try std.testing.expectEqual(
        MemBudget.event_loop_allocator_memory_bytes_max,
        plan.event_loop_allocator_bytes_max,
    );
    try std.testing.expectEqual(MemBudget.total_required_bytes, plan.core_memory_bytes_max);
}

test "runtime plan rejects resources outside the static ceiling" {
    try std.testing.expectError(
        error.InvalidConnectionCount,
        RuntimePlan.init(0, 16 * KiB, 2),
    );
    try std.testing.expectError(
        error.ConnectionCountExceedsBudget,
        RuntimePlan.init(MemBudget.max_connections + 1, 16 * KiB, 2),
    );
    try std.testing.expectError(
        error.IoBufferSizeExceedsBudget,
        RuntimePlan.init(1, MemBudget.max_io_buffer_size_bytes + 1, 2),
    );
    try std.testing.expectError(
        error.WorkerCountExceedsBudget,
        RuntimePlan.init(1, 16 * KiB, MemBudget.worker_count_max + 1),
    );
}

test "static allocator lifecycle records startup bytes" {
    try initStaticAllocator(std.testing.allocator);
    try std.testing.expect(backingAllocatorMatches(std.testing.allocator));
    try std.testing.expect(!backingAllocatorMatches(std.heap.page_allocator));
    const allocator_instance = staticAllocatorPtr().allocator();
    const allocation = try allocator_instance.alloc(u8, 64);

    freezeStaticAllocator();
    const snapshot = allocatorSnapshot();
    try std.testing.expectEqual(@as(usize, 64), snapshot.bytes_reserved);
    try std.testing.expectEqual(StaticAllocator.State.static, snapshot.state);

    beginStaticAllocatorDeinit();
    allocator_instance.free(allocation);
    deinitStaticAllocator();
}
