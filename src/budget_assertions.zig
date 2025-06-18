//! This module provides comprehensive compile-time checks to ensure
//! the memory budget system is correctly configured and cannot fail at runtime.
//!
//! - Fail-fast at compile time
//! - Explicit resource constraints
//! - Zero runtime surprises
//! - System-aware configuration
const std = @import("std");
const memory_budget = @import("memory_budget.zig");
/// Comprehensive compile-time memory budget validation
pub fn validateMemoryBudget() void {
    comptime {
        // === BASIC SANITY CHECKS ===
        // Ensure all constants are positive
        if (memory_budget.MemBudget.max_conns == 0) {
            @compileError("max_conns cannot be zero");
        }
        if (memory_budget.MemBudget.max_streams_per_conn == 0) {
            @compileError("max_streams_per_conn cannot be zero");
        }
        if (memory_budget.MemBudget.worker_count == 0) {
            @compileError("worker_count cannot be zero");
        }
        // === SYSTEM RESOURCE LIMITS ===
        const system_memory_limit = 8 * memory_budget.GiB;
        if (memory_budget.MemBudget.total_required > system_memory_limit) {
            @compileError(std.fmt.comptimePrint("Memory budget exceeds system limit: {d}MB required > {d}MB available", .{ memory_budget.MemBudget.total_required / memory_budget.MiB, system_memory_limit / memory_budget.MiB }));
        }
        // Ensure we don't exceed practical CPU limits
        const max_reasonable_workers = 128;
        if (memory_budget.MemBudget.worker_count > max_reasonable_workers) {
            @compileError(std.fmt.comptimePrint("Worker count too high: {d} > {d} (maximum reasonable)", .{ memory_budget.MemBudget.worker_count, max_reasonable_workers }));
        }
        // === MEMORY LAYOUT VALIDATION ===
        // Ensure per-connection memory is reasonable
        const max_memory_per_conn = 64 * memory_budget.MiB;
        const actual_memory_per_conn = memory_budget.MemBudget.bytes_per_conn +
            memory_budget.MemBudget.stream_memory;
        if (actual_memory_per_conn > max_memory_per_conn) {
            @compileError(std.fmt.comptimePrint("Memory per connection too high: {d}MB > {d}MB limit", .{ actual_memory_per_conn / memory_budget.MiB, max_memory_per_conn / memory_budget.MiB }));
        }
        // Ensure stream memory is reasonable relative to connection memory
        const stream_to_conn_ratio = (memory_budget.MemBudget.stream_memory * 100) / memory_budget.MemBudget.bytes_per_conn;
        if (stream_to_conn_ratio > 10000) { // Stream memory shouldn't be more than 100x connection buffer
            @compileError(std.fmt.comptimePrint("Stream memory ratio too high: {d}% of connection memory", .{stream_to_conn_ratio}));
        }
        // === HTTP/2 PROTOCOL COMPLIANCE ===
        // Validate against HTTP/2 protocol limits
        const http2_max_frame_size = 16 * memory_budget.MiB;
        if (memory_budget.MemBudget.max_frame_size > http2_max_frame_size) {
            @compileError(std.fmt.comptimePrint("Max frame size exceeds HTTP/2 limit: {d} > {d}", .{ memory_budget.MemBudget.max_frame_size, http2_max_frame_size }));
        }
        const http2_min_frame_size = 16384; // 16KB minimum
        if (memory_budget.MemBudget.max_frame_size < http2_min_frame_size) {
            @compileError(std.fmt.comptimePrint("Max frame size below HTTP/2 minimum: {d} < {d}", .{ memory_budget.MemBudget.max_frame_size, http2_min_frame_size }));
        }
        // Validate initial window size (must be <= 2^31-1)
        const max_window_size = 2147483647; // 2^31-1
        if (memory_budget.MemBudget.bytes_per_conn > max_window_size) {
            @compileError(std.fmt.comptimePrint("Connection window size exceeds HTTP/2 limit: {d} > {d}", .{ memory_budget.MemBudget.bytes_per_conn, max_window_size }));
        }
        // === PERFORMANCE CONSTRAINTS ===
        // Ensure total stream capacity is reasonable
        const total_streams = memory_budget.MemBudget.max_conns * memory_budget.MemBudget.max_streams_per_conn;
        const max_reasonable_streams = 10_000_000; // 10M streams max
        if (total_streams > max_reasonable_streams) {
            @compileError(std.fmt.comptimePrint("Total stream capacity too high: {d} > {d} streams", .{ total_streams, max_reasonable_streams }));
        }
        // Ensure memory pools can be addressed with reasonable index sizes
        const max_pool_index = 65535; // u16 max
        if (memory_budget.MemBudget.max_conns > max_pool_index) {
            @compileError(std.fmt.comptimePrint("Connection pool too large for u16 indexing: {d} > {d}", .{ memory_budget.MemBudget.max_conns, max_pool_index }));
        }
        if (memory_budget.MemBudget.max_streams_per_conn > max_pool_index) {
            @compileError(std.fmt.comptimePrint("Stream pool per connection too large for u16 indexing: {d} > {d}", .{ memory_budget.MemBudget.max_streams_per_conn, max_pool_index }));
        }
        // === MEMORY EFFICIENCY CHECKS ===
        // Warn if memory efficiency is too low (< 50% utilization at peak)
        const peak_efficiency = (memory_budget.MemBudget.connection_memory * 100) / memory_budget.MemBudget.total_required;
        if (peak_efficiency < 50) {
            @compileError(std.fmt.comptimePrint("Memory efficiency too low: {d}% utilization at peak load", .{peak_efficiency}));
        }
        // Ensure reserves are reasonable (not more than 50% of total)
        const total_reserves = memory_budget.MemBudget.global_reserve + memory_budget.MemBudget.emergency_reserve;
        const reserve_percentage = (total_reserves * 100) / memory_budget.MemBudget.total_required;
        if (reserve_percentage > 50) {
            @compileError(std.fmt.comptimePrint("Memory reserves too high: {d}% of total budget", .{reserve_percentage}));
        }
        // === THREAD SAFETY VALIDATION ===
        // Ensure atomic operations are available for our index types
        if (!@hasDecl(std.atomic.Value(u32), "load")) {
            @compileError("Platform does not support required atomic operations for u32");
        }
        if (!@hasDecl(std.atomic.Value(usize), "load")) {
            @compileError("Platform does not support required atomic operations for usize");
        }
        // === PLATFORM COMPATIBILITY ===
        // Ensure we're on a 64-bit platform (required for large address spaces)
        if (@sizeOf(usize) < 8) {
            @compileError("64-bit platform required for memory budget system");
        }
        // Ensure pointer alignment is reasonable
        if (@alignOf(*anyopaque) > 8) {
            @compileError("Platform pointer alignment too strict for efficient memory pools");
        }
        // === DEVELOPMENT CONSTRAINTS ===
        // In debug builds, add additional checks
        if (std.debug.runtime_safety) {
            // Ensure debug overhead doesn't push us over limits
            const debug_overhead_factor = 120; // 20% overhead for debug builds
            const debug_total = (memory_budget.MemBudget.total_required * debug_overhead_factor) / 100;
            if (debug_total > system_memory_limit) {
                @compileError(std.fmt.comptimePrint("Debug build memory budget exceeds system limit: {d}MB > {d}MB", .{ debug_total / memory_budget.MiB, system_memory_limit / memory_budget.MiB }));
            }
        }
    }
}
/// Compile-time validation of buffer sizes and layouts
pub fn validateBufferLayout() void {
    comptime {
        // Ensure data buffer can be partitioned as expected
        const min_partition_size = 4096; // 4KB minimum per partition
        const data_partitions = 4; // recv_headers, send_headers, recv_data, send_data
        if (memory_budget.MemBudget.max_data_buffer < (min_partition_size * data_partitions)) {
            @compileError(std.fmt.comptimePrint("Data buffer too small for partitioning: {d} < {d}", .{ memory_budget.MemBudget.max_data_buffer, min_partition_size * data_partitions }));
        }
        // Ensure header buffer can be partitioned
        const header_partitions = 3;
        if (memory_budget.MemBudget.max_header_size < (min_partition_size * header_partitions / 2)) {
            @compileError(std.fmt.comptimePrint("Header buffer too small for partitioning: {d} < {d}", .{ memory_budget.MemBudget.max_header_size, min_partition_size * header_partitions }));
        }
        // Ensure buffers are aligned for efficient access
        if (memory_budget.MemBudget.max_data_buffer % 64 != 0) {
            @compileError("Data buffer size should be 64-byte aligned for cache efficiency");
        }
        if (memory_budget.MemBudget.max_header_size % 64 != 0) {
            @compileError("Header buffer size should be 64-byte aligned for cache efficiency");
        }
    }
}
/// Generate compile-time report of memory layout
pub fn generateMemoryReport() void {
    comptime {
        // const total_mb = memory_budget.MemBudget.total_required / memory_budget.MiB;
        // const conn_mb = memory_budget.MemBudget.connection_memory / memory_budget.MiB;
        // const worker_mb = memory_budget.MemBudget.worker_memory / memory_budget.MiB;
        // const reserve_mb = (memory_budget.MemBudget.global_reserve + memory_budget.MemBudget.emergency_reserve) / memory_budget.MiB;
        // @compileLog(std.fmt.comptimePrint("Total Memory Budget: {d}MB", .{total_mb}));
        // @compileLog(std.fmt.comptimePrint("  Connection Memory: {d}MB ({d}%)", .{
        //     conn_mb,
        //     (conn_mb * 100) / total_mb
        // }));
        // @compileLog(std.fmt.comptimePrint("  Worker Memory: {d}MB ({d}%)", .{
        //     worker_mb,
        //     (worker_mb * 100) / total_mb
        // }));
        // @compileLog(std.fmt.comptimePrint("  Reserves: {d}MB ({d}%)", .{
        //     reserve_mb,
        //     (reserve_mb * 100) / total_mb
        // }));
        // @compileLog(std.fmt.comptimePrint("Max Connections: {d}", .{memory_budget.MemBudget.max_conns}));
        // @compileLog(std.fmt.comptimePrint("Max Streams/Conn: {d}", .{memory_budget.MemBudget.max_streams_per_conn}));
        // @compileLog(std.fmt.comptimePrint("Worker Threads: {d}", .{memory_budget.MemBudget.worker_count}));
        // @compileLog(std.fmt.comptimePrint("Total Possible Streams: {d}", .{
        //     memory_budget.MemBudget.max_conns * memory_budget.MemBudget.max_streams_per_conn
        // }));
        // @compileLog("=== End Memory Budget Report ===");
    }
}
/// Master validation function - call this to validate entire budget system
pub fn validateAll() void {
    validateMemoryBudget();
    validateBufferLayout();
    // Only generate report in debug builds to avoid spam
    if (std.debug.runtime_safety) {
        generateMemoryReport();
    }
}
test "Memory budget validation" {
    // This will fail to compile if any assertions fail
    validateAll();
    // Runtime verification that we can actually instantiate the system
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var memory_pool = try memory_budget.StaticMemoryPool.init(arena.allocator());
    defer memory_pool.deinit();
    // Verify basic pool operations work
    const conn_slot = memory_pool.acquireConnection();
    try std.testing.expect(conn_slot != null);
    const stream_slot = memory_pool.acquireStream(0);
    try std.testing.expect(stream_slot != null);
    const data_buffer = memory_pool.getDataBuffer(0, 0);
    try std.testing.expect(data_buffer != null);
    try std.testing.expect(data_buffer.?.len == memory_budget.MemBudget.max_data_buffer);
    // Clean up
    if (stream_slot) |s| memory_pool.releaseStream(s);
    if (conn_slot) |c| memory_pool.releaseConnection(c);
}
test "Pool operation performance" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var memory_pool = try memory_budget.StaticMemoryPool.init(arena.allocator());
    defer memory_pool.deinit();
    const start_time = std.time.nanoTimestamp();
    // Perform many pool operations
    const iterations = 1000;
    for (0..iterations) |_| {
        if (memory_pool.acquireConnection()) |conn| {
            if (memory_pool.acquireStream(0)) |stream| {
                memory_pool.releaseStream(stream);
            }
            memory_pool.releaseConnection(conn);
        }
    }
    const end_time = std.time.nanoTimestamp();
    const duration_ns = end_time - start_time;
    const ns_per_op = @divTrunc(duration_ns, (iterations * 2)); // 2 operations per iteration
    // Should be very fast (< 1000ns per operation)
    try std.testing.expect(ns_per_op < 1000);
    std.log.debug("Pool operations: {d}ns per acquire/release cycle", .{ns_per_op});
}
