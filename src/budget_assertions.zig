//! Compile-time validation that the memory budget is correctly configured.
//!
//! Every assertion in this module runs at comptime so that a misconfigured
//! budget fails the build before any test or deployment can run.
const std = @import("std");
const memory_budget = @import("memory_budget.zig");
const MemBudget = memory_budget.MemBudget;

/// Validate resource counts are non-zero and within reasonable ceilings.
fn validateCounts() void {
    comptime {
        if (MemBudget.max_connections == 0) {
            @compileError("max_connections cannot be zero");
        }
        if (MemBudget.max_streams_per_connection == 0) {
            @compileError("max_streams_per_connection cannot be zero");
        }
        if (MemBudget.worker_count == 0) {
            @compileError("worker_count cannot be zero");
        }

        const max_reasonable_workers = 128;
        if (MemBudget.worker_count > max_reasonable_workers) {
            @compileError(std.fmt.comptimePrint(
                "Worker count too high: {d} > {d}",
                .{ MemBudget.worker_count, max_reasonable_workers },
            ));
        }

        // The budget ceiling for max_connections must match the server
        // Config default so that budget calculations and deployed code
        // refer to the same capacity.
        const server_default_max_connections = 1000;
        if (MemBudget.max_connections > server_default_max_connections) {
            @compileError(std.fmt.comptimePrint(
                "max_connections in budget ({d}) exceeds server Config" ++ " default ({d})",
                .{ MemBudget.max_connections, server_default_max_connections },
            ));
        }
    }
}

/// Validate total memory requirements against system limits.
fn validateTotalMemory() void {
    comptime {
        const system_memory_limit = 8 * memory_budget.GiB;
        if (MemBudget.total_required_bytes > system_memory_limit) {
            @compileError(std.fmt.comptimePrint(
                "Memory budget exceeds system limit: {d}MB required" ++ " > {d}MB available",
                .{ MemBudget.total_required_bytes / memory_budget.MiB, system_memory_limit / memory_budget.MiB },
            ));
        }

        const total_streams = MemBudget.max_connections *
            MemBudget.max_streams_per_connection;
        if (total_streams > 10_000_000) {
            @compileError(std.fmt.comptimePrint(
                "Total stream capacity too high: {d} > 10M",
                .{total_streams},
            ));
        }

        // Connection memory should dominate the total budget;
        // server overhead and worker memory are ancillary.
        const conn_ratio = (MemBudget.connection_memory_bytes * 100) /
            MemBudget.total_required_bytes;
        if (conn_ratio < 80) {
            @compileError(std.fmt.comptimePrint(
                "Connection memory proportion too low: {d}%",
                .{conn_ratio},
            ));
        }
    }
}

/// Validate per-connection slot and stream storage sizing.
fn validatePerConnectionSizing() void {
    comptime {
        const max_memory_per_connection = 64 * memory_budget.MiB;
        if (MemBudget.connection_slot_bytes > max_memory_per_connection) {
            @compileError(std.fmt.comptimePrint(
                "Memory per connection too high: {d}MB > {d}MB limit",
                .{ MemBudget.connection_slot_bytes / memory_budget.MiB, max_memory_per_connection / memory_budget.MiB },
            ));
        }

        // Stream storage must dominate the connection slot.
        // If overhead dwarfs payload storage the budget is misconfigured.
        const stream_ratio = (MemBudget.stream_storage_bytes * 100) /
            MemBudget.connection_slot_bytes;
        if (stream_ratio < 80) {
            @compileError(std.fmt.comptimePrint(
                "Stream storage proportion too low: {d}% of connection slot",
                .{stream_ratio},
            ));
        }
    }
}

/// Validate HTTP/2 protocol constants embedded in the budget.
fn validateProtocolConstants() void {
    comptime {
        const http2_max_frame_size = 16 * memory_budget.MiB;
        if (MemBudget.max_frame_size_bytes > http2_max_frame_size) {
            @compileError(std.fmt.comptimePrint(
                "Max frame size exceeds HTTP/2 limit: {d} > {d}",
                .{ MemBudget.max_frame_size_bytes, http2_max_frame_size },
            ));
        }
        // RFC 7540 §4.2: frame payload minimum is 16384.
        if (MemBudget.max_frame_size_bytes < 16384) {
            @compileError(std.fmt.comptimePrint(
                "Max frame size below HTTP/2 minimum: {d} < 16384",
                .{MemBudget.max_frame_size_bytes},
            ));
        }

        const max_window_size = 2147483647;
        if (MemBudget.bytes_per_connection > max_window_size) {
            @compileError("Connection window size exceeds HTTP/2 limit");
        }
    }
}

/// Validate platform requirements.
fn validatePlatform() void {
    comptime {
        if (@sizeOf(usize) < 8) {
            @compileError("64-bit platform required");
        }

        // Runtime safety (debug builds) inflates memory usage; verify the
        // inflated budget still fits within system limits.
        if (std.debug.runtime_safety) {
            const debug_overhead_factor = 120;
            const debug_total = (MemBudget.total_required_bytes *
                debug_overhead_factor) / 100;
            const system_memory_limit = 8 * memory_budget.GiB;
            if (debug_total > system_memory_limit) {
                @compileError(std.fmt.comptimePrint(
                    "Debug build exceeds system limit: {d}MB > {d}MB",
                    .{ debug_total / memory_budget.MiB, system_memory_limit / memory_budget.MiB },
                ));
            }
        }
    }
}

/// Validate buffer alignment and sizing.
fn validateBufferLayout() void {
    comptime {
        const min_partition_size_bytes = 4096;
        const data_partitions = 4;
        if (MemBudget.max_data_buffer_bytes <
            (min_partition_size_bytes * data_partitions))
        {
            @compileError("Data buffer too small for partitioning");
        }
        if (MemBudget.max_data_buffer_bytes % 64 != 0) {
            @compileError("Data buffer size must be 64-byte aligned");
        }
        if (MemBudget.max_header_size_bytes % 64 != 0) {
            @compileError("Header buffer size must be 64-byte aligned");
        }
    }
}

/// Run every budget validation at comptime.
pub fn validateAll() void {
    comptime {
        validateCounts();
        validateTotalMemory();
        validatePerConnectionSizing();
        validateProtocolConstants();
        validatePlatform();
        validateBufferLayout();
    }
}

test "Memory budget validation passes at comptime" {
    validateAll();
}

test "Memory budget constants are non-zero and within limits" {
    try std.testing.expect(MemBudget.total_required_bytes > 0);
    try std.testing.expect(MemBudget.total_required_bytes < 8 * memory_budget.GiB);
    try std.testing.expect(MemBudget.worker_count > 0);
    try std.testing.expect(MemBudget.worker_count <= 128);

    const minimum_stream_bytes = MemBudget.stream_header_fragments_bytes +
        MemBudget.stream_request_body_bytes;
    try std.testing.expect(
        MemBudget.stream_instance_bytes >= minimum_stream_bytes,
    );
}
