//! Cluster simulator that orchestrates the deterministic simulation testing
//! of multiple HTTP/2 connections over a simulated network.
//!
//! Wires together the network simulator, simulated pipes, and HTTP/2
//! connections into a single tick-driven loop. Each tick:
//! 1. Collects outgoing bytes from all connections.
//! 2. Delivers pending bytes through the network (with faults).
//! 3. Refreshes each connection's reader with newly delivered data.
//! 4. Optionally runs connection processing for one frame.
//!
//! The cluster is fully seeded and deterministic: given the same seed,
//! the same sequence of operations produces identical results.

const std = @import("std");
const assert = std.debug.assert;

const network_sim = @import("network_sim.zig");
const prng = @import("prng.zig");
const time_sim = @import("time_sim.zig");

const NetworkSim = network_sim.NetworkSim;
const SimPipe = network_sim.SimPipe;
const LinkConfig = network_sim.LinkConfig;
const Ratio = prng.Ratio;

/// Maximum number of peers (connections) in a cluster.
pub const max_peers = 16;

/// Configuration for a cluster simulation.
pub const ClusterConfig = struct {
    /// Seed for the PRNG. Determines all random behaviour.
    seed: u64,

    /// Number of simulated nanoseconds per tick.
    tick_resolution_ns: u64 = std.time.ns_per_ms,

    /// Number of peer connections in the cluster.
    peer_count: u32 = 2,
};

pub const Failure = enum {
    correctness,
    liveness,
    performance,
};

pub const ClusterChecker = struct {
    ticks: u64 = 0,
    bytes_injected: u64 = 0,
    bytes_extracted: u64 = 0,
    partitioned_links: u32 = 0,

    fn onTick(self: *ClusterChecker, cluster: *const ClusterSim) void {
        self.ticks += 1;
        assert(self.ticks == cluster.ticks);
        assert(cluster.peer_count > 0);
        assert(cluster.peer_count <= max_peers);
    }

    fn onInject(self: *ClusterChecker, bytes: usize) void {
        self.bytes_injected += bytes;
    }

    fn onExtract(self: *ClusterChecker, bytes: u32) void {
        self.bytes_extracted += bytes;
        assert(self.bytes_extracted <= self.bytes_injected * (max_peers - 1));
    }

    fn onSetLink(config: LinkConfig) void {
        assert(config.drop_probability.numerator <= config.drop_probability.denominator);
        assert(config.corrupt_probability.numerator <= config.corrupt_probability.denominator);
    }
};

/// A cluster of simulated HTTP/2 peers connected through a deterministic network.
pub const ClusterSim = struct {
    /// The underlying simulated network.
    network: *NetworkSim,

    /// Simulated pipes, allocated on the heap to avoid stack overflow.
    pipes: []SimPipe,

    /// Random number generator for the cluster itself.
    random: prng,

    /// Simulated time source.
    time: time_sim.TimeSim,

    /// Number of active peers.
    peer_count: u32,

    /// Ticks elapsed since initialisation.
    ticks: u64 = 0,

    /// Deterministic correctness and accounting checks.
    checker: ClusterChecker = .{},

    /// Underlying allocator.
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: ClusterConfig) !ClusterSim {
        assert(config.peer_count > 0);
        assert(config.peer_count <= max_peers);

        const network = try allocator.create(NetworkSim);
        errdefer allocator.destroy(network);

        network.* = try NetworkSim.init(
            allocator,
            config.seed,
            config.tick_resolution_ns,
            config.peer_count,
        );
        errdefer network.deinit();

        const pipes = try allocator.alloc(SimPipe, config.peer_count);
        errdefer allocator.free(pipes);

        // Initialise all pipes to safe defaults before constructing the cluster.
        for (pipes) |*p| {
            p.* = SimPipe.init(network, 0);
        }

        var cluster = ClusterSim{
            .network = network,
            .pipes = pipes,
            .random = prng.init(config.seed +% 0xDEADBEEF),
            .time = time_sim.TimeSim.init(config.tick_resolution_ns),
            .peer_count = config.peer_count,
            .checker = .{},
            .allocator = allocator,
        };

        // Re-initialise pipes with correct peer indices now that cluster exists.
        for (0..config.peer_count) |i| {
            cluster.pipes[i] = SimPipe.init(network, @intCast(i));
        }

        return cluster;
    }

    pub fn deinit(self: *ClusterSim) void {
        self.allocator.free(self.pipes);
        self.network.deinit();
        self.allocator.destroy(self.network);
    }

    /// Advance the simulation by one tick.
    pub fn tick(self: *ClusterSim) void {
        self.network.tick();
        self.refresh_readers();
        self.ticks += 1;
        self.time.tick();
        self.checker.onTick(self);
    }

    /// Advance by `count` ticks.
    pub fn tick_many(self: *ClusterSim, count: u32) void {
        var i: u32 = 0;
        while (i < count) : (i += 1) self.tick();
    }

    /// Get the SimPipe for a peer.
    pub fn pipe(self: *ClusterSim, peer: u32) *SimPipe {
        assert(peer < self.peer_count);
        return &self.pipes[peer];
    }

    /// Get the reader interface for a peer.
    pub fn reader(self: *ClusterSim, peer: u32) *std.Io.Reader {
        return self.pipe(peer).reader();
    }

    /// Get the writer interface for a peer.
    pub fn writer(self: *ClusterSim, peer: u32) *std.Io.Writer {
        return self.pipe(peer).writer();
    }

    /// Write bytes as if from a client to a server peer.
    /// The caller must call `tick()` afterwards to propagate the data.
    pub fn inject_bytes(self: *ClusterSim, source: u32, data: []const u8) !void {
        assert(source < self.peer_count);
        try self.pipe(source).writer().writeAll(data);
        self.checker.onInject(data.len);
    }

    /// Write bytes from one peer to one target peer through the simulated link.
    pub fn inject_bytes_to(
        self: *ClusterSim,
        source: u32,
        target: u32,
        data: []const u8,
    ) !void {
        assert(source < self.peer_count);
        assert(target < self.peer_count);
        try self.network.send(source, target, data);
        self.checker.onInject(data.len);
    }

    /// Read available bytes from a peer's reader.
    pub fn extract_bytes(self: *ClusterSim, peer: u32, buffer: []u8) !u32 {
        assert(peer < self.peer_count);
        const n = try self.reader(peer).readSliceShort(buffer);
        self.checker.onExtract(@intCast(n));
        return @intCast(n);
    }

    /// Check how many bytes are available in a peer's reader.
    pub fn available(self: *ClusterSim, peer: u32) u32 {
        assert(peer < self.peer_count);
        return @intCast(self.reader(peer).bufferedLen());
    }

    /// Set the link configuration between two peers.
    pub fn set_link(self: *ClusterSim, source: u32, target: u32, config: LinkConfig) void {
        ClusterChecker.onSetLink(config);
        self.network.set_link(source, target, config);
    }

    /// Partition a peer from the network.
    pub fn partition_peer(self: *ClusterSim, peer: u32) void {
        self.network.partition_peer(peer);
    }

    /// Heal all network partitions.
    pub fn heal_partitions(self: *ClusterSim) void {
        self.network.heal_partitions();
    }

    /// Refresh all readers from the network delivery queues.
    fn refresh_readers(self: *ClusterSim) void {
        var i: u32 = 0;
        while (i < self.peer_count) : (i += 1) {
            self.pipes[i].refresh_reader();
        }
    }
};

// --- Tests ---

test "ClusterSim init and deinit" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 42, .peer_count = 2 },
    );
    defer cluster.deinit();

    try std.testing.expectEqual(@as(u32, 2), cluster.peer_count);
    try std.testing.expectEqual(@as(u64, 0), cluster.ticks);
}

test "ClusterSim tick advances ticks" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 42, .peer_count = 2 },
    );
    defer cluster.deinit();

    cluster.tick();
    try std.testing.expectEqual(@as(u64, 1), cluster.ticks);

    cluster.tick_many(9);
    try std.testing.expectEqual(@as(u64, 10), cluster.ticks);
}

test "inject_bytes delivers data to target" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 1, .peer_count = 2 },
    );
    defer cluster.deinit();

    // Configure zero-delay link.
    cluster.set_link(0, 1, .{ .one_way_delay_ns = 0 });

    // Send "hello" from peer 0.
    try cluster.inject_bytes(0, "hello");
    cluster.tick();

    // Peer 1 should have 5 bytes available.
    try std.testing.expectEqual(@as(u32, 5), cluster.available(1));

    var buf: [16]u8 = undefined;
    const n = try cluster.extract_bytes(1, &buf);
    try std.testing.expectEqual(@as(u32, 5), n);
    try std.testing.expectEqualStrings("hello", buf[0..5]);
}

test "inject_bytes_to delivers only to target" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 1, .peer_count = 3 },
    );
    defer cluster.deinit();

    cluster.set_link(0, 1, .{ .one_way_delay_ns = 0 });
    cluster.set_link(0, 2, .{ .one_way_delay_ns = 0 });

    try cluster.inject_bytes_to(0, 1, "hello");
    cluster.tick();

    try std.testing.expectEqual(@as(u32, 5), cluster.available(1));
    try std.testing.expectEqual(@as(u32, 0), cluster.available(2));
}

test "inject_bytes with delay" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 1, .peer_count = 2 },
    );
    defer cluster.deinit();

    // Set 5 tick delay between peer 0 and 1.
    cluster.set_link(0, 1, .{ .one_way_delay_ns = 5 * std.time.ns_per_ms });

    try cluster.inject_bytes(0, "delayed");
    cluster.tick();

    // Should not have arrived yet.
    try std.testing.expectEqual(@as(u32, 0), cluster.available(1));

    // Wait enough ticks for delay.
    cluster.tick_many(5);

    // Now it should be available.
    const available = cluster.available(1);
    try std.testing.expect(available > 0);
}

test "partition blocks data flow" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 1, .peer_count = 2 },
    );
    defer cluster.deinit();

    cluster.set_link(0, 1, .{ .one_way_delay_ns = 0 });
    cluster.partition_peer(0);

    try cluster.inject_bytes(0, "blocked");
    cluster.tick();

    // Data should not have arrived due to partition.
    try std.testing.expectEqual(@as(u32, 0), cluster.available(1));

    cluster.heal_partitions();
    try cluster.inject_bytes(0, "passed");
    cluster.tick();

    // Data should now flow.
    try std.testing.expect(cluster.available(1) > 0);
}

test "multiple peers can communicate" {
    var cluster = try ClusterSim.init(
        std.testing.allocator,
        .{ .seed = 1, .peer_count = 3 },
    );
    defer cluster.deinit();

    // Set up links with zero delay.
    cluster.set_link(0, 1, .{ .one_way_delay_ns = 0 });
    cluster.set_link(0, 2, .{ .one_way_delay_ns = 0 });
    cluster.set_link(1, 0, .{ .one_way_delay_ns = 0 });
    cluster.set_link(1, 2, .{ .one_way_delay_ns = 0 });

    // Peer 0 sends to peer 1.
    try cluster.inject_bytes(0, "from_0");
    cluster.tick();
    try std.testing.expect(cluster.available(1) > 0);

    // Peer 1 sends to peer 0.
    try cluster.inject_bytes(1, "from_1");
    cluster.tick();
    try std.testing.expect(cluster.available(0) > 0);

    // Peer 2 receives broadcasts from both.
    try cluster.inject_bytes(0, "to_2");
    cluster.tick();
    try std.testing.expect(cluster.available(2) > 0);
}

test "deterministic replay" {
    const allocator = std.testing.allocator;
    var cluster_a = try ClusterSim.init(allocator, .{ .seed = 99, .peer_count = 2 });
    defer cluster_a.deinit();
    var cluster_b = try ClusterSim.init(allocator, .{ .seed = 99, .peer_count = 2 });
    defer cluster_b.deinit();

    cluster_a.set_link(0, 1, .{ .one_way_delay_ns = 0 });
    cluster_b.set_link(0, 1, .{ .one_way_delay_ns = 0 });

    // Same sequence should produce identical results.
    try cluster_a.inject_bytes(0, "test_data");
    cluster_a.tick();
    try cluster_b.inject_bytes(0, "test_data");
    cluster_b.tick();

    try std.testing.expectEqual(cluster_a.available(1), cluster_b.available(1));
    try std.testing.expectEqual(cluster_a.ticks, cluster_b.ticks);
}
