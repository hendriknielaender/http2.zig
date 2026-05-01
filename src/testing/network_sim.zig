//! Deterministic byte-stream network simulator for HTTP/2 connections.
//!
//! Replaces real TCP with an in-memory network that supports configurable
//! one-way delay, random packet loss, bit-level corruption, network
//! partitions, and path clogging. All behaviour is driven by a single
//! seeded PRNG, making every simulation run perfectly reproducible.
//!
//! Each peer in the simulation is assigned a `SimPipe` that provides
//! `std.Io.Reader` and `std.Io.Writer` interfaces. These interfaces
//! are backed by the in-memory network so that the `Connection`
//! implementation sees the same API as real TCP.

const std = @import("std");
const assert = std.debug.assert;

const Io = std.Io;
const prng = @import("prng.zig");
const time_sim = @import("time_sim.zig");

const Self = @This();

const KiB = 1024;

/// Maximum bytes buffered per delivery queue direction.
pub const max_delivery_bytes = 256 * KiB;

/// Maximum bytes buffered per outgoing buffer.
pub const max_outgoing_bytes = 256 * KiB;

/// Maximum bytes in a SimPipe reader buffer.
pub const max_recv_bytes = 256 * KiB;

/// Maximum in-flight deliveries across all links.
pub const max_pending_deliveries = 256;

/// Configuration for a link between two peers.
pub const LinkConfig = struct {
    /// One-way delay in simulated nanoseconds added to every byte.
    one_way_delay_ns: u64 = std.time.ns_per_ms * 5,

    /// Probability (as a ratio) that a byte is dropped.
    drop_probability: prng.Ratio = prng.Ratio.zero(),

    /// Probability (as a ratio) that a byte is corrupted (bit flipped).
    corrupt_probability: prng.Ratio = prng.Ratio.zero(),

    /// Number of bytes delivered per tick from this link.
    bandwidth_bytes_per_tick: u32 = 65_536,

    /// True if the link is currently partitioned (blocked).
    partitioned: bool = false,

    /// Tick at which a temporary clog ends.
    clog_until_tick: u64 = 0,
};

/// Pending bytes waiting to traverse the network along one direction.
const DeliveryQueue = struct {
    bytes: [max_delivery_bytes]u8 = undefined,
    len: u32 = 0,
    consumed: u32 = 0,

    fn reset(self: *DeliveryQueue) void {
        self.len = 0;
        self.consumed = 0;
    }

    fn available(self: *const DeliveryQueue) u32 {
        return self.len - self.consumed;
    }

    fn append(self: *DeliveryQueue, data: []const u8) void {
        assert(self.len + data.len <= max_delivery_bytes);
        @memcpy(self.bytes[self.len..][0..data.len], data);
        self.len += @intCast(data.len);
    }

    fn compact(self: *DeliveryQueue) void {
        if (self.consumed > 0) {
            const remaining = self.available();
            std.mem.copyForwards(u8, self.bytes[0..remaining], self.bytes[self.consumed..][0..remaining]);
            self.len = remaining;
            self.consumed = 0;
        }
    }
};

/// Bytes written by a peer waiting to be sent through the network.
const OutgoingBuffer = struct {
    bytes: [max_outgoing_bytes]u8 = undefined,
    len: u32 = 0,

    fn reset(self: *OutgoingBuffer) void {
        self.len = 0;
    }

    fn consume(self: *OutgoingBuffer, count: u32) void {
        assert(count <= self.len);
        const remaining = self.len - count;
        std.mem.copyForwards(u8, self.bytes[0..remaining], self.bytes[count..][0..remaining]);
        self.len = remaining;
    }

    fn append(self: *OutgoingBuffer, data: []const u8) error{BufferOverflow}!void {
        if (self.len + data.len > max_outgoing_bytes) return error.BufferOverflow;
        @memcpy(self.bytes[self.len..][0..data.len], data);
        self.len += @intCast(data.len);
    }
};

/// A pending delivery with a tick deadline.
const PendingDelivery = struct {
    target_peer: u32,
    tick_due: u64,
    data: [max_delivery_bytes]u8 = undefined,
    data_len: u32,
};

/// Simulated network connecting multiple peers.
pub const NetworkSim = struct {
    /// Random number generator for this simulation.
    random: prng,

    /// Time source for delay calculations.
    time: time_sim.TimeSim,

    /// Per-peer delivery queues (incoming data from other peers).
    delivery_queues: []DeliveryQueue,

    /// Per-peer outgoing buffers (data written by each peer).
    outgoing_buffers: []OutgoingBuffer,

    /// Link configuration matrix: links[source][target].
    links: []LinkConfig,

    /// Number of peers in the network.
    peer_count: u32,

    /// Pending deliveries waiting for their tick_due.
    pending: std.ArrayListUnmanaged(PendingDelivery),

    /// Underlying allocator for the pending list and array allocations.
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        seed: u64,
        resolution_ns: u64,
        peer_count: u32,
    ) !NetworkSim {
        assert(peer_count > 0);
        assert(peer_count <= 256);

        const delivery_queues = try allocator.alloc(DeliveryQueue, peer_count);
        errdefer allocator.free(delivery_queues);

        const outgoing_buffers = try allocator.alloc(OutgoingBuffer, peer_count);
        errdefer allocator.free(outgoing_buffers);

        const links = try allocator.alloc(LinkConfig, @as(usize, peer_count) * peer_count);
        errdefer allocator.free(links);

        const pending = try std.ArrayListUnmanaged(PendingDelivery).initCapacity(
            allocator,
            max_pending_deliveries,
        );
        errdefer pending.deinit(allocator);

        for (delivery_queues) |*queue| {
            queue.* = .{};
        }
        for (outgoing_buffers) |*buf| {
            buf.* = .{};
        }
        @memset(links, .{});

        return .{
            .random = prng.init(seed),
            .time = time_sim.TimeSim.init(resolution_ns),
            .delivery_queues = delivery_queues,
            .outgoing_buffers = outgoing_buffers,
            .links = links,
            .peer_count = peer_count,
            .pending = pending,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NetworkSim) void {
        self.pending.deinit(self.allocator);
        self.allocator.free(self.links);
        self.allocator.free(self.outgoing_buffers);
        self.allocator.free(self.delivery_queues);
    }

    /// Advance the simulation by one tick.
    pub fn tick(self: *NetworkSim) void {
        self.collect_outgoing();
        self.deliver_ready_pending();
        self.time.tick();
    }

    /// Set the link configuration between two peers.
    pub fn set_link(self: *NetworkSim, source: u32, target: u32, config: LinkConfig) void {
        assert(source < self.peer_count);
        assert(target < self.peer_count);
        const index = @as(usize, source) * self.peer_count + target;
        self.links[index] = config;
    }

    /// Get a mutable reference to the link between two peers.
    pub fn get_link(self: *NetworkSim, source: u32, target: u32) *LinkConfig {
        assert(source < self.peer_count);
        assert(target < self.peer_count);
        const index = @as(usize, source) * self.peer_count + target;
        return &self.links[index];
    }

    /// Partition a peer: block all links to and from it.
    pub fn partition_peer(self: *NetworkSim, peer: u32) void {
        assert(peer < self.peer_count);
        var i: u32 = 0;
        while (i < self.peer_count) : (i += 1) {
            self.get_link(peer, i).partitioned = true;
            self.get_link(i, peer).partitioned = true;
        }
    }

    /// Heal all partitions.
    pub fn heal_partitions(self: *NetworkSim) void {
        for (self.links) |*link| {
            link.partitioned = false;
            link.clog_until_tick = 0;
        }
    }

    /// Number of bytes immediately available for reading on a peer's queue.
    pub fn available(self: *const NetworkSim, peer: u32) u32 {
        assert(peer < self.peer_count);
        return self.delivery_queues[peer].available();
    }

    /// Consume a slice of bytes from the peer's delivery queue.
    /// Returns the number of bytes actually consumed.
    pub fn consume(self: *NetworkSim, peer: u32, target: []u8) u32 {
        assert(peer < self.peer_count);
        const queue = &self.delivery_queues[peer];
        const to_consume = @min(@as(u32, @intCast(target.len)), queue.available());
        @memcpy(target[0..to_consume], queue.bytes[queue.consumed..][0..to_consume]);
        queue.consumed += to_consume;
        return to_consume;
    }

    /// Send bytes from one peer to one target peer through the configured link.
    pub fn send(
        self: *NetworkSim,
        source: u32,
        target: u32,
        data: []const u8,
    ) error{BufferOverflow}!void {
        assert(source < self.peer_count);
        assert(target < self.peer_count);
        assert(source != target);
        assert(data.len <= max_outgoing_bytes);

        self.schedule_delivery(source, target, data) catch |err| switch (err) {
            error.BufferOverflow => return error.BufferOverflow,
        };
    }

    /// Deliver bytes that have reached their tick deadline.
    fn deliver_ready_pending(self: *NetworkSim) void {
        var i: u32 = 0;
        while (i < self.pending.items.len) {
            const delivery = self.pending.items[i];
            if (delivery.tick_due <= self.time.ticks) {
                add_to_delivery_queue(self, delivery.target_peer, delivery.data[0..delivery.data_len]);
                _ = self.pending.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Collect outgoing bytes from all peers and push them through the network.
    fn collect_outgoing(self: *NetworkSim) void {
        var source: u32 = 0;
        while (source < self.peer_count) : (source += 1) {
            const outgoing = &self.outgoing_buffers[source];
            if (outgoing.len == 0) continue;

            const sent_len = @min(
                outgoing.len,
                minimum_link_bandwidth(self, source),
            );
            const data = outgoing.bytes[0..sent_len];

            var target: u32 = 0;
            while (target < self.peer_count) : (target += 1) {
                if (source == target) continue;
                self.schedule_delivery(source, target, data) catch continue;
            }

            outgoing.consume(@intCast(sent_len));
        }
    }

    fn minimum_link_bandwidth(self: *NetworkSim, source: u32) usize {
        var minimum: u32 = max_outgoing_bytes;
        var target: u32 = 0;
        while (target < self.peer_count) : (target += 1) {
            if (source == target) continue;
            minimum = @min(minimum, self.get_link(source, target).bandwidth_bytes_per_tick);
        }
        return minimum;
    }

    fn schedule_delivery(
        self: *NetworkSim,
        source: u32,
        target: u32,
        data: []const u8,
    ) error{BufferOverflow}!void {
        if (data.len > max_delivery_bytes) return error.BufferOverflow;

        const link = self.get_link(source, target);
        if (link.partitioned) return;
        if (link.clog_until_tick > self.time.ticks) return;

        var filtered_storage: [max_delivery_bytes]u8 = undefined;
        const filtered = apply_loss_and_corruption(
            self,
            link,
            data,
            &filtered_storage,
        );
        if (filtered.len == 0) return;

        const delay_ticks = delay_to_ticks(self, link);
        const tick_due = self.time.ticks + delay_ticks;
        try add_pending_delivery(self, target, tick_due, filtered);
    }

    /// Apply random packet loss and corruption to the byte stream.
    fn apply_loss_and_corruption(
        self: *NetworkSim,
        link: *const LinkConfig,
        data: []const u8,
        scratch: []u8,
    ) []const u8 {
        // Always deliver zero bytes as-is.
        if (data.len == 0) return data;
        assert(scratch.len >= @min(data.len, max_delivery_bytes));

        var write_pos: u32 = 0;

        for (data) |byte| {
            if (self.random.chance(link.drop_probability)) continue;

            var b = byte;
            if (self.random.chance(link.corrupt_probability)) {
                const bit_to_flip = @as(u8, 1) << @as(u3, @intCast(self.random.range_inclusive(u32, 0, 7)));
                b ^= bit_to_flip;
            }

            if (write_pos < max_delivery_bytes) {
                scratch[write_pos] = b;
                write_pos += 1;
            }
        }

        return scratch[0..write_pos];
    }

    /// Compute delay in ticks for a link.
    fn delay_to_ticks(self: *NetworkSim, link: *const LinkConfig) u64 {
        if (link.one_way_delay_ns == 0) return 0;
        const half_tick = self.time.resolution_ns / 2;
        return (link.one_way_delay_ns + half_tick) / self.time.resolution_ns;
    }

    /// Schedule a delivery to a peer at a future tick.
    fn add_pending_delivery(
        self: *NetworkSim,
        target: u32,
        tick_due: u64,
        data: []const u8,
    ) error{BufferOverflow}!void {
        assert(data.len <= max_delivery_bytes);
        if (self.pending.items.len == max_pending_deliveries) return error.BufferOverflow;

        var delivery: PendingDelivery = undefined;
        delivery.target_peer = target;
        delivery.tick_due = tick_due;
        @memcpy(delivery.data[0..data.len], data);
        delivery.data_len = @intCast(data.len);

        self.pending.appendAssumeCapacity(delivery);
    }
};

/// Append data to a peer's delivery queue, compacting if needed.
fn add_to_delivery_queue(network: *NetworkSim, peer: u32, data: []const u8) void {
    const queue = &network.delivery_queues[peer];
    queue.compact();

    assert(queue.len + data.len <= max_delivery_bytes);
    queue.append(data);
}

/// A bidirectional byte pipe between a peer and the simulated network.
///
/// Owns `std.Io.Reader` and `std.Io.Writer` interfaces that the
/// `Connection` code can use exactly like real TCP. The reader's
/// buffer is pre-filled from the network's delivery queue so that
/// `peek`, `take`, and `readSliceShort` operate on available data
/// without calling `stream()` on an empty buffer.
pub const SimPipe = struct {
    reader_interface: std.Io.Reader,
    writer_interface: std.Io.Writer,

    /// Storage for the reader's internal buffer.
    reader_buffer: [max_recv_bytes]u8 = undefined,

    network: *NetworkSim,
    peer_index: u32,

    pub fn init(network: *NetworkSim, peer_index: u32) SimPipe {
        assert(peer_index < network.peer_count);

        var pipe = SimPipe{
            .reader_interface = undefined,
            .writer_interface = undefined,
            .network = network,
            .peer_index = peer_index,
        };

        // Reader uses fixed-buffer semantics: data is pre-loaded into the
        // buffer before every network tick so that the connection code's
        // `peek`/`take`/`readSliceShort` calls see available data directly.
        pipe.reader_interface = std.Io.Reader.fixed("");

        pipe.writer_interface = .{
            .vtable = &.{ .drain = drain },
            .buffer = &.{},
        };

        return pipe;
    }

    /// Get a mutable pointer to the reader interface.
    pub fn reader(self: *SimPipe) *std.Io.Reader {
        return &self.reader_interface;
    }

    /// Get a mutable pointer to the writer interface.
    pub fn writer(self: *SimPipe) *std.Io.Writer {
        return &self.writer_interface;
    }

    /// Copy bytes from the network delivery queue into the reader's buffer.
    /// Must be called before the connection reads, typically at the start
    /// of every tick after the network has delivered new data.
    pub fn refresh_reader(self: *SimPipe) void {
        const network = self.network;
        const peer = self.peer_index;

        const queue = &network.delivery_queues[peer];
        const available = queue.available();
        if (available == 0) {
            self.reader_interface = std.Io.Reader.fixed("");
            return;
        }

        assert(available <= max_recv_bytes);
        const data = queue.bytes[queue.consumed..][0..available];
        @memcpy(self.reader_buffer[0..available], data);
        queue.consumed += available;

        self.reader_interface = std.Io.Reader.fixed(self.reader_buffer[0..available]);
    }

    /// Enable the drain vtable function to find the SimPipe from the writer pointer.
    fn from_writer(w: *std.Io.Writer) *SimPipe {
        return @fieldParentPtr("writer_interface", w);
    }

    /// Vtable function: append bytes from the connection to the network's outgoing buffer.
    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const pipe = from_writer(w);
        const network = pipe.network;
        const peer = pipe.peer_index;

        const outgoing = &network.outgoing_buffers[peer];
        var total: u32 = 0;

        // Write all elements except the last once each.
        var ci: u32 = 0;
        while (ci < data.len -| 1) : (ci += 1) {
            const chunk = data[ci];
            outgoing.append(chunk) catch break;
            total += @intCast(chunk.len);
        }

        // Write the last element (pattern) `splat` times.
        if (data.len > 0) {
            const pattern = data[data.len - 1];
            var i: usize = 0;
            while (i < splat) : (i += 1) {
                outgoing.append(pattern) catch break;
            }
            total += @intCast(pattern.len * splat);
        }

        return total;
    }
};

// --- Tests ---

test "NetworkSim init and deinit" {
    var network = try NetworkSim.init(
        std.testing.allocator,
        42,
        std.time.ns_per_ms,
        2,
    );
    defer network.deinit();

    try std.testing.expectEqual(@as(u32, 2), network.peer_count);
    try std.testing.expectEqual(@as(u64, 0), network.time.ticks);
}

test "SimPipe reader and writer vtable lookup" {
    var network = try NetworkSim.init(
        std.testing.allocator,
        42,
        std.time.ns_per_ms,
        2,
    );
    defer network.deinit();

    var pipe = SimPipe.init(&network, 0);
    try std.testing.expect(pipe.reader() == &pipe.reader_interface);
    try std.testing.expect(pipe.writer() == &pipe.writer_interface);
}

test "bytes flow from writer through network to reader" {
    var network = try NetworkSim.init(
        std.testing.allocator,
        1,
        std.time.ns_per_ms,
        2,
    );
    defer network.deinit();

    // Set fast link.
    network.set_link(0, 1, .{ .one_way_delay_ns = 0 });

    var pipe_a = SimPipe.init(&network, 0);

    // Peer 0 writes data.
    try pipe_a.writer().writeAll("hello");

    // Tick to process outgoing.
    network.tick();

    // Peer 1 should have 5 bytes available.
    try std.testing.expectEqual(@as(u32, 5), network.available(1));

    // Read from peer 1's queue through the consume API.
    var read_buf: [16]u8 = undefined;
    const consumed = network.consume(1, &read_buf);
    try std.testing.expectEqual(@as(u32, 5), consumed);
    try std.testing.expectEqualStrings("hello", read_buf[0..5]);
}

test "one_way_delay defers delivery" {
    var network = try NetworkSim.init(
        std.testing.allocator,
        1,
        std.time.ns_per_ms,
        2,
    );
    defer network.deinit();

    // 10ms delay.
    network.set_link(0, 1, .{ .one_way_delay_ns = 10 * std.time.ns_per_ms });

    var pipe_a = SimPipe.init(&network, 0);
    try pipe_a.writer().writeAll("delayed");

    // Tick once - should not arrive yet (delay is 10 ticks).
    network.tick();
    try std.testing.expectEqual(@as(u32, 0), network.available(1));

    // Tick enough times to cross the delay threshold.
    var i: u32 = 0;
    while (i < 10) : (i += 1) network.tick();
    try std.testing.expectEqual(@as(u32, 7), network.available(1));
}

test "partition blocks delivery" {
    var network = try NetworkSim.init(
        std.testing.allocator,
        1,
        std.time.ns_per_ms,
        2,
    );
    defer network.deinit();

    network.set_link(0, 1, .{ .one_way_delay_ns = 0 });

    var pipe_a = SimPipe.init(&network, 0);

    // Partition peer 0 from peer 1.
    network.get_link(0, 1).partitioned = true;
    try pipe_a.writer().writeAll("blocked");

    network.tick();
    try std.testing.expectEqual(@as(u32, 0), network.available(1));

    // Heal the partition.
    network.get_link(0, 1).partitioned = false;
    try pipe_a.writer().writeAll("unblocked");

    network.tick();
    try std.testing.expectEqual(@as(u32, 9), network.available(1));
}

test "drop probability removes bytes" {
    const allocator = std.testing.allocator;
    var network = try NetworkSim.init(allocator, 1, std.time.ns_per_ms, 2);
    defer network.deinit();

    // 50% drop rate.
    network.set_link(0, 1, .{
        .one_way_delay_ns = 0,
        .drop_probability = prng.ratio(1, 2),
    });

    var pipe_a = SimPipe.init(&network, 0);

    // Write 1000 bytes.
    var buf: [1000]u8 = undefined;
    @memset(&buf, 0xAA);
    try pipe_a.writer().writeAll(&buf);

    network.tick();

    // Should have fewer than 1000 bytes (some dropped).
    const available = network.available(1);
    try std.testing.expect(available < 1000);
    try std.testing.expect(available >= 200);
}

test "corrupt probability flips bits" {
    const allocator = std.testing.allocator;
    var network = try NetworkSim.init(allocator, 1, std.time.ns_per_ms, 2);
    defer network.deinit();

    // 100% corruption - note: ratio(1,1) is 100%.
    network.set_link(0, 1, .{
        .one_way_delay_ns = 0,
        .corrupt_probability = prng.ratio(1, 1),
    });

    var pipe_a = SimPipe.init(&network, 0);
    try pipe_a.writer().writeAll("hello");

    network.tick();

    var read_buf: [5]u8 = undefined;
    _ = network.consume(1, &read_buf);
    // All bytes should be corrupted (different from original).
    try std.testing.expect(!std.mem.eql(u8, "hello", &read_buf));
}

test "multiple peers can exchange data" {
    const allocator = std.testing.allocator;
    var network = try NetworkSim.init(allocator, 1, std.time.ns_per_ms, 3);
    defer network.deinit();

    // Configure all relevant links with zero delay.
    network.set_link(0, 1, .{ .one_way_delay_ns = 0 });
    network.set_link(0, 2, .{ .one_way_delay_ns = 0 });
    network.set_link(1, 0, .{ .one_way_delay_ns = 0 });
    network.set_link(1, 2, .{ .one_way_delay_ns = 0 });

    var pipe_a = SimPipe.init(&network, 0);
    var pipe_b = SimPipe.init(&network, 1);

    try pipe_a.writer().writeAll("to_b");
    // Also write from peer 1 to peer 0.
    try pipe_b.writer().writeAll("to_a");

    network.tick();

    try std.testing.expectEqual(@as(u32, 4), network.available(0));
    try std.testing.expectEqual(@as(u32, 4), network.available(1));
    try std.testing.expectEqual(@as(u32, 8), network.available(2));
}

test "reader refresh loads data from delivery queue" {
    const allocator = std.testing.allocator;
    var network = try NetworkSim.init(allocator, 1, std.time.ns_per_ms, 2);
    defer network.deinit();

    network.set_link(0, 1, .{ .one_way_delay_ns = 0 });

    var pipe_a = SimPipe.init(&network, 0);
    var pipe_b = SimPipe.init(&network, 1);

    // Write from peer 0.
    try pipe_a.writer().writeAll("stream_test");

    network.tick();

    // Refresh peer 1's reader from the delivery queue.
    pipe_b.refresh_reader();

    // Read via the reader interface.
    var recv_buf: [16]u8 = undefined;
    const n = try pipe_b.reader().readSliceShort(&recv_buf);
    try std.testing.expectEqual(@as(usize, 11), n);
    try std.testing.expectEqualStrings("stream_test", recv_buf[0..n]);
}

test "deterministic output with same seed" {
    const allocator = std.testing.allocator;

    var net_a = try NetworkSim.init(allocator, 42, std.time.ns_per_ms, 2);
    defer net_a.deinit();
    var net_b = try NetworkSim.init(allocator, 42, std.time.ns_per_ms, 2);
    defer net_b.deinit();

    net_a.set_link(0, 1, .{
        .one_way_delay_ns = 0,
        .drop_probability = prng.ratio(1, 10),
    });
    net_b.set_link(0, 1, .{
        .one_way_delay_ns = 0,
        .drop_probability = prng.ratio(1, 10),
    });

    var pipe_a_a = SimPipe.init(&net_a, 0);
    var pipe_b_a = SimPipe.init(&net_b, 0);

    const data = [_]u8{0} ** 500;
    try pipe_a_a.writer().writeAll(&data);
    try pipe_b_a.writer().writeAll(&data);

    net_a.tick();
    net_b.tick();

    try std.testing.expectEqual(net_a.available(1), net_b.available(1));
}
