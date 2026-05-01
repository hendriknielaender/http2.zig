//! Bounded deterministic packet simulator for protocol-aware HTTP/2 tests.
//!
//! This complements the byte-stream simulator with a frame-level network. It is
//! intentionally small and explicit: all queues have fixed maximum sizes, all
//! faults are driven from one seeded PRNG, and packet delivery is tick-driven.

const std = @import("std");
const assert = std.debug.assert;

const prng = @import("prng.zig");

const Ratio = prng.Ratio;

pub const FrameType = enum(u8) {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9,
    PRIORITY_UPDATE = 0x10,
};

pub const max_nodes = 16;
pub const max_payload_bytes = 256;
pub const max_path_capacity = 8;
pub const max_inbox_capacity = 16;
pub const max_recorded_packets = 16;

pub const Options = struct {
    node_count: u8,
    seed: u64,
    one_way_delay_ticks: u32 = 1,
    packet_loss_probability: Ratio = Ratio.zero(),
    packet_replay_probability: Ratio = Ratio.zero(),
    partition_probability: Ratio = Ratio.zero(),
    unpartition_probability: Ratio = Ratio.zero(),
    partition_stability_ticks: u32 = 0,
    unpartition_stability_ticks: u32 = 0,
    path_capacity: u8 = 8,
    recorded_count_max: u8 = 0,
};

pub const Packet = struct {
    source: u8,
    target: u8,
    frame_type: FrameType,
    flags: u8,
    stream_id: u32,
    tick_due: u64 = 0,
    payload_len: u16 = 0,
    payload: [max_payload_bytes]u8 = undefined,

    pub fn init(
        source: u8,
        target: u8,
        frame_type: FrameType,
        flags: u8,
        stream_id: u32,
        payload: []const u8,
    ) Packet {
        assert(payload.len <= max_payload_bytes);

        var packet: Packet = .{
            .source = source,
            .target = target,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = stream_id,
            .payload_len = @intCast(payload.len),
        };
        @memcpy(packet.payload[0..payload.len], payload);
        return packet;
    }

    pub fn payload_slice(self: *const Packet) []const u8 {
        return self.payload[0..self.payload_len];
    }
};

const Link = struct {
    queue: [max_path_capacity]Packet = undefined,
    queue_len: u8 = 0,
    partitioned: bool = false,
    clog_until_tick: u64 = 0,
    drop_frame_type: ?FrameType = null,
    delay_frame_type: ?FrameType = null,
    delay_frame_extra_ticks: u32 = 0,

    fn enqueue(self: *Link, packet: Packet, capacity: u8) error{PathFull}!void {
        assert(capacity <= max_path_capacity);
        if (self.queue_len == capacity) return error.PathFull;
        self.queue[self.queue_len] = packet;
        self.queue_len += 1;
    }

    fn swap_remove(self: *Link, index: u8) Packet {
        assert(index < self.queue_len);
        const packet = self.queue[index];
        self.queue_len -= 1;
        if (index != self.queue_len) {
            self.queue[index] = self.queue[self.queue_len];
        }
        return packet;
    }
};

const Inbox = struct {
    packets: [max_inbox_capacity]Packet = undefined,
    len: u8 = 0,

    fn push(self: *Inbox, packet: Packet) error{InboxFull}!void {
        if (self.len == max_inbox_capacity) return error.InboxFull;
        self.packets[self.len] = packet;
        self.len += 1;
    }

    fn pop(self: *Inbox) ?Packet {
        if (self.len == 0) return null;
        const packet = self.packets[0];
        self.len -= 1;
        std.mem.copyForwards(Packet, self.packets[0..self.len], self.packets[1..][0..self.len]);
        return packet;
    }
};

pub const Metrics = struct {
    sent: u64 = 0,
    delivered: u64 = 0,
    dropped: u64 = 0,
    replayed: u64 = 0,
    partitioned: u64 = 0,
    path_full: u64 = 0,
    inbox_full: u64 = 0,
};

pub const PacketSimulator = struct {
    options: Options,
    random: prng,
    tick_current: u64 = 0,
    links: [max_nodes * max_nodes]Link = undefined,
    inboxes: [max_nodes]Inbox = undefined,
    auto_partition: [max_nodes]bool = undefined,
    auto_partition_active: bool = false,
    auto_partition_stability: u32 = 0,
    recorded: [max_recorded_packets]Packet = undefined,
    recorded_len: u8 = 0,
    metrics: Metrics = .{},

    pub fn init(options: Options) PacketSimulator {
        assert(options.node_count > 0);
        assert(options.node_count <= max_nodes);
        assert(options.path_capacity > 0);
        assert(options.path_capacity <= max_path_capacity);
        assert(options.recorded_count_max <= max_recorded_packets);

        var simulator: PacketSimulator = .{
            .options = options,
            .random = prng.init(options.seed),
        };

        for (&simulator.links) |*link_state| link_state.* = .{};
        for (&simulator.inboxes) |*inbox| inbox.* = .{};
        @memset(&simulator.auto_partition, false);
        simulator.auto_partition_stability = options.unpartition_stability_ticks;
        return simulator;
    }

    pub fn send(self: *PacketSimulator, packet_in: Packet) void {
        assert(packet_in.source < self.options.node_count);
        assert(packet_in.target < self.options.node_count);
        assert(packet_in.source != packet_in.target);

        var packet = packet_in;
        packet.tick_due = self.tick_current + self.options.one_way_delay_ticks;

        const link_state = self.link(packet.source, packet.target);
        if (link_state.partitioned or link_state.clog_until_tick > self.tick_current) {
            self.metrics.partitioned += 1;
            return;
        }
        if (link_state.drop_frame_type) |frame_type| {
            if (frame_type == packet.frame_type) {
                self.metrics.dropped += 1;
                return;
            }
        }
        if (link_state.delay_frame_type) |frame_type| {
            if (frame_type == packet.frame_type) {
                packet.tick_due += link_state.delay_frame_extra_ticks;
            }
        }
        if (self.random.chance(self.options.packet_loss_probability)) {
            self.metrics.dropped += 1;
            return;
        }

        link_state.enqueue(packet, self.options.path_capacity) catch {
            self.metrics.path_full += 1;
            return;
        };
        self.metrics.sent += 1;

        if (self.recorded_len < self.options.recorded_count_max) {
            self.recorded[self.recorded_len] = packet;
            self.recorded_len += 1;
        }
    }

    pub fn tick(self: *PacketSimulator) void {
        self.tick_partitions();
        self.deliver_ready_packets();
        self.tick_current += 1;
    }

    pub fn receive(self: *PacketSimulator, node: u8) ?Packet {
        assert(node < self.options.node_count);
        return self.inboxes[node].pop();
    }

    pub fn link_drop_frame_type(
        self: *PacketSimulator,
        source: u8,
        target: u8,
        frame_type: ?FrameType,
    ) void {
        self.link(source, target).drop_frame_type = frame_type;
    }

    pub fn link_delay_frame_type(
        self: *PacketSimulator,
        source: u8,
        target: u8,
        frame_type: ?FrameType,
        extra_ticks: u32,
    ) void {
        const link_state = self.link(source, target);
        link_state.delay_frame_type = frame_type;
        link_state.delay_frame_extra_ticks = extra_ticks;
    }

    pub fn clog_path(
        self: *PacketSimulator,
        source: u8,
        target: u8,
        duration_ticks: u32,
    ) void {
        self.link(source, target).clog_until_tick = self.tick_current + duration_ticks;
    }

    pub fn partition_path(self: *PacketSimulator, source: u8, target: u8) void {
        self.link(source, target).partitioned = true;
    }

    pub fn heal_path(self: *PacketSimulator, source: u8, target: u8) void {
        const link_state = self.link(source, target);
        link_state.partitioned = false;
        link_state.clog_until_tick = 0;
    }

    pub fn partition_node(self: *PacketSimulator, node: u8) void {
        assert(node < self.options.node_count);
        var other: u8 = 0;
        while (other < self.options.node_count) : (other += 1) {
            self.link(node, other).partitioned = true;
            self.link(other, node).partitioned = true;
        }
    }

    pub fn heal(self: *PacketSimulator) void {
        for (&self.links) |*link_state| {
            link_state.partitioned = false;
            link_state.clog_until_tick = 0;
        }
        @memset(&self.auto_partition, false);
        self.auto_partition_active = false;
    }

    pub fn replay_recorded(self: *PacketSimulator) void {
        var index: u8 = 0;
        while (index < self.recorded_len) : (index += 1) {
            self.send(self.recorded[index]);
            self.metrics.replayed += 1;
        }
    }

    fn link(self: *PacketSimulator, source: u8, target: u8) *Link {
        assert(source < self.options.node_count);
        assert(target < self.options.node_count);
        return &self.links[@as(usize, source) * max_nodes + target];
    }

    fn tick_partitions(self: *PacketSimulator) void {
        if (self.options.partition_probability.numerator == 0 and
            self.options.unpartition_probability.numerator == 0)
        {
            return;
        }

        if (self.auto_partition_stability > 0) {
            self.auto_partition_stability -= 1;
            return;
        }

        if (self.auto_partition_active) {
            if (!self.random.chance(self.options.unpartition_probability)) return;
            self.heal();
            self.auto_partition_stability = self.options.unpartition_stability_ticks;
            return;
        }

        if (!self.random.chance(self.options.partition_probability)) return;
        const isolated = @as(u8, @intCast(self.random.index(self.auto_partition[0..self.options.node_count])));
        self.partition_node(isolated);
        self.auto_partition[isolated] = true;
        self.auto_partition_active = true;
        self.auto_partition_stability = self.options.partition_stability_ticks;
    }

    fn deliver_ready_packets(self: *PacketSimulator) void {
        var source: u8 = 0;
        while (source < self.options.node_count) : (source += 1) {
            var target: u8 = 0;
            while (target < self.options.node_count) : (target += 1) {
                if (source == target) continue;
                self.deliver_ready_link(source, target);
            }
        }
    }

    fn deliver_ready_link(self: *PacketSimulator, source: u8, target: u8) void {
        const link_state = self.link(source, target);
        var index: u8 = 0;
        while (index < link_state.queue_len) {
            if (link_state.queue[index].tick_due > self.tick_current) {
                index += 1;
                continue;
            }

            const packet = link_state.swap_remove(index);
            self.inboxes[target].push(packet) catch {
                self.metrics.inbox_full += 1;
                continue;
            };
            self.metrics.delivered += 1;

            if (self.random.chance(self.options.packet_replay_probability)) {
                var replay = packet;
                replay.tick_due = self.tick_current + self.options.one_way_delay_ticks;
                link_state.enqueue(replay, self.options.path_capacity) catch {
                    self.metrics.path_full += 1;
                    continue;
                };
                self.metrics.replayed += 1;
            }
        }
    }
};

test "PacketSimulator delivers deterministically" {
    var a = PacketSimulator.init(.{ .node_count = 2, .seed = 7, .one_way_delay_ticks = 2 });
    var b = PacketSimulator.init(.{ .node_count = 2, .seed = 7, .one_way_delay_ticks = 2 });

    const packet = Packet.init(0, 1, .HEADERS, 5, 1, "abc");
    a.send(packet);
    b.send(packet);

    a.tick();
    b.tick();
    try std.testing.expect(a.receive(1) == null);
    try std.testing.expect(b.receive(1) == null);

    a.tick();
    b.tick();
    try std.testing.expect(a.receive(1) == null);
    try std.testing.expect(b.receive(1) == null);

    a.tick();
    b.tick();
    const packet_a = a.receive(1).?;
    const packet_b = b.receive(1).?;
    try std.testing.expectEqual(packet_a.frame_type, packet_b.frame_type);
    try std.testing.expectEqual(packet_a.stream_id, packet_b.stream_id);
    try std.testing.expectEqualStrings(packet_a.payload_slice(), packet_b.payload_slice());
}

test "PacketSimulator frame filter drops selected command" {
    var simulator = PacketSimulator.init(.{ .node_count = 2, .seed = 1, .one_way_delay_ticks = 0 });
    simulator.link_drop_frame_type(0, 1, .WINDOW_UPDATE);

    simulator.send(Packet.init(0, 1, .WINDOW_UPDATE, 0, 0, ""));
    simulator.send(Packet.init(0, 1, .PING, 0, 0, "12345678"));
    simulator.tick();

    const received = simulator.receive(1).?;
    try std.testing.expectEqual(FrameType.PING, received.frame_type);
    try std.testing.expect(simulator.receive(1) == null);
    try std.testing.expectEqual(@as(u64, 1), simulator.metrics.dropped);
}

test "PacketSimulator partition blocks delivery" {
    var simulator = PacketSimulator.init(.{ .node_count = 3, .seed = 1, .one_way_delay_ticks = 0 });
    simulator.partition_node(1);
    simulator.send(Packet.init(0, 1, .HEADERS, 0, 1, ""));
    simulator.send(Packet.init(0, 2, .HEADERS, 0, 3, ""));
    simulator.tick();

    try std.testing.expect(simulator.receive(1) == null);
    try std.testing.expect(simulator.receive(2) != null);
    try std.testing.expectEqual(@as(u64, 1), simulator.metrics.partitioned);
}

test "PacketSimulator frame filter delays selected command" {
    var simulator = PacketSimulator.init(.{ .node_count = 2, .seed = 1, .one_way_delay_ticks = 0 });
    simulator.link_delay_frame_type(0, 1, .HEADERS, 2);

    simulator.send(Packet.init(0, 1, .HEADERS, 0, 1, ""));
    simulator.send(Packet.init(0, 1, .PING, 0, 0, "12345678"));

    simulator.tick();
    const first = simulator.receive(1).?;
    try std.testing.expectEqual(FrameType.PING, first.frame_type);
    try std.testing.expect(simulator.receive(1) == null);

    simulator.tick();
    try std.testing.expect(simulator.receive(1) == null);

    simulator.tick();
    const delayed = simulator.receive(1).?;
    try std.testing.expectEqual(FrameType.HEADERS, delayed.frame_type);
}

test "PacketSimulator clogs and heals one path asymmetrically" {
    var simulator = PacketSimulator.init(.{ .node_count = 2, .seed = 1, .one_way_delay_ticks = 0 });
    simulator.clog_path(0, 1, 2);

    simulator.send(Packet.init(0, 1, .HEADERS, 0, 1, ""));
    simulator.send(Packet.init(1, 0, .HEADERS, 0, 3, ""));
    simulator.tick();

    try std.testing.expect(simulator.receive(1) == null);
    try std.testing.expect(simulator.receive(0) != null);
    try std.testing.expectEqual(@as(u64, 1), simulator.metrics.partitioned);

    simulator.tick();
    simulator.tick();
    simulator.send(Packet.init(0, 1, .HEADERS, 0, 5, ""));
    simulator.tick();
    try std.testing.expect(simulator.receive(1) != null);
}
