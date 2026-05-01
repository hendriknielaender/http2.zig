//! Deterministic HTTP/2 cluster simulator.
//!
//! This is the bridge between the protocol-aware single-connection simulator
//! and a TigerBeetle-style cluster harness: peers own real `Connection` state,
//! frames move through a bounded packet simulator, ticks are fixed, and the
//! checker is protocol-aware enough to catch stream/accounting violations.

const std = @import("std");
const assert = std.debug.assert;

pub const std_options: std.Options = .{
    .log_level = .err,
};

const connection_mod = @import("connection.zig");
const frame_mod = @import("frame.zig");
const handler = @import("handler.zig");
const hpack_mod = @import("hpack.zig");
const memory_budget = @import("memory_budget.zig");
const packet_sim = @import("testing/packet_simulator.zig");
const prng_mod = @import("testing/prng.zig");

const Connection = connection_mod.Connection;
const Frame = frame_mod.Frame;
const FrameFlags = frame_mod.FrameFlags;
const FrameType = frame_mod.FrameType;
const Hpack = hpack_mod.Hpack;
const Packet = packet_sim.Packet;
const PacketSimulator = packet_sim.PacketSimulator;
const Prng = prng_mod;

const max_peers = 4;
const max_ticks_default = 128;
const max_work_per_peer_per_tick = 4;
const writer_capacity = 512 * 1024;
const max_payload_size = packet_sim.max_payload_bytes;
const max_reset_streams_tracked = 128;
const max_tracked_streams = 256;

pub const Role = enum {
    client,
    server,
};

pub const Options = struct {
    seed: u64 = 1,
    ticks: u64 = max_ticks_default,
    client_count: u8 = 1,
    server_count: u8 = 1,
    request_probability: Prng.Ratio = Prng.ratio(1, 1),
    network: packet_sim.Options = .{
        .node_count = 2,
        .seed = 1,
        .one_way_delay_ticks = 1,
        .path_capacity = 8,
    },

    fn nodeCount(self: Options) u8 {
        return self.client_count + self.server_count;
    }
};

pub const Metrics = struct {
    seed: u64,
    ticks: u64 = 0,
    requests_sent: u64 = 0,
    frames_delivered: u64 = 0,
    frames_collected: u64 = 0,
    protocol_errors: u64 = 0,
    completed_responses: u64 = 0,
    completed_client_responses: u64 = 0,
    digest: u64 = 0,

    fn finalizeDigest(self: *Metrics) void {
        var value: u64 = 0xcbf29ce484222325;
        value = digestMix(value, self.seed);
        value = digestMix(value, self.ticks);
        value = digestMix(value, self.requests_sent);
        value = digestMix(value, self.frames_delivered);
        value = digestMix(value, self.frames_collected);
        value = digestMix(value, self.protocol_errors);
        value = digestMix(value, self.completed_responses);
        value = digestMix(value, self.completed_client_responses);
        self.digest = value;
    }
};

const SimWriter = struct {
    interface: std.Io.Writer,
    storage: [writer_capacity]u8 = undefined,

    fn init() SimWriter {
        var self: SimWriter = undefined;
        self.interface = .fixed(&self.storage);
        return self;
    }

    fn written(self: *const SimWriter) []const u8 {
        return self.interface.buffered();
    }
};

pub const Http2Peer = struct {
    role: Role,
    reader: std.Io.Reader,
    writer: SimWriter,
    stream_storage: Connection.StreamStorage,
    connection: Connection,
    has_connection: bool = false,
    output_consumed: usize = 0,

    fn init(
        self: *Http2Peer,
        allocator: std.mem.Allocator,
        role: Role,
    ) !void {
        self.role = role;
        self.reader = .fixed("");
        self.writer = SimWriter.init();
        self.stream_storage = undefined;
        self.has_connection = role == .server;
        self.output_consumed = 0;

        if (role == .client) return;

        try Connection.initServerEventDrivenInPlace(
            &self.connection,
            &self.stream_storage,
            allocator,
            &self.reader,
            &self.writer.interface,
        );
        self.connection.bindRequestDispatcher(
            handler.RequestDispatcher.fromHandlerWithoutHeaders(clusterHandler),
        );
    }

    fn deinit(self: *Http2Peer) void {
        if (self.has_connection) {
            self.connection.deinit();
        }
    }
};

const StreamKey = struct {
    source: u8,
    target: u8,
    stream_id: u32,
};

const StreamRoute = struct {
    key: StreamKey,
    active: bool = true,
};

const ClientStreamOracle = struct {
    key: StreamKey,
    headers_seen: bool = false,
    remote_end_seen: bool = false,
    end_stream_seen: bool = false,
    data_bytes: u64 = 0,
};

const ClientOracle = struct {
    decoder_table: Hpack.DynamicTable,
    streams: [max_tracked_streams]ClientStreamOracle = undefined,
    stream_count: u32 = 0,
    completed_responses: u64 = 0,

    fn init(allocator: std.mem.Allocator) ClientOracle {
        return .{
            .decoder_table = Hpack.DynamicTable.init(allocator, 4096),
            .streams = undefined,
            .stream_count = 0,
            .completed_responses = 0,
        };
    }

    fn deinit(self: *ClientOracle) void {
        self.decoder_table.deinit();
    }

    fn onRequest(self: *ClientOracle, key: StreamKey) void {
        assert(self.stream_count < max_tracked_streams);
        self.streams[self.stream_count] = .{ .key = key };
        self.stream_count += 1;
    }

    fn onFrame(
        self: *ClientOracle,
        allocator: std.mem.Allocator,
        packet: *const Packet,
    ) !void {
        switch (packet.frame_type) {
            .HEADERS => {
                var stream = self.findStream(packet.source, packet.target, packet.stream_id);
                assert(!stream.headers_seen);
                try self.decodeHeaders(allocator, packet.payload_slice());
                stream.headers_seen = true;
                if ((packet.flags & FrameFlags.END_STREAM) != 0) {
                    stream.remote_end_seen = true;
                    self.completeIfReady(stream);
                }
            },
            .DATA => {
                const stream = self.findStream(packet.source, packet.target, packet.stream_id);
                stream.data_bytes += packet.payload_len;
                if ((packet.flags & FrameFlags.END_STREAM) != 0) {
                    stream.remote_end_seen = true;
                    self.completeIfReady(stream);
                }
            },
            .RST_STREAM => {
                const stream = self.findStream(packet.source, packet.target, packet.stream_id);
                stream.headers_seen = true;
                stream.remote_end_seen = true;
                self.completeIfReady(stream);
            },
            .GOAWAY, .PING, .SETTINGS, .WINDOW_UPDATE => {},
            else => {},
        }
    }

    fn decodeHeaders(
        self: *ClientOracle,
        allocator: std.mem.Allocator,
        payload: []const u8,
    ) !void {
        var cursor: usize = 0;
        var status_seen = false;
        while (cursor < payload.len) {
            var decoded = try Hpack.decodeHeaderField(payload[cursor..], &self.decoder_table, allocator);
            defer decoded.deinit();
            cursor += decoded.bytes_consumed;
            if (std.mem.eql(u8, decoded.header.name, ":status")) {
                status_seen = true;
            }
        }
        assert(status_seen);
    }

    fn findStream(
        self: *ClientOracle,
        server: u8,
        client: u8,
        stream_id: u32,
    ) *ClientStreamOracle {
        var index: u32 = 0;
        while (index < self.stream_count) : (index += 1) {
            const stream = &self.streams[index];
            if (stream.key.source == client and
                stream.key.target == server and
                stream.key.stream_id == stream_id)
            {
                return stream;
            }
        }
        unreachable;
    }

    fn completeIfReady(self: *ClientOracle, stream: *ClientStreamOracle) void {
        if (stream.end_stream_seen) return;
        if (!stream.headers_seen or !stream.remote_end_seen) return;
        stream.end_stream_seen = true;
        self.completed_responses += 1;
    }
};

const ClusterChecker = struct {
    highest_client_stream_id: [max_peers]u32 = [_]u32{0} ** max_peers,
    last_goaway_stream_id: [max_peers]u32 = [_]u32{0} ** max_peers,
    reset_streams: [max_reset_streams_tracked]StreamKey = undefined,
    reset_stream_count: u32 = 0,
    routes: [max_tracked_streams]StreamRoute = undefined,
    route_count: u32 = 0,
    requests_sent: u64 = 0,
    responses_completed: u64 = 0,

    fn onRequest(self: *ClusterChecker, client: u8, server: u8, stream_id: u32) void {
        assert(client < max_peers);
        assert(server < max_peers);
        assert(stream_id > 0);
        assert(stream_id & 1 == 1);
        assert(stream_id > self.highest_client_stream_id[client]);
        self.highest_client_stream_id[client] = stream_id;
        self.rememberRoute(.{ .source = client, .target = server, .stream_id = stream_id });
        self.requests_sent += 1;
    }

    fn onFrameDelivered(self: *const ClusterChecker, packet: *const Packet) void {
        assert(packet.source != packet.target);
        assert(packet.payload_len <= max_payload_size);
        switch (packet.frame_type) {
            .HEADERS => {
                assert(packet.stream_id > 0);
                assert(!self.wasReset(packet.source, packet.target, packet.stream_id));
            },
            .DATA => {
                assert(packet.stream_id > 0);
                assert(!self.wasReset(packet.source, packet.target, packet.stream_id));
            },
            .CONTINUATION => assert(packet.stream_id > 0),
            .GOAWAY => assert(packet.stream_id == 0),
            .SETTINGS => assert(packet.stream_id == 0),
            .PING => assert(packet.stream_id == 0),
            .WINDOW_UPDATE => {},
            else => {},
        }
    }

    fn onOutgoingFrame(
        self: *ClusterChecker,
        source: u8,
        target: u8,
        frame_type: FrameType,
        stream_id: u32,
        payload: []const u8,
    ) void {
        assert(source < max_peers);
        switch (frame_type) {
            .GOAWAY => {
                assert(stream_id == 0);
                assert(payload.len >= 8);
                const last_stream_id = (@as(u32, payload[0]) << 24) |
                    (@as(u32, payload[1]) << 16) |
                    (@as(u32, payload[2]) << 8) |
                    @as(u32, payload[3]);
                const normalized = last_stream_id & 0x7fffffff;
                assert(normalized >= self.last_goaway_stream_id[source]);
                self.last_goaway_stream_id[source] = normalized;
            },
            .RST_STREAM => {
                assert(stream_id > 0);
                self.rememberReset(.{ .source = source, .target = target, .stream_id = stream_id });
            },
            .HEADERS, .DATA => {
                assert(stream_id > 0);
                assert(!self.wasReset(source, target, stream_id));
            },
            .CONTINUATION => assert(stream_id > 0),
            .PING, .SETTINGS, .WINDOW_UPDATE => {},
            else => {},
        }
    }

    fn check(self: *ClusterChecker, peers: []const Http2Peer, client_completed: u64) void {
        var completed: u64 = 0;
        for (peers, 0..) |*peer, peer_index| {
            if (!peer.has_connection) continue;
            assert(peer.connection.stream_slots_in_use_count <= memory_budget.MemBudget.max_streams_per_conn);
            assert(peer.connection.pending_stream_count <= memory_budget.MemBudget.max_streams_per_conn);
            assert(peer.connection.recv_window_size <= std.math.maxInt(i32));
            assert(peer.connection.send_window_size <= std.math.maxInt(i32));
            assert(peer.connection.hpack_decoder_table.current_size <= peer.connection.hpack_decoder_table.max_size);
            assert(peer.connection.hpack_encoder_table.current_size <= peer.connection.hpack_encoder_table.max_size);
            assert(peer.connection.hpack_decoder_table.max_size <= peer.connection.hpack_decoder_table.max_allowed_size);
            assert(peer.connection.hpack_encoder_table.max_size <= peer.connection.hpack_encoder_table.max_allowed_size);
            completed += peer.connection.completed_responses_pending;

            for (peer.connection.stream_slots_in_use, 0..) |in_use, slot_index| {
                if (!in_use) continue;
                const stream = &peer.connection.stream_slots[slot_index];
                assert(stream.id > 0);
                assert(stream.request_body_len <= stream.request_body_storage.len);
                assert(stream.send_window_size <= std.math.maxInt(i32));
                assert(stream.recv_window_size <= std.math.maxInt(i32));
                if (stream.response) |response| {
                    assert(stream.response_body_sent <= response.body.len);
                } else {
                    assert(stream.response_body_sent == 0);
                }
                if (self.wasResetForPeer(stream.id, @intCast(peer_index))) {
                    assert(stream.state == .Closed);
                }
            }
        }
        assert(completed <= self.requests_sent);
        assert(client_completed <= self.requests_sent);
        self.responses_completed = completed;
    }

    fn rememberRoute(self: *ClusterChecker, key: StreamKey) void {
        assert(self.route_count < max_tracked_streams);
        self.routes[self.route_count] = .{ .key = key };
        self.route_count += 1;
    }

    fn findRoute(self: *const ClusterChecker, server: u8, stream_id: u32) ?StreamKey {
        var index: u32 = 0;
        while (index < self.route_count) : (index += 1) {
            const route = self.routes[index];
            if (route.active and route.key.target == server and route.key.stream_id == stream_id) {
                return route.key;
            }
        }
        return null;
    }

    fn rememberReset(self: *ClusterChecker, key: StreamKey) void {
        if (self.wasReset(key.source, key.target, key.stream_id)) return;
        assert(self.reset_stream_count < max_reset_streams_tracked);
        self.reset_streams[self.reset_stream_count] = key;
        self.reset_stream_count += 1;
    }

    fn wasReset(self: *const ClusterChecker, source: u8, target: u8, stream_id: u32) bool {
        var index: u32 = 0;
        while (index < self.reset_stream_count) : (index += 1) {
            const key = self.reset_streams[index];
            if (key.source == source and key.target == target and key.stream_id == stream_id) {
                return true;
            }
        }
        return false;
    }

    fn wasResetForPeer(self: *const ClusterChecker, stream_id: u32, peer: u8) bool {
        var index: u32 = 0;
        while (index < self.reset_stream_count) : (index += 1) {
            const key = self.reset_streams[index];
            if (key.target == peer and key.stream_id == stream_id) return true;
        }
        return false;
    }
};

pub const Http2Cluster = struct {
    allocator: std.mem.Allocator,
    random: Prng,
    options: Options,
    peers: []Http2Peer,
    network: PacketSimulator,
    client_encoder_tables: []Hpack.DynamicTable,
    client_oracles: []ClientOracle,
    next_stream_ids: []u32,
    checker: ClusterChecker = .{},
    metrics: Metrics,

    pub fn init(allocator: std.mem.Allocator, options_in: Options) !Http2Cluster {
        var options = options_in;
        assert(options.client_count > 0);
        assert(options.server_count > 0);
        assert(options.nodeCount() <= max_peers);
        options.network.node_count = options.nodeCount();
        options.network.seed = options.seed;

        const peers = try allocator.alloc(Http2Peer, options.nodeCount());
        errdefer allocator.free(peers);

        var peer_index: u8 = 0;
        while (peer_index < options.nodeCount()) : (peer_index += 1) {
            const role: Role = if (peer_index < options.client_count) .client else .server;
            try peers[peer_index].init(allocator, role);
        }
        errdefer for (peers) |*peer| peer.deinit();

        const client_encoder_tables = try allocator.alloc(Hpack.DynamicTable, options.client_count);
        errdefer allocator.free(client_encoder_tables);
        for (client_encoder_tables) |*table| {
            table.* = Hpack.DynamicTable.init(allocator, 4096);
        }
        errdefer for (client_encoder_tables) |*table| table.deinit();

        const client_oracles = try allocator.alloc(ClientOracle, options.client_count);
        errdefer allocator.free(client_oracles);
        for (client_oracles) |*oracle| {
            oracle.* = ClientOracle.init(allocator);
        }
        errdefer for (client_oracles) |*oracle| oracle.deinit();

        const next_stream_ids = try allocator.alloc(u32, options.client_count);
        errdefer allocator.free(next_stream_ids);
        @memset(next_stream_ids, 1);

        return .{
            .allocator = allocator,
            .random = Prng.init(options.seed),
            .options = options,
            .peers = peers,
            .network = PacketSimulator.init(options.network),
            .client_encoder_tables = client_encoder_tables,
            .client_oracles = client_oracles,
            .next_stream_ids = next_stream_ids,
            .metrics = .{ .seed = options.seed },
        };
    }

    pub fn deinit(self: *Http2Cluster) void {
        for (self.client_oracles) |*oracle| oracle.deinit();
        self.allocator.free(self.client_oracles);
        for (self.client_encoder_tables) |*table| table.deinit();
        self.allocator.free(self.next_stream_ids);
        self.allocator.free(self.client_encoder_tables);
        for (self.peers) |*peer| peer.deinit();
        self.allocator.free(self.peers);
    }

    pub fn run(self: *Http2Cluster) !Metrics {
        var tick_current: u64 = 0;
        while (tick_current < self.options.ticks) : (tick_current += 1) {
            self.metrics.ticks = tick_current + 1;
            try self.tick(tick_current);
        }
        self.metrics.completed_responses = self.checker.responses_completed;
        self.metrics.completed_client_responses = self.clientCompletedResponses();
        self.metrics.finalizeDigest();
        return self.metrics;
    }

    fn tick(self: *Http2Cluster, tick_current: u64) !void {
        try self.generateWorkload(tick_current);
        self.network.tick();
        try self.deliverPackets();
        self.collectOutgoingFrames();
        self.checker.check(self.peers, self.clientCompletedResponses());
    }

    fn generateWorkload(self: *Http2Cluster, tick_current: u64) !void {
        var client: u8 = 0;
        while (client < self.options.client_count) : (client += 1) {
            if (!self.random.chance(self.options.request_probability)) continue;

            const server = self.options.client_count +
                @as(u8, @intCast(tick_current % self.options.server_count));
            const stream_id = self.next_stream_ids[client];
            self.next_stream_ids[client] += 2;
            const key: StreamKey = .{
                .source = client,
                .target = server,
                .stream_id = stream_id,
            };
            self.checker.onRequest(client, server, stream_id);
            self.client_oracles[client].onRequest(key);

            var payload_storage: [max_payload_size]u8 = undefined;
            const payload = try encodeRequestHeaders(
                self.allocator,
                &self.client_encoder_tables[client],
                stream_id,
                &payload_storage,
            );
            self.network.send(Packet.init(
                client,
                server,
                packetFrameType(.HEADERS),
                FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
                stream_id,
                payload,
            ));
            self.metrics.requests_sent += 1;
        }
    }

    fn deliverPackets(self: *Http2Cluster) !void {
        var peer_index: u8 = 0;
        while (peer_index < self.options.nodeCount()) : (peer_index += 1) {
            var work: u8 = 0;
            while (work < max_work_per_peer_per_tick) : (work += 1) {
                var packet = self.network.receive(peer_index) orelse break;
                self.checker.onFrameDelivered(&packet);
                self.metrics.frames_delivered += 1;

                if (self.peers[peer_index].role == .client) {
                    try self.client_oracles[peer_index].onFrame(self.allocator, &packet);
                } else {
                    const result = self.peers[peer_index].connection.handleFrameEventDriven(frameFromPacket(&packet));
                    result catch |err| {
                        self.metrics.protocol_errors += 1;
                        if (!isExpectedError(err)) return err;
                    };
                }
            }
        }
    }

    fn collectOutgoingFrames(self: *Http2Cluster) void {
        var peer_index: u8 = 0;
        while (peer_index < self.options.nodeCount()) : (peer_index += 1) {
            const peer = &self.peers[peer_index];
            const bytes = peer.writer.written();
            var offset = peer.output_consumed;
            while (offset + 9 <= bytes.len) {
                const length = (@as(u32, bytes[offset]) << 16) |
                    (@as(u32, bytes[offset + 1]) << 8) |
                    @as(u32, bytes[offset + 2]);
                const frame_size = 9 + @as(usize, length);
                if (offset + frame_size > bytes.len) break;

                const frame_type = FrameType.fromU8(bytes[offset + 3]) orelse break;
                const flags = bytes[offset + 4];
                const stream_id_raw = (@as(u32, bytes[offset + 5]) << 24) |
                    (@as(u32, bytes[offset + 6]) << 16) |
                    (@as(u32, bytes[offset + 7]) << 8) |
                    @as(u32, bytes[offset + 8]);
                const stream_id = stream_id_raw & 0x7fffffff;
                const payload = bytes[offset + 9 .. offset + frame_size];

                const target = self.outgoingTarget(peer_index, frame_type, stream_id) orelse {
                    offset += frame_size;
                    continue;
                };
                self.checker.onOutgoingFrame(peer_index, target, frame_type, stream_id, payload);
                self.network.send(Packet.init(
                    peer_index,
                    target,
                    packetFrameType(frame_type),
                    flags,
                    stream_id,
                    payload,
                ));
                self.metrics.frames_collected += 1;
                offset += frame_size;
            }
            peer.output_consumed = offset;
        }
    }

    fn outgoingTarget(
        self: *const Http2Cluster,
        source: u8,
        frame_type: FrameType,
        stream_id: u32,
    ) ?u8 {
        if (self.peers[source].role == .client) return null;
        if (stream_id == 0) return 0;
        const route = self.checker.findRoute(source, stream_id) orelse return null;
        return switch (frame_type) {
            .HEADERS, .DATA, .RST_STREAM, .CONTINUATION => route.source,
            else => null,
        };
    }

    fn clientCompletedResponses(self: *const Http2Cluster) u64 {
        var completed: u64 = 0;
        for (self.client_oracles) |*oracle| {
            completed += oracle.completed_responses;
        }
        return completed;
    }
};

fn frameFromPacket(packet: *const Packet) Frame {
    return .{
        .header = .{
            .length = packet.payload_len,
            .frame_type = coreFrameType(packet.frame_type),
            .flags = FrameFlags.init(packet.flags),
            .reserved = false,
            .stream_id = packet.stream_id,
        },
        .payload = packet.payload_slice(),
    };
}

fn packetFrameType(frame_type: FrameType) packet_sim.FrameType {
    return @enumFromInt(@intFromEnum(frame_type));
}

fn coreFrameType(frame_type: packet_sim.FrameType) FrameType {
    return @enumFromInt(@intFromEnum(frame_type));
}

fn digestMix(value: u64, input: u64) u64 {
    return (value ^ input) *% 0x100000001b3;
}

fn isExpectedError(err: anyerror) bool {
    return switch (err) {
        error.ProtocolError,
        error.StreamClosed,
        error.FrameSizeError,
        error.FlowControlError,
        error.InvalidStreamState,
        error.IdleStreamError,
        error.CompressionError,
        error.MaxConcurrentStreamsExceeded,
        => true,
        else => false,
    };
}

fn encodeRequestHeaders(
    allocator: std.mem.Allocator,
    table: *Hpack.DynamicTable,
    stream_id: u32,
    storage: []u8,
) ![]const u8 {
    var encoded = std.ArrayList(u8).initBuffer(storage);
    try Hpack.encodeHeaderField(.{ .name = ":method", .value = "GET" }, table, &encoded, allocator);
    try Hpack.encodeHeaderField(.{ .name = ":scheme", .value = "https" }, table, &encoded, allocator);
    try Hpack.encodeHeaderField(.{ .name = ":authority", .value = "cluster.sim" }, table, &encoded, allocator);

    var path_storage: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_storage, "/cluster/{d}", .{stream_id});
    try Hpack.encodeHeaderField(.{ .name = ":path", .value = path }, table, &encoded, allocator);
    return encoded.items;
}

fn clusterHandler(ctx: *const handler.Context) !handler.Response {
    const text = try std.fmt.bufPrint(ctx.response_body_buffer, "cluster:{s}", .{ctx.path});
    return ctx.response.text(.ok, text);
}

pub fn run(allocator: std.mem.Allocator, options: Options) !Metrics {
    var cluster = try Http2Cluster.init(allocator, options);
    defer cluster.deinit();
    return cluster.run();
}

test "Http2Cluster owns real peers and runs deterministic workload" {
    const allocator = std.testing.allocator;
    const options: Options = .{
        .seed = 33,
        .ticks = 16,
        .client_count = 1,
        .server_count = 1,
        .network = .{
            .node_count = 2,
            .seed = 33,
            .one_way_delay_ticks = 0,
            .path_capacity = 8,
        },
    };

    const a = try run(allocator, options);
    const b = try run(allocator, options);
    try std.testing.expectEqual(a.requests_sent, b.requests_sent);
    try std.testing.expectEqual(a.frames_delivered, b.frames_delivered);
    try std.testing.expectEqual(a.digest, b.digest);
    try std.testing.expect(a.requests_sent > 0);
    try std.testing.expect(a.completed_responses <= a.requests_sent);
}
