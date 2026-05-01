//! Protocol-aware deterministic simulation testing for the HTTP/2 engine.
//!
//! The byte network simulator is useful, but HTTP/2 needs a simulator that
//! understands frames, stream state, flow control, priorities, and connection
//! close semantics. This module drives the real `Connection` state machine
//! through narrow frame-level interfaces and checks invariants after every
//! simulated event.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");

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

const max_ticks_default = 512;
const max_warmup_ticks_default = 32;
const writer_capacity = 2 * 1024 * 1024;
const max_trace_events = 256;
const max_payload_size = 512;
const max_response_body_size = 256;
const max_reset_streams_tracked = 128;
const min_frame_size = 16 * 1024;

pub const FaultProfile = enum {
    perfect,
    malformed_boundary,
    flow_control_squeeze,
    gray_slow_peer,
    hpack_pressure,
    recovery_after_goaway,

    pub fn parse(name: []const u8) ?FaultProfile {
        inline for (std.meta.fields(FaultProfile)) |field| {
            if (std.mem.eql(u8, name, field.name)) {
                return @enumFromInt(field.value);
            }
        }
        return null;
    }
};

pub const Mode = enum {
    dst,
    dpt,
};

pub const RunShape = enum {
    standard,
    lite,
    swarm,
    performance,
};

pub const Failure = enum {
    correctness,
    liveness,
    performance,
};

fn classifyFailure(err: anyerror) Failure {
    return switch (err) {
        error.PerformanceRegression => .performance,
        error.OutOfMemory => .liveness,
        else => .correctness,
    };
}

pub const DptThresholds = struct {
    max_frames_per_response_x100: u64 = 250,
    max_bytes_per_response: u64 = 64,
    max_blocked_ticks: u64 = 0,
    max_control_frames: u64 = 64,
    max_protocol_errors: u64 = 0,
};

const Action = enum {
    valid_request,
    ping,
    window_update_connection,
    priority_update_idle,
    invalid_data_on_idle,
    invalid_continuation,
    settings_ack,
    goaway,
    zero_window_request,
    header_table_pressure,
    delayed_noop,
};

const TraceEvent = struct {
    tick: u64,
    action: Action,
    stream_id: u32,
};

fn digestMix(value: u64, input: u64) u64 {
    return (value ^ input) *% 0x100000001b3;
}

pub const Metrics = struct {
    seed: u64,
    ticks: u64 = 0,
    actions: u64 = 0,
    successful_actions: u64 = 0,
    protocol_errors: u64 = 0,
    frames_in: u64 = 0,
    frames_out: u64 = 0,
    bytes_out: u64 = 0,
    goaway_sent: u64 = 0,
    rst_stream_sent: u64 = 0,
    ping_sent: u64 = 0,
    window_update_sent: u64 = 0,
    response_headers_sent: u64 = 0,
    response_data_sent: u64 = 0,
    completed_responses: u64 = 0,
    blocked_ticks: u64 = 0,
    max_live_streams: u32 = 0,
    warmup_ticks: u64 = 0,
    measured_ticks: u64 = 0,
    digest: u64 = 0,

    fn observeOutput(self: *Metrics, previous_len: usize, current: []const u8) void {
        assert(current.len >= previous_len);
        const delta = current[previous_len..];
        self.bytes_out += delta.len;

        var offset: usize = 0;
        while (offset + 9 <= delta.len) {
            const length = (@as(u32, delta[offset]) << 16) |
                (@as(u32, delta[offset + 1]) << 8) |
                @as(u32, delta[offset + 2]);
            const frame_size = 9 + @as(usize, length);
            if (offset + frame_size > delta.len) break;

            self.frames_out += 1;
            switch (delta[offset + 3]) {
                @intFromEnum(FrameType.GOAWAY) => self.goaway_sent += 1,
                @intFromEnum(FrameType.RST_STREAM) => self.rst_stream_sent += 1,
                @intFromEnum(FrameType.PING) => self.ping_sent += 1,
                @intFromEnum(FrameType.WINDOW_UPDATE) => self.window_update_sent += 1,
                @intFromEnum(FrameType.HEADERS) => self.response_headers_sent += 1,
                @intFromEnum(FrameType.DATA) => self.response_data_sent += 1,
                else => {},
            }

            offset += frame_size;
        }
    }

    fn finalizeDigest(self: *Metrics) void {
        var value: u64 = 0xcbf29ce484222325;
        value = digestMix(value, self.seed);
        value = digestMix(value, self.ticks);
        value = digestMix(value, self.actions);
        value = digestMix(value, self.protocol_errors);
        value = digestMix(value, self.frames_in);
        value = digestMix(value, self.frames_out);
        value = digestMix(value, self.bytes_out);
        value = digestMix(value, self.completed_responses);
        value = digestMix(value, self.blocked_ticks);
        self.digest = value;
    }
};

pub const Config = struct {
    seed: u64 = 1,
    ticks: u64 = max_ticks_default,
    warmup_ticks: u64 = max_warmup_ticks_default,
    profile: FaultProfile = .perfect,
    mode: Mode = .dst,
    shape: RunShape = .standard,
    packet_loss_probability: Prng.Ratio = Prng.Ratio.zero(),
    packet_replay_probability: Prng.Ratio = Prng.Ratio.zero(),
    path_capacity: u8 = 8,
    packet_delay_ticks: u32 = 1,
    max_frame_size: u32 = 16 * 1024,
    hpack_table_size: usize = 4096,
    initial_window_size: u32 = 65535,
    request_body_size: u16 = 0,
    response_body_size: u16 = 16,
    dpt_compare: bool = false,
    dpt_thresholds: DptThresholds = .{},

    fn measuredTicks(self: Config) u64 {
        if (self.mode == .dst) return self.ticks;
        return self.ticks -| self.warmup_ticks;
    }
};

fn optionsLite(seed: u64, mode: Mode) Config {
    var config: Config = .{
        .seed = seed,
        .ticks = 96,
        .warmup_ticks = 8,
        .mode = mode,
        .shape = .lite,
        .path_capacity = 4,
    };
    if (mode == .dpt) {
        config.profile = .hpack_pressure;
    }
    return config;
}

fn optionsPerformance(seed: u64) Config {
    return .{
        .seed = seed,
        .ticks = 1024,
        .warmup_ticks = 128,
        .profile = .hpack_pressure,
        .mode = .dpt,
        .shape = .performance,
        .packet_loss_probability = Prng.Ratio.zero(),
        .packet_replay_probability = Prng.Ratio.zero(),
        .path_capacity = packet_sim.max_path_capacity,
        .packet_delay_ticks = 0,
        .max_frame_size = 16 * 1024,
        .hpack_table_size = 4096,
        .initial_window_size = 65535,
        .request_body_size = 0,
        .response_body_size = 32,
        .dpt_thresholds = .{},
    };
}

fn optionsSwarm(seed: u64, mode: Mode) Config {
    var random = Prng.init(seed);
    const profiles = std.enums.values(FaultProfile);
    return .{
        .seed = seed,
        .ticks = random.range_inclusive(u64, 96, 768),
        .warmup_ticks = random.range_inclusive(u64, 0, 64),
        .profile = profiles[random.index(profiles)],
        .mode = mode,
        .shape = .swarm,
        .packet_loss_probability = Prng.ratio(random.int_inclusive(u8, 5), 100),
        .packet_replay_probability = Prng.ratio(random.int_inclusive(u8, 2), 100),
        .path_capacity = random.range_inclusive(u8, 2, packet_sim.max_path_capacity),
        .packet_delay_ticks = random.range_inclusive(u32, 0, 8),
        .max_frame_size = random.range_inclusive(u32, min_frame_size, 32 * 1024),
        .hpack_table_size = random.range_inclusive(usize, 128, 4096),
        .initial_window_size = random.range_inclusive(u32, 1024, 65535),
        .request_body_size = random.range_inclusive(u16, 0, 256),
        .response_body_size = random.range_inclusive(u16, 0, max_response_body_size),
    };
}

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

const Model = struct {
    next_stream_id: u32 = 1,
    highest_stream_id: u32 = 0,
    requests_sent: u32 = 0,
    goaway_expected: bool = false,

    fn allocateStream(self: *Model) u32 {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        self.highest_stream_id = stream_id;
        self.requests_sent += 1;
        return stream_id;
    }
};

const SimHandlerState = struct {
    response_body_size: u16,

    fn dispatch(self: *const SimHandlerState, ctx: *const handler.Context) !handler.Response {
        assert(self.response_body_size <= ctx.response_body_buffer.len);

        const len: usize = self.response_body_size;
        var index: usize = 0;
        while (index < len) : (index += 1) {
            ctx.response_body_buffer[index] = @intCast('A' + (index % 26));
        }

        return ctx.response.text(.ok, ctx.response_body_buffer[0..len]);
    }
};

const Http2StateChecker = struct {
    requests_seen: u32 = 0,
    highest_stream_id: u32 = 0,
    last_goaway_stream_id: u32 = 0,
    goaway_seen: bool = false,
    reset_streams: [max_reset_streams_tracked]u32 = [_]u32{0} ** max_reset_streams_tracked,
    reset_stream_count: u32 = 0,

    fn onRequest(self: *Http2StateChecker, stream_id: u32) void {
        assert(stream_id > 0);
        assert(stream_id & 1 == 1);
        assert(stream_id > self.highest_stream_id);
        self.highest_stream_id = stream_id;
        self.requests_seen += 1;
    }

    fn onGoaway(self: *Http2StateChecker, last_stream_id: u32) void {
        assert(last_stream_id == 0 or last_stream_id & 1 == 1);
        assert(last_stream_id <= self.highest_stream_id);
        assert(last_stream_id >= self.last_goaway_stream_id);
        self.last_goaway_stream_id = last_stream_id;
        self.goaway_seen = true;
    }

    fn observeOutput(self: *Http2StateChecker, delta: []const u8) void {
        var offset: usize = 0;
        while (offset + 9 <= delta.len) {
            const length = (@as(u32, delta[offset]) << 16) |
                (@as(u32, delta[offset + 1]) << 8) |
                @as(u32, delta[offset + 2]);
            const frame_size = 9 + @as(usize, length);
            if (offset + frame_size > delta.len) break;

            const frame_type = FrameType.fromU8(delta[offset + 3]) orelse unreachable;
            const stream_id_raw = (@as(u32, delta[offset + 5]) << 24) |
                (@as(u32, delta[offset + 6]) << 16) |
                (@as(u32, delta[offset + 7]) << 8) |
                @as(u32, delta[offset + 8]);
            const stream_id = stream_id_raw & 0x7fffffff;
            const payload = delta[offset + 9 .. offset + frame_size];

            switch (frame_type) {
                .GOAWAY => {
                    assert(stream_id == 0);
                    assert(payload.len >= 8);
                    const last_stream_id = (@as(u32, payload[0]) << 24) |
                        (@as(u32, payload[1]) << 16) |
                        (@as(u32, payload[2]) << 8) |
                        @as(u32, payload[3]);
                    self.onGoaway(last_stream_id & 0x7fffffff);
                },
                .RST_STREAM => {
                    assert(stream_id > 0);
                    self.rememberReset(stream_id);
                },
                .HEADERS, .DATA => {
                    assert(stream_id > 0);
                    assert(!self.wasReset(stream_id));
                },
                .CONTINUATION => assert(stream_id > 0),
                .PING, .SETTINGS, .WINDOW_UPDATE => {},
                else => {},
            }

            offset += frame_size;
        }
    }

    fn check(self: *const Http2StateChecker, connection: *const Connection) void {
        assert(connection.completed_responses_pending <= self.requests_seen);
        if (self.goaway_seen) assert(connection.goaway_sent);
        assert(connection.recv_window_size <= std.math.maxInt(i32));
        assert(connection.send_window_size <= std.math.maxInt(i32));
        assert(connection.hpack_decoder_table.current_size <= connection.hpack_decoder_table.max_size);
        assert(connection.hpack_encoder_table.current_size <= connection.hpack_encoder_table.max_size);
        assert(connection.hpack_decoder_table.max_size <= connection.hpack_decoder_table.max_allowed_size);
        assert(connection.hpack_encoder_table.max_size <= connection.hpack_encoder_table.max_allowed_size);

        for (connection.stream_slots_in_use, 0..) |in_use, index| {
            if (!in_use) continue;
            const stream = &connection.stream_slots[index];
            assert(stream.id > 0);
            assert(stream.id <= self.highest_stream_id or stream.id & 1 == 0);
            assert(stream.request_body_len <= stream.request_body_storage.len);
            assert(stream.send_window_size <= std.math.maxInt(i32));
            assert(stream.recv_window_size <= std.math.maxInt(i32));
            if (stream.response) |response| {
                assert(stream.response_body_sent <= response.body.len);
            } else {
                assert(stream.response_body_sent == 0);
            }
            if (self.wasReset(stream.id)) {
                assert(stream.state == .Closed);
            }
        }
    }

    fn rememberReset(self: *Http2StateChecker, stream_id: u32) void {
        if (self.wasReset(stream_id)) return;
        assert(self.reset_stream_count < max_reset_streams_tracked);
        self.reset_streams[self.reset_stream_count] = stream_id;
        self.reset_stream_count += 1;
    }

    fn wasReset(self: *const Http2StateChecker, stream_id: u32) bool {
        var index: u32 = 0;
        while (index < self.reset_stream_count) : (index += 1) {
            if (self.reset_streams[index] == stream_id) return true;
        }
        return false;
    }
};

const Simulator = struct {
    allocator: std.mem.Allocator,
    random: Prng,
    config: Config,
    reader: std.Io.Reader,
    writer: SimWriter,
    stream_storage: Connection.StreamStorage,
    connection: Connection,
    network: PacketSimulator,
    client_encoder_table: Hpack.DynamicTable,
    handler_state: SimHandlerState,
    model: Model = .{},
    checker: Http2StateChecker = .{},
    metrics: Metrics,
    dpt_baseline: ?Metrics = null,
    trace: [max_trace_events]TraceEvent = undefined,
    trace_count: u32 = 0,

    fn init(self: *Simulator, allocator: std.mem.Allocator, config: Config) !void {
        assert(config.ticks > 0);
        assert(config.warmup_ticks <= config.ticks);
        assert(config.path_capacity > 0);
        assert(config.max_frame_size >= min_frame_size);
        assert(config.request_body_size <= max_payload_size);
        assert(config.response_body_size <= max_response_body_size);
        assert(config.hpack_table_size <= 4096);
        assert(config.initial_window_size <= 65535);

        self.allocator = allocator;
        self.random = Prng.init(config.seed);
        self.config = config;
        self.reader = .fixed("");
        self.writer = SimWriter.init();
        self.stream_storage = undefined;
        self.network = PacketSimulator.init(.{
            .node_count = 2,
            .seed = config.seed,
            .one_way_delay_ticks = config.packet_delay_ticks,
            .packet_loss_probability = config.packet_loss_probability,
            .packet_replay_probability = config.packet_replay_probability,
            .path_capacity = config.path_capacity,
        });
        self.client_encoder_table = Hpack.DynamicTable.init(allocator, config.hpack_table_size);
        self.model = .{};
        self.checker = .{};
        self.metrics = .{
            .seed = config.seed,
            .warmup_ticks = if (config.mode == .dpt) config.warmup_ticks else 0,
            .measured_ticks = config.measuredTicks(),
        };
        self.dpt_baseline = null;
        self.trace = undefined;
        self.trace_count = 0;

        try Connection.initServerEventDrivenInPlace(
            &self.connection,
            &self.stream_storage,
            allocator,
            &self.reader,
            &self.writer.interface,
        );
        self.connection.hpack_decoder_table.setMaxAllowedSize(config.hpack_table_size);
        self.connection.hpack_encoder_table.setMaxAllowedSize(config.hpack_table_size);
        self.connection.settings.header_table_size = @intCast(config.hpack_table_size);
        self.connection.settings.initial_window_size = config.initial_window_size;
        self.connection.settings.max_frame_size = config.max_frame_size;
        self.connection.recv_window_size = @intCast(config.initial_window_size);
        self.connection.send_window_size = @intCast(config.initial_window_size);
        self.handler_state = .{ .response_body_size = config.response_body_size };
        self.connection.bindRequestDispatcher(handler.RequestDispatcher.bind(
            SimHandlerState,
            &self.handler_state,
            SimHandlerState.dispatch,
        ));

        self.metrics.observeOutput(0, self.writer.written());
        try self.checkInvariants();
    }

    fn deinit(self: *Simulator) void {
        self.client_encoder_table.deinit();
        self.connection.deinit();
    }

    fn run(self: *Simulator) !Metrics {
        var tick: u64 = 0;
        while (tick < self.config.ticks) : (tick += 1) {
            self.metrics.ticks = tick + 1;
            const action = self.chooseAction(tick);
            try self.applyAction(tick, action);
            try self.drainNetwork();
            try self.checkInvariants();
            if (self.config.mode == .dpt and tick + 1 == self.config.warmup_ticks) {
                self.dpt_baseline = self.metrics;
            }

            if (self.connection.goaway_sent and self.config.profile != .recovery_after_goaway) {
                break;
            }
        }
        try self.drainNetwork();
        if (self.config.mode == .dpt and self.config.warmup_ticks > 0) {
            self.discardDptWarmup();
        }
        self.metrics.finalizeDigest();
        return self.metrics;
    }

    fn chooseAction(self: *Simulator, tick: u64) Action {
        return switch (self.config.profile) {
            .perfect => if (tick % 11 == 0) .ping else .valid_request,
            .malformed_boundary => switch (tick % 7) {
                0 => .invalid_data_on_idle,
                1 => .invalid_continuation,
                2 => .settings_ack,
                else => .valid_request,
            },
            .flow_control_squeeze => switch (tick % 5) {
                0 => .zero_window_request,
                1 => .window_update_connection,
                else => .valid_request,
            },
            .gray_slow_peer => if (self.random.chance(Prng.ratio(2, 5)))
                .delayed_noop
            else
                .valid_request,
            .hpack_pressure => if (tick % 3 == 0) .header_table_pressure else .valid_request,
            .recovery_after_goaway => switch (tick % 13) {
                0 => .goaway,
                1, 2 => .valid_request,
                3 => .ping,
                else => .valid_request,
            },
        };
    }

    fn applyAction(self: *Simulator, tick: u64, action: Action) !void {
        self.recordTrace(tick, action, self.model.next_stream_id);
        self.metrics.actions += 1;

        const before_len = self.writer.written().len;
        const result = switch (action) {
            .valid_request => self.applyValidRequest(false),
            .ping => self.applyPing(),
            .window_update_connection => self.applyWindowUpdate(0, 4096),
            .priority_update_idle => self.applyPriorityUpdate(self.model.next_stream_id),
            .invalid_data_on_idle => self.applyData(self.model.next_stream_id, "bad", true),
            .invalid_continuation => self.applyContinuation(self.model.next_stream_id),
            .settings_ack => self.dispatch(frame(.SETTINGS, FrameFlags.ACK, 0, "")),
            .goaway => self.applyGoaway(),
            .zero_window_request => self.applyZeroWindowRequest(),
            .header_table_pressure => self.applyValidRequest(true),
            .delayed_noop => blk: {
                self.metrics.blocked_ticks += 1;
                break :blk {};
            },
        };

        result catch |err| {
            self.metrics.protocol_errors += 1;
            if (!self.connection.goaway_sent and !isExpectedError(err)) {
                return err;
            }
        };

        self.metrics.successful_actions += 1;
        const written = self.writer.written();
        self.checker.observeOutput(written[before_len..]);
        self.metrics.observeOutput(before_len, written);
        self.metrics.completed_responses = self.connection.completed_responses_pending;
        self.metrics.max_live_streams = @max(
            self.metrics.max_live_streams,
            self.connection.stream_slots_in_use_count,
        );
    }

    fn applyValidRequest(self: *Simulator, pressure: bool) !void {
        const stream_id = self.model.allocateStream();
        self.checker.onRequest(stream_id);
        var payload_storage: [max_payload_size]u8 = undefined;
        const payload = try encodeRequestHeaders(
            self.allocator,
            &self.client_encoder_table,
            stream_id,
            pressure,
            &payload_storage,
        );
        if (self.config.request_body_size == 0) {
            try self.dispatch(frame(
                .HEADERS,
                FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
                stream_id,
                payload,
            ));
        } else {
            try self.dispatch(frame(
                .HEADERS,
                FrameFlags.END_HEADERS,
                stream_id,
                payload,
            ));
            try self.applyConfiguredRequestBody(stream_id);
        }
    }

    fn applyZeroWindowRequest(self: *Simulator) !void {
        self.connection.send_window_size = 0;
        const stream_id = self.model.allocateStream();
        self.checker.onRequest(stream_id);
        var payload_storage: [max_payload_size]u8 = undefined;
        const payload = try encodeRequestHeaders(
            self.allocator,
            &self.client_encoder_table,
            stream_id,
            false,
            &payload_storage,
        );
        try self.dispatch(frame(
            .HEADERS,
            FrameFlags.END_HEADERS | FrameFlags.END_STREAM,
            stream_id,
            payload,
        ));
        try self.applyWindowUpdate(0, 65535);
    }

    fn applyPing(self: *Simulator) !void {
        try self.dispatch(frame(.PING, 0, 0, "12345678"));
    }

    fn applyWindowUpdate(self: *Simulator, stream_id: u32, increment: u32) !void {
        var payload: [4]u8 = undefined;
        std.mem.writeInt(u32, &payload, increment, .big);
        try self.dispatch(frame(.WINDOW_UPDATE, 0, stream_id, &payload));
    }

    fn applyPriorityUpdate(self: *Simulator, stream_id: u32) !void {
        var payload: [10]u8 = undefined;
        std.mem.writeInt(u32, payload[0..4], stream_id, .big);
        @memcpy(payload[4..], "u=1, i");
        try self.dispatch(frame(.PRIORITY_UPDATE, 0, 0, &payload));
    }

    fn applyData(self: *Simulator, stream_id: u32, data: []const u8, end_stream: bool) !void {
        const flags: u8 = if (end_stream) FrameFlags.END_STREAM else 0;
        try self.dispatch(frame(.DATA, flags, stream_id, data));
    }

    fn applyConfiguredRequestBody(self: *Simulator, stream_id: u32) !void {
        assert(self.config.request_body_size > 0);
        assert(self.config.request_body_size <= max_payload_size);

        var body: [max_payload_size]u8 = undefined;
        const len: usize = self.config.request_body_size;
        var index: usize = 0;
        while (index < len) : (index += 1) {
            body[index] = @intCast('a' + (index % 26));
        }
        try self.applyData(stream_id, body[0..len], true);
    }

    fn applyContinuation(self: *Simulator, stream_id: u32) !void {
        try self.dispatch(frame(.CONTINUATION, FrameFlags.END_HEADERS, stream_id, ""));
    }

    fn applyGoaway(self: *Simulator) !void {
        var payload: [8]u8 = undefined;
        std.mem.writeInt(u32, payload[0..4], self.model.highest_stream_id, .big);
        std.mem.writeInt(u32, payload[4..8], 0, .big);
        self.model.goaway_expected = true;
        self.checker.onGoaway(self.model.highest_stream_id);
        try self.dispatch(frame(.GOAWAY, 0, 0, &payload));
    }

    fn dispatch(self: *Simulator, f: Frame) !void {
        self.network.send(Packet.init(
            0,
            1,
            packetFrameType(f.header.frame_type),
            f.header.flags.value,
            f.header.stream_id,
            f.payload,
        ));
        try self.drainNetwork();
    }

    fn drainNetwork(self: *Simulator) !void {
        var ticks: u32 = 0;
        while (ticks <= self.config.packet_delay_ticks) : (ticks += 1) {
            self.network.tick();
            while (self.network.receive(1)) |packet| {
                self.metrics.frames_in += 1;
                try self.connection.handleFrameEventDriven(frameFromPacket(&packet));
            }
        }
    }

    fn discardDptWarmup(self: *Simulator) void {
        const baseline = self.dpt_baseline orelse return;
        self.metrics.actions -|= baseline.actions;
        self.metrics.successful_actions -|= baseline.successful_actions;
        self.metrics.protocol_errors -|= baseline.protocol_errors;
        self.metrics.frames_in -|= baseline.frames_in;
        self.metrics.frames_out -|= baseline.frames_out;
        self.metrics.bytes_out -|= baseline.bytes_out;
        self.metrics.goaway_sent -|= baseline.goaway_sent;
        self.metrics.rst_stream_sent -|= baseline.rst_stream_sent;
        self.metrics.ping_sent -|= baseline.ping_sent;
        self.metrics.window_update_sent -|= baseline.window_update_sent;
        self.metrics.response_headers_sent -|= baseline.response_headers_sent;
        self.metrics.response_data_sent -|= baseline.response_data_sent;
        self.metrics.completed_responses -|= baseline.completed_responses;
        self.metrics.blocked_ticks -|= baseline.blocked_ticks;
    }

    fn checkInvariants(self: *Simulator) !void {
        assert(self.connection.stream_slots_in_use_count <= memory_budget.MemBudget.max_streams_per_conn);
        assert(self.connection.pending_stream_count <= memory_budget.MemBudget.max_streams_per_conn);
        assert(self.connection.completed_responses_pending <= self.model.requests_sent);
        self.checker.check(&self.connection);

        if (self.connection.expecting_continuation_stream_id) |stream_id| {
            assert(stream_id > 0);
        }

        var live_count: u32 = 0;
        for (self.connection.stream_slots_in_use, 0..) |in_use, index| {
            if (!in_use) continue;
            live_count += 1;
            const stream = &self.connection.stream_slots[index];
            assert(stream.id > 0);
            assert(stream.request_body_len <= stream.request_body_storage.len);
            if (stream.response) |response| {
                assert(stream.response_body_sent <= response.body.len);
            } else {
                assert(stream.response_body_sent == 0);
            }
            assert(stream.send_window_size <= std.math.maxInt(i32));
            assert(stream.recv_window_size <= std.math.maxInt(i32));
        }
        assert(live_count == self.connection.stream_slots_in_use_count);
    }

    fn recordTrace(self: *Simulator, tick: u64, action: Action, stream_id: u32) void {
        const index = self.trace_count % max_trace_events;
        self.trace[index] = .{
            .tick = tick,
            .action = action,
            .stream_id = stream_id,
        };
        self.trace_count +%= 1;
    }
};

fn frame(frame_type: FrameType, flags: u8, stream_id: u32, payload: []const u8) Frame {
    return .{
        .header = .{
            .length = @intCast(payload.len),
            .frame_type = frame_type,
            .flags = FrameFlags.init(flags),
            .reserved = false,
            .stream_id = stream_id,
        },
        .payload = payload,
    };
}

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
    pressure: bool,
    storage: []u8,
) ![]const u8 {
    var encoded = std.ArrayList(u8).initBuffer(storage);
    try Hpack.encodeHeaderField(.{ .name = ":method", .value = "GET" }, table, &encoded, allocator);
    try Hpack.encodeHeaderField(.{ .name = ":scheme", .value = "https" }, table, &encoded, allocator);
    try Hpack.encodeHeaderField(.{ .name = ":authority", .value = "sim.local" }, table, &encoded, allocator);

    var path_storage: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_storage, "/sim/{d}", .{stream_id});
    try Hpack.encodeHeaderField(.{ .name = ":path", .value = path }, table, &encoded, allocator);

    if (pressure) {
        var value_storage: [96]u8 = undefined;
        const value = try std.fmt.bufPrint(
            &value_storage,
            "seeded-header-value-for-stream-{d}-xxxxxxxxxxxxxxxxxxxxxxxx",
            .{stream_id},
        );
        try Hpack.encodeHeaderField(.{ .name = "x-sim-pressure", .value = value }, table, &encoded, allocator);
    }

    return encoded.items;
}

pub fn run(allocator: std.mem.Allocator, config: Config) !Metrics {
    comptime {
        assert(builtin.mode != .ReleaseSmall);
    }

    const sim = try allocator.create(Simulator);
    defer allocator.destroy(sim);

    try sim.init(allocator, config);
    defer sim.deinit();

    const metrics = try sim.run();
    if (config.mode == .dpt and config.dpt_compare) {
        try validateDpt(metrics, config.dpt_thresholds);
    }
    return metrics;
}

fn validateDpt(metrics: Metrics, thresholds: DptThresholds) !void {
    const completed = @max(metrics.completed_responses, 1);
    const frames_per_response_x100 = (metrics.frames_out * 100) / completed;
    const bytes_per_response = metrics.bytes_out / completed;
    const control_frames =
        metrics.goaway_sent +
        metrics.rst_stream_sent +
        metrics.ping_sent +
        metrics.window_update_sent;

    if (frames_per_response_x100 > thresholds.max_frames_per_response_x100) {
        if (!builtin.is_test) logRegression("frames_per_response_x100", frames_per_response_x100, thresholds.max_frames_per_response_x100);
        return error.PerformanceRegression;
    }
    if (bytes_per_response > thresholds.max_bytes_per_response) {
        if (!builtin.is_test) logRegression("bytes_per_response", bytes_per_response, thresholds.max_bytes_per_response);
        return error.PerformanceRegression;
    }
    if (metrics.blocked_ticks > thresholds.max_blocked_ticks) {
        if (!builtin.is_test) logRegression("blocked_ticks", metrics.blocked_ticks, thresholds.max_blocked_ticks);
        return error.PerformanceRegression;
    }
    if (control_frames > thresholds.max_control_frames) {
        if (!builtin.is_test) logRegression("control_frames", control_frames, thresholds.max_control_frames);
        return error.PerformanceRegression;
    }
    if (metrics.protocol_errors > thresholds.max_protocol_errors) {
        if (!builtin.is_test) logRegression("protocol_errors", metrics.protocol_errors, thresholds.max_protocol_errors);
        return error.PerformanceRegression;
    }
}

fn logRegression(metric: []const u8, actual: anytype, max: anytype) void {
    std.debug.print("\n performance regression: {s}={d} (max={d})\n", .{ metric, actual, max });
}

fn parseArgs(args_source: std.process.Args) Config {
    var seed: u64 = 1;
    var mode: Mode = .dst;
    var shape: RunShape = .standard;
    var args_seed = args_source.iterate();
    _ = args_seed.next();
    while (args_seed.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            seed = std.fmt.parseInt(u64, arg["--seed=".len..], 10) catch seed;
        } else if (std.mem.eql(u8, arg, "--performance")) {
            mode = .dpt;
            shape = .performance;
        } else if (std.mem.eql(u8, arg, "--dpt")) {
            mode = .dpt;
        } else if (std.mem.eql(u8, arg, "--dst")) {
            mode = .dst;
        } else if (std.mem.eql(u8, arg, "--lite")) {
            shape = .lite;
        } else if (std.mem.eql(u8, arg, "--swarm")) {
            shape = .swarm;
        }
    }

    var config = switch (shape) {
        .standard => Config{ .seed = seed, .mode = mode },
        .lite => optionsLite(seed, mode),
        .swarm => optionsSwarm(seed, mode),
        .performance => optionsPerformance(seed),
    };

    var args = args_source.iterate();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            config.seed = std.fmt.parseInt(u64, arg["--seed=".len..], 10) catch config.seed;
        } else if (std.mem.startsWith(u8, arg, "--ticks=")) {
            config.ticks = std.fmt.parseInt(u64, arg["--ticks=".len..], 10) catch config.ticks;
        } else if (std.mem.startsWith(u8, arg, "--warmup-ticks=")) {
            config.warmup_ticks = std.fmt.parseInt(u64, arg["--warmup-ticks=".len..], 10) catch config.warmup_ticks;
        } else if (std.mem.startsWith(u8, arg, "--profile=")) {
            config.profile = FaultProfile.parse(arg["--profile=".len..]) orelse config.profile;
        } else if (std.mem.startsWith(u8, arg, "--packet-loss=")) {
            config.packet_loss_probability = parseRatio(arg["--packet-loss=".len..]) orelse config.packet_loss_probability;
        } else if (std.mem.startsWith(u8, arg, "--packet-replay=")) {
            config.packet_replay_probability = parseRatio(arg["--packet-replay=".len..]) orelse config.packet_replay_probability;
        } else if (std.mem.startsWith(u8, arg, "--path-capacity=")) {
            config.path_capacity = std.fmt.parseInt(u8, arg["--path-capacity=".len..], 10) catch config.path_capacity;
        } else if (std.mem.startsWith(u8, arg, "--max-path-capacity=")) {
            config.path_capacity = std.fmt.parseInt(u8, arg["--max-path-capacity=".len..], 10) catch config.path_capacity;
        } else if (std.mem.startsWith(u8, arg, "--packet-delay-ticks=")) {
            config.packet_delay_ticks = std.fmt.parseInt(u32, arg["--packet-delay-ticks=".len..], 10) catch config.packet_delay_ticks;
        } else if (std.mem.startsWith(u8, arg, "--max-frame-size=")) {
            config.max_frame_size = std.fmt.parseInt(u32, arg["--max-frame-size=".len..], 10) catch config.max_frame_size;
        } else if (std.mem.startsWith(u8, arg, "--hpack-table-size=")) {
            config.hpack_table_size = std.fmt.parseInt(usize, arg["--hpack-table-size=".len..], 10) catch config.hpack_table_size;
        } else if (std.mem.startsWith(u8, arg, "--initial-window-size=")) {
            config.initial_window_size = std.fmt.parseInt(u32, arg["--initial-window-size=".len..], 10) catch config.initial_window_size;
        } else if (std.mem.startsWith(u8, arg, "--request-body-size=")) {
            config.request_body_size = std.fmt.parseInt(u16, arg["--request-body-size=".len..], 10) catch config.request_body_size;
        } else if (std.mem.startsWith(u8, arg, "--response-body-size=")) {
            config.response_body_size = std.fmt.parseInt(u16, arg["--response-body-size=".len..], 10) catch config.response_body_size;
        } else if (std.mem.eql(u8, arg, "--dpt")) {
            config.mode = .dpt;
        } else if (std.mem.eql(u8, arg, "--dst")) {
            config.mode = .dst;
        } else if (std.mem.eql(u8, arg, "--lite")) {
            config.shape = .lite;
        } else if (std.mem.eql(u8, arg, "--swarm")) {
            config.shape = .swarm;
        } else if (std.mem.eql(u8, arg, "--performance")) {
            config.mode = .dpt;
            config.shape = .performance;
        } else if (std.mem.eql(u8, arg, "--dpt-compare")) {
            config.mode = .dpt;
            config.dpt_compare = true;
        } else if (std.mem.eql(u8, arg, "--dpt-baseline")) {
            config.mode = .dpt;
            config.dpt_compare = false;
        } else if (std.mem.startsWith(u8, arg, "--max-frames-per-response-x100=")) {
            config.dpt_thresholds.max_frames_per_response_x100 =
                std.fmt.parseInt(u64, arg["--max-frames-per-response-x100=".len..], 10) catch
                    config.dpt_thresholds.max_frames_per_response_x100;
        } else if (std.mem.startsWith(u8, arg, "--max-bytes-per-response=")) {
            config.dpt_thresholds.max_bytes_per_response =
                std.fmt.parseInt(u64, arg["--max-bytes-per-response=".len..], 10) catch
                    config.dpt_thresholds.max_bytes_per_response;
        } else if (std.mem.startsWith(u8, arg, "--max-blocked-ticks=")) {
            config.dpt_thresholds.max_blocked_ticks =
                std.fmt.parseInt(u64, arg["--max-blocked-ticks=".len..], 10) catch
                    config.dpt_thresholds.max_blocked_ticks;
        } else if (std.mem.startsWith(u8, arg, "--max-control-frames=")) {
            config.dpt_thresholds.max_control_frames =
                std.fmt.parseInt(u64, arg["--max-control-frames=".len..], 10) catch
                    config.dpt_thresholds.max_control_frames;
        } else if (std.mem.startsWith(u8, arg, "--max-protocol-errors=")) {
            config.dpt_thresholds.max_protocol_errors =
                std.fmt.parseInt(u64, arg["--max-protocol-errors=".len..], 10) catch
                    config.dpt_thresholds.max_protocol_errors;
        }
    }
    config.warmup_ticks = @min(config.warmup_ticks, config.ticks);
    return config;
}

fn parseRatio(text: []const u8) ?Prng.Ratio {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    const numerator = std.fmt.parseInt(u64, text[0..slash], 10) catch return null;
    const denominator = std.fmt.parseInt(u64, text[slash + 1 ..], 10) catch return null;
    if (denominator == 0) return null;
    if (numerator > denominator) return null;
    return Prng.ratio(numerator, denominator);
}

fn appendRatio(writer: *std.Io.Writer, ratio: Prng.Ratio) !void {
    try writer.print("{}/{}", .{ ratio.numerator, ratio.denominator });
}

fn effectiveWarmupTicks(config: Config) u64 {
    if (config.mode == .dst) return 0;
    return @min(config.warmup_ticks, config.ticks);
}

fn appendReplayCommand(writer: *std.Io.Writer, config: Config) !void {
    try writer.print(
        "zig build {s} -- --seed={} --ticks={} --warmup-ticks={} --profile={s} --packet-loss=",
        .{
            @tagName(config.mode),
            config.seed,
            config.ticks,
            effectiveWarmupTicks(config),
            @tagName(config.profile),
        },
    );
    try appendRatio(writer, config.packet_loss_probability);
    try writer.writeAll(" --packet-replay=");
    try appendRatio(writer, config.packet_replay_probability);
    try writer.print(
        " --path-capacity={} --packet-delay-ticks={} --max-frame-size={} --hpack-table-size={} --initial-window-size={} --request-body-size={} --response-body-size={}",
        .{
            config.path_capacity,
            config.packet_delay_ticks,
            config.max_frame_size,
            config.hpack_table_size,
            config.initial_window_size,
            config.request_body_size,
            config.response_body_size,
        },
    );
    if (config.dpt_compare) {
        try writer.print(
            " --dpt-compare --max-frames-per-response-x100={} --max-bytes-per-response={} --max-blocked-ticks={} --max-control-frames={} --max-protocol-errors={}",
            .{
                config.dpt_thresholds.max_frames_per_response_x100,
                config.dpt_thresholds.max_bytes_per_response,
                config.dpt_thresholds.max_blocked_ticks,
                config.dpt_thresholds.max_control_frames,
                config.dpt_thresholds.max_protocol_errors,
            },
        );
    }
}

fn writeFailure(init: std.process.Init, config: Config, err: anyerror) !void {
    var output_buffer: [1024]u8 = undefined;
    var output = std.Io.Writer.fixed(&output_buffer);
    try output.print(
        "failure={s} error={t}\nreplay=",
        .{ @tagName(classifyFailure(err)), err },
    );
    try appendReplayCommand(&output, config);
    try output.writeAll("\n");
    try std.Io.File.writeStreamingAll(.stderr(), init.io, output.buffered());
}

pub fn main(init: std.process.Init) !void {
    const config = parseArgs(init.minimal.args);
    const metrics = run(init.gpa, config) catch |err| {
        try writeFailure(init, config, err);
        return err;
    };

    var output_buffer: [2048]u8 = undefined;
    var output = std.Io.Writer.fixed(&output_buffer);
    try output.print(
        \\mode={s} shape={s} profile={s} seed={} ticks={} warmup_ticks={} measured_ticks={}
        \\packet_loss=
    , .{
        @tagName(config.mode),
        @tagName(config.shape),
        @tagName(config.profile),
        metrics.seed,
        metrics.ticks,
        metrics.warmup_ticks,
        metrics.measured_ticks,
    });
    try appendRatio(&output, config.packet_loss_probability);
    try output.writeAll(" packet_replay=");
    try appendRatio(&output, config.packet_replay_probability);
    try output.print(
        \\ path_capacity={} packet_delay_ticks={} max_frame_size={} hpack_table_size={} initial_window_size={} request_body_size={} response_body_size={} dpt_compare={} max_frames_per_response_x100={} max_bytes_per_response={} max_blocked_ticks={} max_control_frames={} max_protocol_errors={} actions={} ok={} protocol_errors={} frames_in={} frames_out={} bytes_out={} completed={} max_live_streams={} blocked_ticks={} digest={x}
        \\replay=
    , .{
        config.path_capacity,
        config.packet_delay_ticks,
        config.max_frame_size,
        config.hpack_table_size,
        config.initial_window_size,
        config.request_body_size,
        config.response_body_size,
        config.dpt_compare,
        config.dpt_thresholds.max_frames_per_response_x100,
        config.dpt_thresholds.max_bytes_per_response,
        config.dpt_thresholds.max_blocked_ticks,
        config.dpt_thresholds.max_control_frames,
        config.dpt_thresholds.max_protocol_errors,
        metrics.actions,
        metrics.successful_actions,
        metrics.protocol_errors,
        metrics.frames_in,
        metrics.frames_out,
        metrics.bytes_out,
        metrics.completed_responses,
        metrics.max_live_streams,
        metrics.blocked_ticks,
        metrics.digest,
    });
    try appendReplayCommand(&output, config);
    try output.writeAll("\n");
    try std.Io.File.writeStreamingAll(.stdout(), init.io, output.buffered());
}

test "protocol-aware DST perfect profile is deterministic" {
    const allocator = std.testing.allocator;
    const a = try run(allocator, .{ .seed = 7, .ticks = 64, .profile = .perfect });
    const b = try run(allocator, .{ .seed = 7, .ticks = 64, .profile = .perfect });
    try std.testing.expectEqual(a.actions, b.actions);
    try std.testing.expectEqual(a.frames_out, b.frames_out);
    try std.testing.expectEqual(a.bytes_out, b.bytes_out);
    try std.testing.expect(a.completed_responses > 0);
}

test "protocol-aware DPT produces deterministic counters" {
    const allocator = std.testing.allocator;
    const a = try run(allocator, .{
        .seed = 99,
        .ticks = 128,
        .profile = .hpack_pressure,
        .mode = .dpt,
    });
    const b = try run(allocator, .{
        .seed = 99,
        .ticks = 128,
        .profile = .hpack_pressure,
        .mode = .dpt,
    });
    try std.testing.expectEqual(a.bytes_out, b.bytes_out);
    try std.testing.expectEqual(a.response_headers_sent, b.response_headers_sent);
    try std.testing.expectEqual(a.response_data_sent, b.response_data_sent);
}

test "protocol-aware DPT compare enforces thresholds" {
    const allocator = std.testing.allocator;
    _ = try run(allocator, .{
        .seed = 99,
        .ticks = 128,
        .profile = .hpack_pressure,
        .mode = .dpt,
        .dpt_compare = true,
    });

    try std.testing.expectError(error.PerformanceRegression, run(allocator, .{
        .seed = 99,
        .ticks = 128,
        .profile = .hpack_pressure,
        .mode = .dpt,
        .dpt_compare = true,
        .dpt_thresholds = .{ .max_bytes_per_response = 1 },
    }));
}

test "swarm request body and settings knobs affect real connection" {
    const allocator = std.testing.allocator;
    const metrics = try run(allocator, .{
        .seed = 123,
        .ticks = 32,
        .profile = .perfect,
        .request_body_size = 32,
        .max_frame_size = min_frame_size,
        .hpack_table_size = 512,
        .initial_window_size = 8192,
    });
    try std.testing.expect(metrics.frames_in > metrics.actions);
    try std.testing.expect(metrics.completed_responses > 0);
}

test "response body size knob affects deterministic output bytes" {
    const allocator = std.testing.allocator;
    const small = try run(allocator, .{
        .seed = 7,
        .ticks = 32,
        .profile = .perfect,
        .response_body_size = 0,
    });
    const large = try run(allocator, .{
        .seed = 7,
        .ticks = 32,
        .profile = .perfect,
        .response_body_size = 64,
    });
    try std.testing.expect(large.bytes_out > small.bytes_out);
}
