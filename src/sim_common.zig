const std = @import("std");
const frame_mod = @import("frame.zig");
const packet_sim = @import("testing/packet_simulator.zig");

const Frame = frame_mod.Frame;
const FrameFlags = frame_mod.FrameFlags;
const FrameType = frame_mod.FrameType;
const Packet = packet_sim.Packet;

pub fn digestMix(value: u64, input: u64) u64 {
    return (value ^ input) *% 0x100000001b3;
}

pub fn isExpectedError(err: anyerror) bool {
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

pub fn packetFrameType(frame_type: FrameType) packet_sim.FrameType {
    return @enumFromInt(@intFromEnum(frame_type));
}

pub fn coreFrameType(frame_type: packet_sim.FrameType) FrameType {
    return @enumFromInt(@intFromEnum(frame_type));
}

pub fn frameFromPacket(packet: *const Packet) Frame {
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

pub fn SimWriter(comptime writer_capacity: usize) type {
    return struct {
        interface: std.Io.Writer,
        storage: [writer_capacity]u8 = undefined,

        const Self = @This();

        pub fn init() Self {
            var self: Self = undefined;
            self.interface = .fixed(&self.storage);
            return self;
        }

        pub fn written(self: *const Self) []const u8 {
            return self.interface.buffered();
        }
    };
}
