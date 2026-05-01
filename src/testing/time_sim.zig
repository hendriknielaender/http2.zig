//! Deterministic tick-based clock for simulation testing.
//!
//! In a deterministic simulation, time must not depend on the host machine's
//! wall clock. This module provides a counter-based clock that advances only
//! when explicitly ticked, making all time-dependent behaviour reproducible.
//!
//! Each tick represents a fixed quantum of simulated time. Network delays,
//! timeouts, and flow-control deadlines are all expressed in ticks.

const std = @import("std");
const assert = std.debug.assert;

/// A duration in simulated nanoseconds.
pub const Duration = struct {
    ns: u64,

    pub fn from_ms(ms: u64) Duration {
        return .{ .ns = ms * std.time.ns_per_ms };
    }

    pub fn from_us(us: u64) Duration {
        return .{ .ns = us * std.time.ns_per_us };
    }
};

/// A point in simulated monotonic time.
pub const Instant = struct {
    ns: u64,

    pub fn elapsed(now: Instant, earlier: Instant) Duration {
        assert(now.ns >= earlier.ns);
        return .{ .ns = now.ns - earlier.ns };
    }
};

/// Deterministic time source driven by ticks.
pub const TimeSim = struct {
    /// The simulated elapsed nanoseconds per tick.
    resolution_ns: u64,

    /// The number of ticks elapsed since initialisation.
    ticks: u64,

    pub fn init(resolution_ns: u64) TimeSim {
        assert(resolution_ns > 0);
        return .{
            .resolution_ns = resolution_ns,
            .ticks = 0,
        };
    }

    /// Advance time by one tick.
    pub fn tick(self: *TimeSim) void {
        self.ticks += 1;
    }

    /// Current simulated time in nanoseconds.
    pub fn now_ns(self: *const TimeSim) u64 {
        return self.ticks * self.resolution_ns;
    }

    /// Current simulated instant.
    pub fn now(self: *const TimeSim) Instant {
        return .{ .ns = self.now_ns() };
    }

    /// Duration between now and an earlier instant.
    pub fn duration_since(self: *const TimeSim, earlier: Instant) Duration {
        const current_ns = self.now_ns();
        assert(earlier.ns <= current_ns);
        return .{ .ns = current_ns - earlier.ns };
    }

    /// Convert a Duration into ticks, rounding up.
    pub fn duration_to_ticks(self: *const TimeSim, duration: Duration) u64 {
        return (duration.ns + self.resolution_ns - 1) / self.resolution_ns;
    }
};

// --- Tests ---

test "tick advances time" {
    var ts = TimeSim.init(std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u64, 0), ts.now_ns());
    ts.tick();
    try std.testing.expectEqual(std.time.ns_per_ms, ts.now_ns());
    ts.tick();
    try std.testing.expectEqual(2 * std.time.ns_per_ms, ts.now_ns());
}

test "ticks is monotonic" {
    var ts = TimeSim.init(1_000_000);
    try std.testing.expectEqual(@as(u64, 0), ts.ticks);
    var previous: u64 = 0;
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        ts.tick();
        try std.testing.expect(ts.ticks > previous);
        previous = ts.ticks;
    }
}

test "now returns correct instant" {
    var ts = TimeSim.init(std.time.ns_per_ms);
    ts.tick();
    ts.tick();
    ts.tick();
    const instant = ts.now();
    try std.testing.expectEqual(3 * std.time.ns_per_ms, instant.ns);
}

test "elapsed computes correct duration" {
    var ts = TimeSim.init(std.time.ns_per_ms);
    const start = ts.now();
    var i: u32 = 0;
    while (i < 10) : (i += 1) ts.tick();
    const elapsed = Instant.elapsed(ts.now(), start);
    try std.testing.expectEqual(10 * std.time.ns_per_ms, elapsed.ns);
}

test "duration_to_ticks rounds up" {
    var ts = TimeSim.init(std.time.ns_per_ms);
    const dur = Duration.from_ms(5);
    try std.testing.expectEqual(@as(u64, 5), ts.duration_to_ticks(dur));

    const dur_partial = Duration{ .ns = std.time.ns_per_ms + 1 };
    try std.testing.expectEqual(@as(u64, 2), ts.duration_to_ticks(dur_partial));
}

test "Duration from_ms and from_us" {
    const dur_ms = Duration.from_ms(100);
    try std.testing.expectEqual(100 * std.time.ns_per_ms, dur_ms.ns);

    const dur_us = Duration.from_us(500);
    try std.testing.expectEqual(500 * std.time.ns_per_us, dur_us.ns);

    try std.testing.expectEqual(dur_ms.ns, Duration.from_us(100_000).ns);
}

test "multiple clocks are independent" {
    var ts_a = TimeSim.init(std.time.ns_per_ms);
    var ts_b = TimeSim.init(std.time.ns_per_ms);

    ts_a.tick();
    ts_a.tick();

    ts_b.tick();

    try std.testing.expectEqual(2 * std.time.ns_per_ms, ts_a.now_ns());
    try std.testing.expectEqual(std.time.ns_per_ms, ts_b.now_ns());
}
