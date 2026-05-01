//! Deterministic pseudo-random number generator for simulation testing.
//!
//! Uses the xoroshiro128++ algorithm, matching TigerBeetle's PRNG choice.
//! Separated from `std.Random` to ensure determinism across Zig versions and
//! to avoid floating-point operations that can differ across architectures.
//!
//! The zero-allocation design allows many hundreds of engine-internal PRNG
//! instances (e.g. one per simulated connection) without any runtime overhead.

const std = @import("std");
const assert = std.debug.assert;

s: [4]u64,

const Self = @This();

/// A rational number used to express probabilities.
pub const Ratio = struct {
    numerator: u64,
    denominator: u64,

    pub fn zero() Ratio {
        return .{ .numerator = 0, .denominator = 1 };
    }
};

/// Construct a `Ratio`.
pub fn ratio(numerator: u64, denominator: u64) Ratio {
    assert(denominator > 0);
    assert(numerator <= denominator);
    return .{ .numerator = numerator, .denominator = denominator };
}

/// Initialise the PRNG from a single 64-bit seed.
pub fn init(seed: u64) Self {
    var s = seed;
    return .{ .s = .{
        split_mix_64(&s),
        split_mix_64(&s),
        split_mix_64(&s),
        split_mix_64(&s),
    } };
}

fn split_mix_64(s: *u64) u64 {
    s.* +%= 0x9e3779b97f4a7c15;
    var z = s.*;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

fn next(self: *Self) u64 {
    const r = std.math.rotl(u64, self.s[0] +% self.s[3], 23) +% self.s[0];
    const t = self.s[1] << 17;
    self.s[2] ^= self.s[0];
    self.s[3] ^= self.s[1];
    self.s[1] ^= self.s[2];
    self.s[0] ^= self.s[3];
    self.s[2] ^= t;
    self.s[3] = std.math.rotl(u64, self.s[3], 45);
    return r;
}

/// Fill `target` with random bytes.
pub fn fill(self: *Self, target: []u8) void {
    var i: u32 = 0;
    const aligned_len = target.len - (target.len & 7);
    while (i < aligned_len) : (i += 8) {
        var n = self.next();
        comptime var j: u32 = 0;
        inline while (j < 8) : (j += 1) {
            target[i + j] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
    if (i != target.len) {
        var n = self.next();
        while (i < target.len) : (i += 1) {
            target[i] = @as(u8, @truncate(n));
            n >>= 8;
        }
    }
}

/// Return a uniformly distributed unsigned integer.
pub fn int(self: *Self, comptime Int: type) Int {
    comptime assert(@typeInfo(Int).int.signedness == .unsigned);
    if (Int == u64) return self.next();
    if (@sizeOf(Int) < @sizeOf(u64)) return @truncate(self.next());
    var result: Int = undefined;
    self.fill(std.mem.asBytes(&result));
    return result;
}

/// Return an unsigned integer uniformly distributed in `0..max` (inclusive).
pub fn int_inclusive(self: *Self, Int: type, max: Int) Int {
    comptime assert(@typeInfo(Int).int.signedness == .unsigned);
    if (max == std.math.maxInt(Int)) return self.int(Int);

    const bits = @typeInfo(Int).int.bits;
    const less_than = max + 1;
    var x = self.int(Int);
    var m = std.math.mulWide(Int, x, less_than);
    var l: Int = @truncate(m);

    if (l < less_than) {
        var t = -%less_than;
        if (t >= less_than) {
            t -= less_than;
            if (t >= less_than) {
                t %= less_than;
            }
        }
        while (l < t) {
            x = self.int(Int);
            m = std.math.mulWide(Int, x, less_than);
            l = @truncate(m);
        }
    }
    return @intCast(m >> bits);
}

/// Return an unsigned integer in `min..max` (inclusive).
pub fn range_inclusive(self: *Self, Int: type, min: Int, max: Int) Int {
    comptime assert(@typeInfo(Int).int.signedness == .unsigned);
    assert(min <= max);
    return min + self.int_inclusive(Int, max - min);
}

/// Return a random valid index into `slice`.
pub fn index(self: *Self, slice: anytype) u32 {
    assert(slice.len > 0);
    return @intCast(self.int_inclusive(u32, @intCast(slice.len - 1)));
}

/// Return `true` with probability 0.5.
pub fn boolean(self: *Self) bool {
    return self.next() & 1 == 1;
}

/// Return `true` with the given rational probability.
pub fn chance(self: *Self, probability: Ratio) bool {
    assert(probability.denominator > 0);
    assert(probability.numerator <= probability.denominator);
    return self.int_inclusive(u64, probability.denominator - 1) < probability.numerator;
}

/// Fisher-Yates shuffle the slice in place.
pub fn shuffle(self: *Self, comptime T: type, slice: []T) void {
    var i: u32 = 0;
    while (i < slice.len) : (i += 1) {
        const j = self.int_inclusive(u32, i);
        std.mem.swap(T, &slice[i], &slice[j]);
    }
}

/// Return a random value from an enum, with uniform probability.
pub fn enum_uniform(self: *Self, comptime Enum: type) Enum {
    const values = std.enums.values(Enum);
    return values[self.index(values)];
}

// --- Tests ---

test "init from seed produces deterministic output" {
    const prng_a = Self.init(42);
    const prng_b = Self.init(42);
    var a = prng_a;
    var b = prng_b;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(a.next(), b.next());
    }
}

test "different seeds produce different output" {
    var a = Self.init(42);
    var b = Self.init(99);
    var match_count: u32 = 0;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        if (a.next() == b.next()) match_count += 1;
    }
    try std.testing.expect(match_count < 20);
}

test "int_inclusive produces values within range" {
    var prng = Self.init(1);
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        const value = prng.int_inclusive(u32, 99);
        try std.testing.expect(value <= 99);
    }
}

test "int_inclusive max value produces all bits" {
    var prng = Self.init(1);
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        const value = prng.int_inclusive(u32, std.math.maxInt(u32));
        _ = value;
    }
}

test "range_inclusive produces values within bounds" {
    var prng = Self.init(1);
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        const value = prng.range_inclusive(u32, 10, 20);
        try std.testing.expect(value >= 10);
        try std.testing.expect(value <= 20);
    }
}

test "boolean produces both values" {
    var prng = Self.init(1);
    var seen_true = false;
    var seen_false = false;
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        if (prng.boolean()) seen_true = true else seen_false = true;
    }
    try std.testing.expect(seen_true);
    try std.testing.expect(seen_false);
}

test "chance respects ratio" {
    var prng = Self.init(1);
    const chance_ratio = ratio(1, 100);
    var true_count: u32 = 0;
    var i: u32 = 0;
    while (i < 100000) : (i += 1) {
        if (prng.chance(chance_ratio)) true_count += 1;
    }
    try std.testing.expect(true_count > 500);
    try std.testing.expect(true_count < 1500);
}

test "chance zero never fires" {
    var prng = Self.init(1);
    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expect(!prng.chance(Ratio.zero()));
    }
}

test "shuffle preserves all elements" {
    var prng = Self.init(1);
    var elements = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    prng.shuffle(u32, &elements);
    var sum: u32 = 0;
    for (elements) |e| sum += e;
    try std.testing.expectEqual(@as(u32, 36), sum);
}

test "index returns valid index" {
    var prng = Self.init(1);
    const arr = [_]u8{0} ** 10;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        const idx = prng.index(&arr);
        try std.testing.expect(idx < 10);
    }
}

test "fill writes random bytes" {
    var prng = Self.init(1);
    var buf: [64]u8 = undefined;
    prng.fill(&buf);
    var non_zero: u32 = 0;
    for (buf) |b| {
        if (b != 0) non_zero += 1;
    }
    try std.testing.expect(non_zero > 0);
}

test "ratio with same seed is deterministic" {
    var a = Self.init(42);
    var b = Self.init(42);
    const r = ratio(1, 3);
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        try std.testing.expectEqual(a.chance(r), b.chance(r));
    }
}
