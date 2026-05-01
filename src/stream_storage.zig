//! Per-connection stream slot storage with O(1) stream-id lookup.
//!
//! Manages a fixed pool of stream instances indexed by slot number and
//! accessible by stream-id through an open-addressed multiplicative hash
//! table.  The capacity is comptime-bounded so every allocation is a
//! simple array-index operation — no heap work on the hot path.
//!
//! Backshift-on-remove keeps probe chains contiguous, guaranteeing that
//! a `findIndex` that hits an empty bucket truly means "not present".

const std = @import("std");
const assert = std.debug.assert;

const DefaultStream = @import("stream.zig").DefaultStream;
const memory_budget = @import("memory_budget.zig");

const max_streams_per_connection = memory_budget.MemBudget.max_streams_per_connection;

/// Capacity must be a power of two and large enough that the table stays
/// well below 50 % load with `max_streams_per_connection` live entries.
/// This keeps the average probe length under two for any reasonable hash.
const lookup_capacity: u32 = 256;
const lookup_mask: u32 = lookup_capacity - 1;
const lookup_shift: u5 = 32 - 8;
const slot_index_empty: u8 = std.math.maxInt(u8);

comptime {
    assert(@popCount(lookup_capacity) == 1);
    assert(lookup_capacity >= max_streams_per_connection * 2);
    assert(max_streams_per_connection < slot_index_empty);
    assert((@as(u32, 1) << @as(u5, 32 - @as(u32, lookup_shift))) == lookup_capacity);
}

/// Per-connection storage for stream instances and the associated O(1)
/// lookup table.  All arrays are inline — no runtime allocation once the
/// struct is instantiated.
pub const StreamStorage = struct {
    slots: [max_streams_per_connection]DefaultStream.StreamInstance,
    ids: [max_streams_per_connection]u32,
    in_use: [max_streams_per_connection]bool,
    lookup_ids: [lookup_capacity]u32,
    lookup_indices: [lookup_capacity]u8,
    in_use_count: u8,

    const Self = @This();

    /// Initialise every array to its zero / empty state.
    pub fn init(self: *Self) void {
        self.* = .{
            .slots = undefined,
            .ids = [_]u32{0} ** max_streams_per_connection,
            .in_use = [_]bool{false} ** max_streams_per_connection,
            .lookup_ids = [_]u32{0} ** lookup_capacity,
            .lookup_indices = [_]u8{slot_index_empty} ** lookup_capacity,
            .in_use_count = 0,
        };
    }

    /// Reserve the first free slot for `stream_id` and insert it into
    /// the lookup table.  Returns the slot index, or an error when all
    /// slots are occupied.
    pub fn allocateSlot(self: *Self, stream_id: u32) !u8 {
        assert(stream_id > 0);

        var index: u8 = 0;
        while (index < max_streams_per_connection) : (index += 1) {
            if (self.in_use[index]) continue;

            self.ids[index] = stream_id;
            self.in_use[index] = true;
            assert(self.in_use_count < max_streams_per_connection);
            self.in_use_count += 1;
            self.insertLookup(stream_id, index);
            return index;
        }

        return error.MaxConcurrentStreamsExceeded;
    }

    /// Release the slot at `index`: clear the in-use flag, remove the
    /// entry from the lookup table, and decrement the active count.
    pub fn releaseSlot(self: *Self, index: u8) void {
        assert(index < max_streams_per_connection);
        assert(self.in_use[index]);

        const stream_id = self.ids[index];
        assert(stream_id > 0);

        self.removeLookup(stream_id);
        self.ids[index] = 0;
        self.in_use[index] = false;
        assert(self.in_use_count > 0);
        self.in_use_count -= 1;
    }

    /// O(1) average lookup by stream-id.  Returns the slot index or null.
    pub fn findIndex(self: *const Self, stream_id: u32) ?u8 {
        assert(stream_id > 0);

        var probe: u32 = lookupHash(stream_id);
        var probes: u32 = 0;
        while (probes < lookup_capacity) : (probes += 1) {
            const bucket_id = self.lookup_ids[probe];
            if (bucket_id == 0) return null;
            if (bucket_id == stream_id) {
                const slot_index = self.lookup_indices[probe];
                assert(slot_index < max_streams_per_connection);
                assert(self.in_use[slot_index]);
                assert(self.ids[slot_index] == stream_id);
                return slot_index;
            }
            probe = (probe + 1) & lookup_mask;
        }
        unreachable;
    }

    /// O(1) average lookup.  Returns a pointer to the stream or null.
    pub fn find(self: *Self, stream_id: u32) ?*DefaultStream.StreamInstance {
        const index = self.findIndex(stream_id) orelse return null;
        return &self.slots[index];
    }

    /// Direct access to a stream by its slot index.
    /// Caller must guarantee the slot is in use.
    pub fn findBySlotIndex(self: *Self, index: u8) *DefaultStream.StreamInstance {
        assert(index < max_streams_per_connection);
        assert(self.in_use[index]);
        return &self.slots[index];
    }

    /// Current number of occupied slots.
    pub fn activeCount(self: *const Self) u8 {
        assert(self.in_use_count <= max_streams_per_connection);
        return self.in_use_count;
    }

    /// Reset all slots and the lookup table to the empty state.
    pub fn reset(self: *Self) void {
        @memset(&self.lookup_ids, 0);
        @memset(&self.lookup_indices, slot_index_empty);
        self.in_use = [_]bool{false} ** max_streams_per_connection;
        self.ids = [_]u32{0} ** max_streams_per_connection;
        self.in_use_count = 0;
    }

    /// Check whether a slot is currently occupied.
    pub fn isInUse(self: *const Self, index: u8) bool {
        assert(index < max_streams_per_connection);
        return self.in_use[index];
    }

    /// Return the stream-id stored for the given slot index.
    pub fn slotId(self: *const Self, index: u8) u32 {
        assert(index < max_streams_per_connection);
        return self.ids[index];
    }

    /// Maximum number of concurrent streams this storage can hold.
    pub fn maxSlots() u32 {
        return max_streams_per_connection;
    }

    // -------------------------------------------------------------------
    //  Lookup-table internals
    // -------------------------------------------------------------------

    fn insertLookup(self: *Self, stream_id: u32, slot_index: u8) void {
        assert(stream_id > 0);
        assert(slot_index < max_streams_per_connection);

        var probe: u32 = lookupHash(stream_id);
        var probes: u32 = 0;
        while (probes < lookup_capacity) : (probes += 1) {
            const bucket_id = self.lookup_ids[probe];
            assert(bucket_id != stream_id);
            if (bucket_id == 0) {
                self.lookup_ids[probe] = stream_id;
                self.lookup_indices[probe] = slot_index;
                return;
            }
            probe = (probe + 1) & lookup_mask;
        }
        unreachable;
    }

    fn removeLookup(self: *Self, stream_id: u32) void {
        assert(stream_id > 0);

        var hole: u32 = lookupHash(stream_id);
        var probes: u32 = 0;
        while (self.lookup_ids[hole] != stream_id) {
            assert(self.lookup_ids[hole] != 0);
            hole = (hole + 1) & lookup_mask;
            probes += 1;
            assert(probes < lookup_capacity);
        }

        var next: u32 = (hole + 1) & lookup_mask;
        while (self.lookup_ids[next] != 0) {
            const next_id = self.lookup_ids[next];
            const next_home = lookupHash(next_id);
            const displacement = (next -% next_home) & lookup_mask;
            const gap_distance = (next -% hole) & lookup_mask;
            if (displacement >= gap_distance) {
                self.lookup_ids[hole] = next_id;
                self.lookup_indices[hole] = self.lookup_indices[next];
                hole = next;
            }
            next = (next + 1) & lookup_mask;
        }
        self.lookup_ids[hole] = 0;
        self.lookup_indices[hole] = slot_index_empty;
    }
};

/// Knuth multiplicative hash; the constant is floor(2^32 / φ).
/// Produces strong avalanche on the upper bits for the sequential odd
/// stream IDs that dominate real HTTP/2 traffic.
inline fn lookupHash(stream_id: u32) u32 {
    return (stream_id *% 0x9E3779B1) >> lookup_shift;
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test "allocate and find by id" {
    var storage: StreamStorage = undefined;
    storage.init();

    const index_1 = try storage.allocateSlot(1);
    try std.testing.expectEqual(@as(u8, 0), index_1);
    try std.testing.expectEqual(@as(u32, 1), storage.slotId(0));
    try std.testing.expect(storage.isInUse(0));
    _ = storage.find(1).?;

    try std.testing.expectEqual(@as(u8, 1), storage.activeCount());
}

test "find returns null for missing stream" {
    var storage: StreamStorage = undefined;
    storage.init();

    try std.testing.expect(storage.findIndex(42) == null);
    try std.testing.expect(storage.find(42) == null);
}

test "allocate until full then error" {
    var storage: StreamStorage = undefined;
    storage.init();

    var stream_id: u32 = 1;
    while (stream_id <= max_streams_per_connection * 2 + 1) : (stream_id += 2) {
        if (storage.allocateSlot(stream_id)) |_| {
            continue;
        } else |err| {
            try std.testing.expectEqual(error.MaxConcurrentStreamsExceeded, err);
            try std.testing.expectEqual(max_streams_per_connection, storage.activeCount());
            return;
        }
    }

    try std.testing.expect(false);
}

test "release and reallocate reuses slot" {
    var storage: StreamStorage = undefined;
    storage.init();

    const index = try storage.allocateSlot(1);
    try std.testing.expect(storage.find(1) != null);

    storage.releaseSlot(index);
    try std.testing.expect(storage.find(1) == null);
    try std.testing.expect(!storage.isInUse(index));
    try std.testing.expectEqual(@as(u8, 0), storage.activeCount());

    const new_index = try storage.allocateSlot(3);
    try std.testing.expectEqual(index, new_index);
    try std.testing.expectEqual(@as(u32, 3), storage.slotId(new_index));
}

test "multiple insert and lookup stress" {
    var storage: StreamStorage = undefined;
    storage.init();

    var stream_id: u32 = 1;
    while (stream_id < max_streams_per_connection * 2) : (stream_id += 2) {
        _ = try storage.allocateSlot(stream_id);
    }

    stream_id = 1;
    while (stream_id < max_streams_per_connection * 2) : (stream_id += 2) {
        const index = storage.findIndex(stream_id).?;
        try std.testing.expectEqual(stream_id, storage.slotId(index));
    }
}

test "findIndex returns correct slot index" {
    var storage: StreamStorage = undefined;
    storage.init();

    const index_5 = try storage.allocateSlot(5);
    const index_3 = try storage.allocateSlot(3);
    _ = try storage.allocateSlot(1);

    try std.testing.expectEqual(index_3, storage.findIndex(3).?);
    try std.testing.expectEqual(index_5, storage.findIndex(5).?);
}

test "reset clears all state" {
    var storage: StreamStorage = undefined;
    storage.init();

    _ = try storage.allocateSlot(1);
    _ = try storage.allocateSlot(3);

    storage.reset();

    try std.testing.expect(storage.find(1) == null);
    try std.testing.expect(storage.find(3) == null);
    try std.testing.expectEqual(@as(u8, 0), storage.activeCount());
}
