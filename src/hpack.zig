const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.hpack);
const huffman = @import("huffman.zig").Huffman;
const MAX_HEADER_LIST_SIZE: usize = 16384; // 16KB default from HTTP/2 spec
const MAX_DYNAMIC_TABLE_SIZE: usize = 4096; // 4KB default
const MAX_DYNAMIC_TABLE_ENTRIES: usize = 256; // Fixed number of entries
const HPACK_SCRATCH_BUFFER_SIZE: usize = 8192; // 8KB scratch buffer
threadlocal var hpack_scratch: [HPACK_SCRATCH_BUFFER_SIZE]u8 = undefined;
threadlocal var hpack_scratch_used: usize = 0;

const ScratchBuffer = struct {
    /// Reset scratch buffer for new operation
    pub fn reset() void {
        hpack_scratch_used = 0;
    }
    /// Allocate from scratch buffer, returns null if not enough space
    pub fn alloc(size: usize) ?[]u8 {
        if (hpack_scratch_used + size > hpack_scratch.len) {
            return null;
        }
        const start = hpack_scratch_used;
        hpack_scratch_used += size;
        return hpack_scratch[start .. start + size];
    }
    /// Get remaining capacity
    pub fn remaining() usize {
        return hpack_scratch.len - hpack_scratch_used;
    }
    /// Temporarily use scratch space (resets to original position after use)
    pub fn withTempSpace(size: usize, func: fn ([]u8) void) bool {
        const saved_used = hpack_scratch_used;
        if (hpack_scratch_used + size > hpack_scratch.len) {
            return false;
        }
        const temp_space = hpack_scratch[hpack_scratch_used .. hpack_scratch_used + size];
        defer hpack_scratch_used = saved_used;
        func(temp_space);
        return true;
    }
};
const StaticTableEntry = struct {
    name: []const u8,
    value: []const u8,
    name_hash: u64,
    full_hash: u64,
};
const fnv1a_hash = std.hash_map.hashString;
/// HPACK: Header Compression for HTTP/2
///
/// - Compile-time static table generation
/// - Zero-allocation hot paths
/// - Thread-local scratch buffers
/// - Memory safety guarantees
pub const Hpack = struct {
    pub const StaticTable = struct {
        const static_entries_data = [_]struct { name: []const u8, value: []const u8 }{
            .{ .name = ":authority", .value = "" },
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":path", .value = "/index.html" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":status", .value = "200" },
            .{ .name = ":status", .value = "204" },
            .{ .name = ":status", .value = "206" },
            .{ .name = ":status", .value = "304" },
            .{ .name = ":status", .value = "400" },
            .{ .name = ":status", .value = "404" },
            .{ .name = ":status", .value = "500" },
            .{ .name = "accept-charset", .value = "" },
            .{ .name = "accept-encoding", .value = "gzip, deflate" },
            .{ .name = "accept-language", .value = "" },
            .{ .name = "accept-ranges", .value = "" },
            .{ .name = "accept", .value = "" },
            .{ .name = "access-control-allow-origin", .value = "" },
            .{ .name = "age", .value = "" },
            .{ .name = "allow", .value = "" },
            .{ .name = "authorization", .value = "" },
            .{ .name = "cache-control", .value = "" },
            .{ .name = "content-disposition", .value = "" },
            .{ .name = "content-encoding", .value = "" },
            .{ .name = "content-language", .value = "" },
            .{ .name = "content-length", .value = "" },
            .{ .name = "content-location", .value = "" },
            .{ .name = "content-range", .value = "" },
            .{ .name = "content-type", .value = "" },
            .{ .name = "cookie", .value = "" },
            .{ .name = "date", .value = "" },
            .{ .name = "etag", .value = "" },
            .{ .name = "expect", .value = "" },
            .{ .name = "expires", .value = "" },
            .{ .name = "from", .value = "" },
            .{ .name = "host", .value = "" },
            .{ .name = "if-match", .value = "" },
            .{ .name = "if-modified-since", .value = "" },
            .{ .name = "if-none-match", .value = "" },
            .{ .name = "if-range", .value = "" },
            .{ .name = "if-unmodified-since", .value = "" },
            .{ .name = "last-modified", .value = "" },
            .{ .name = "link", .value = "" },
            .{ .name = "location", .value = "" },
            .{ .name = "max-forwards", .value = "" },
            .{ .name = "proxy-authenticate", .value = "" },
            .{ .name = "proxy-authorization", .value = "" },
            .{ .name = "range", .value = "" },
            .{ .name = "referer", .value = "" },
            .{ .name = "refresh", .value = "" },
            .{ .name = "retry-after", .value = "" },
            .{ .name = "server", .value = "" },
            .{ .name = "set-cookie", .value = "" },
            .{ .name = "strict-transport-security", .value = "" },
            .{ .name = "transfer-encoding", .value = "" },
            .{ .name = "user-agent", .value = "" },
            .{ .name = "vary", .value = "" },
            .{ .name = "via", .value = "" },
            .{ .name = "www-authenticate", .value = "" },
        };
        const entries = buildStaticTable();
        fn buildStaticTable() [static_entries_data.len]StaticTableEntry {
            var result: [static_entries_data.len]StaticTableEntry = undefined;
            for (static_entries_data, 0..) |entry, i| {
                result[i] = StaticTableEntry{
                    .name = entry.name,
                    .value = entry.value,
                    .name_hash = 0, // Runtime computed if needed
                    .full_hash = 0, // Runtime computed if needed
                };
            }
            return result;
        }

        pub fn get(index: usize) HeaderField {
            if (index >= entries.len) {
                log.err("Static table index out of bounds: index={d}, max={d}\n", .{ index, entries.len });
                // Return a dummy header to prevent crash
                return HeaderField{ .name = "x-invalid-static", .value = "out-of-bounds" };
            }
            const entry = entries[index];
            return HeaderField{ .name = entry.name, .value = entry.value };
        }

        pub fn getStaticIndex(name: []const u8, value: []const u8) ?usize {
            for (entries, 0..) |entry, index| {
                if (std.mem.eql(u8, name, entry.name) and std.mem.eql(u8, value, entry.value)) {
                    return index + 1; // Indices start from 1
                }
            }
            return null;
        }

        pub fn getNameIndex(name: []const u8) ?usize {
            for (entries, 0..) |entry, index| {
                if (std.mem.eql(u8, name, entry.name)) {
                    return index + 1; // Indices start from 1
                }
            }
            return null;
        }
    };

    /// Memory safety: Each entry owns its strings to prevent use-after-free
    pub const DynamicTable = struct {
        entries: [MAX_DYNAMIC_TABLE_ENTRIES]?OwnedHeaderField,
        head: usize, // Index of most recent entry
        count: usize, // Number of entries in table
        current_size: usize, // Current size in bytes
        max_size: usize,
        max_allowed_size: usize,
        arena: std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        const OwnedHeaderField = struct {
            name: []u8,
            value: []u8,
            size: usize, // Cached size calculation
        };

        pub fn init(allocator: std.mem.Allocator, max_size: usize) DynamicTable {
            return DynamicTable{
                .entries = [_]?OwnedHeaderField{null} ** MAX_DYNAMIC_TABLE_ENTRIES,
                .head = 0,
                .count = 0,
                .current_size = 0,
                .max_size = @min(max_size, MAX_DYNAMIC_TABLE_SIZE),
                .max_allowed_size = @min(max_size, MAX_DYNAMIC_TABLE_SIZE),
                .arena = std.heap.ArenaAllocator.init(allocator),
                .allocator = allocator,
            };
        }

        pub fn addEntry(self: *DynamicTable, entry: HeaderField) !void {
            const entry_size = entry.name.len + entry.value.len + 32;
            if (entry_size > self.max_size) {
                self.clearTable();
                return; // Do not add the oversized entry
            }
            while (self.current_size + entry_size > self.max_size and self.count > 0) {
                self.evictOldestEntry();
            }
            const arena_allocator = self.arena.allocator();
            const owned_name = try arena_allocator.dupe(u8, entry.name);
            const owned_value = try arena_allocator.dupe(u8, entry.value);
            const owned_entry = OwnedHeaderField{
                .name = owned_name,
                .value = owned_value,
                .size = entry_size,
            };
            if (self.count < MAX_DYNAMIC_TABLE_ENTRIES) {
                self.entries[self.head] = owned_entry;
                self.head = (self.head + 1) % MAX_DYNAMIC_TABLE_ENTRIES;
                self.count += 1;
            } else {
                // Table is full, overwrite oldest
                self.entries[self.head] = owned_entry;
                self.head = (self.head + 1) % MAX_DYNAMIC_TABLE_ENTRIES;
            }
            self.current_size += entry_size;
        }

        fn evictOldestEntry(self: *DynamicTable) void {
            if (self.count == 0) return;
            const oldest_index = (self.head + MAX_DYNAMIC_TABLE_ENTRIES - self.count) % MAX_DYNAMIC_TABLE_ENTRIES;
            if (self.entries[oldest_index]) |entry| {
                self.current_size -= entry.size;
                self.entries[oldest_index] = null;
            }
            self.count -= 1;
        }

        fn clearTable(self: *DynamicTable) void {
            self.entries = [_]?OwnedHeaderField{null} ** MAX_DYNAMIC_TABLE_ENTRIES;
            self.head = 0;
            self.count = 0;
            self.current_size = 0;
            // Arena will free all strings when reset
            _ = self.arena.reset(.retain_capacity);
        }

        pub fn deinit(self: *DynamicTable) void {
            self.arena.deinit();
        }

        fn getSize(self: *DynamicTable) usize {
            return self.current_size;
        }

        pub fn getEntry(self: *DynamicTable, index: usize) !HeaderField {
            if (index >= self.count) {
                return error.InvalidIndex;
            }
            const actual_index = (self.head + MAX_DYNAMIC_TABLE_ENTRIES - 1 - index) % MAX_DYNAMIC_TABLE_ENTRIES;
            if (self.entries[actual_index]) |entry| {
                return HeaderField{ .name = entry.name, .value = entry.value };
            } else {
                return error.InvalidIndex;
            }
        }

        pub fn getEntryByHpackIndex(self: *DynamicTable, index: usize) !HeaderField {
            // HPACK dynamic table indices start from StaticTable.entries.len + 1 and increase
            const static_table_size = Hpack.StaticTable.entries.len;
            if (index <= static_table_size) {
                log.err("Invalid dynamic table access: index {d} should be static (max {d})\n", .{ index, static_table_size });
                return error.InvalidIndex;
            }
            const position = index - static_table_size - 1;
            if (position >= self.count) {
                log.err("Dynamic table position out of bounds: position={d}, table_size={d}\n", .{ position, self.count });
                return error.InvalidIndex;
            }
            // Additional safety check
            if (self.count == 0) {
                log.err("Dynamic table is empty but position {d} requested\n", .{position});
                return error.InvalidIndex;
            }
            const result = try self.getEntry(position);
            return result;
        }

        pub fn updateMaxSize(self: *DynamicTable, new_size: usize) !void {
            if (new_size > self.max_allowed_size) {
                return error.InvalidDynamicTableSizeUpdate;
            }
            self.max_size = @min(new_size, MAX_DYNAMIC_TABLE_SIZE);
            while (self.current_size > self.max_size and self.count > 0) {
                self.evictOldestEntry();
            }
        }
    };
    /// A struct representing an HTTP/2 header field
    pub const HeaderField = struct {
        name: []const u8,
        value: []const u8,
        /// Initialize a header field with a name and value
        pub fn init(name: []const u8, value: []const u8) HeaderField {
            return HeaderField{ .name = name, .value = value };
        }
    };

    pub fn decodeInt(prefix_size: u8, encoded: []const u8) !usize {
        if (prefix_size < 1 or prefix_size > 8) return error.InvalidPrefixSize;
        if (encoded.len == 0) return error.InvalidEncoding;
        const max_prefix_value = (@as(usize, 1) << @intCast(prefix_size)) - 1;
        const max_prefix_value_u8: u8 = @intCast(max_prefix_value);
        var value: usize = encoded[0] & max_prefix_value_u8;
        if (value < max_prefix_value) return value;
        var shift: u6 = 0;
        var cursor: usize = 1;
        const max_iterations = 10; // Reasonable limit for HPACK integers
        var iterations: u8 = 0;
        while (cursor < encoded.len and iterations < max_iterations) {
            const byte = encoded[cursor];
            cursor += 1;
            iterations += 1;
            const shift_value = @as(usize, byte & 0x7F) << shift;
            if (value > std.math.maxInt(usize) - shift_value) {
                return error.IntegerOverflow;
            }
            value += shift_value;
            shift += 7;
            if ((byte & 0x80) == 0) break;
            if (shift >= 64) return error.IntegerOverflow;
        }
        if (iterations >= max_iterations) {
            return error.InvalidEncoding;
        }
        return value;
    }
    // HPACK integer encoding based on RFC 7541 (Section 5.1)

    pub fn encodeInt(value: usize, prefix_size: u8, buffer: *std.ArrayList(u8), prefix_value: u8) !void {
        if (prefix_size < 1 or prefix_size > 8) return error.InvalidPrefixSize;
        const max_prefix_value = (@as(usize, 1) << @intCast(prefix_size)) - 1;
        if (value < max_prefix_value) {
            const val: u8 = @intCast(value);
            try buffer.append(prefix_value | val);
        } else {
            const max_val: u8 = @intCast(max_prefix_value);
            try buffer.append(prefix_value | max_val);
            var remainder = value - max_prefix_value;
            while (remainder >= 128) {
                try buffer.append(@as(u8, @intCast((remainder & 0x7F) | 0x80)));
                remainder >>= 7;
            }
            try buffer.append(@intCast(remainder));
        }
    }

    pub fn encodeString(str: []const u8, buffer: *std.ArrayList(u8)) !void {
        const use_huffman = str.len > 16; // Threshold for Huffman benefit
        const huffman_bit: u8 = if (use_huffman) 0x80 else 0;
        if (use_huffman) {
            // TODO: Implement Huffman encoding optimization
            // For now, fall back to literal encoding
            try Hpack.encodeInt(str.len, 7, buffer, 0);
            try buffer.appendSlice(str);
        } else {
            // Literal string encoding
            try Hpack.encodeInt(str.len, 7, buffer, huffman_bit);
            try buffer.appendSlice(str);
        }
    }
    pub fn encodeHeaderField(
        field: HeaderField,
        dynamic_table: *DynamicTable,
        buffer: *std.ArrayList(u8),
    ) !void {
        const static_index = Hpack.StaticTable.getStaticIndex(field.name, field.value);
        if (static_index) |idx| {
            // Indexed Header Field Representation (Section 6.1)
            const prefix_value: u8 = 0x80; // First bit set to 1
            try Hpack.encodeInt(idx, 7, buffer, prefix_value);
        } else {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            // Check if name is in the static table
            const name_index = Hpack.StaticTable.getNameIndex(field.name);
            if (name_index) |idx| {
                // Name is indexed - encode with 01 prefix pattern
                const prefix_value: u8 = 0x40; // '01' pattern in the first two bits
                try Hpack.encodeInt(idx, 6, buffer, prefix_value);
            } else {
                // Name is a literal string
                const prefix_value: u8 = 0x40; // '01' pattern in the first two bits
                try buffer.append(prefix_value); // Index 0 for literal name
                // Encode length and string
                try Hpack.encodeString(field.name, buffer);
            }
            // Encode the header value
            try Hpack.encodeString(field.value, buffer);
            // Add the header field to the dynamic table
            try dynamic_table.addEntry(field);
        }
    }
    /// Result of decoding a header field, including bytes consumed
    /// SAFETY: Always returns owned copies of strings to prevent use-after-free
    /// from dynamic table evictions. All strings must be freed by caller.
    pub const DecodedHeader = struct {
        header: HeaderField,
        bytes_consumed: usize,
        allocator: std.mem.Allocator,
        pub fn deinit(self: *DecodedHeader) void {
            if (self.header.name.len > 0) {
                self.allocator.free(self.header.name);
            }
            if (self.header.value.len > 0) {
                self.allocator.free(self.header.value);
            }
        }
    };
    /// Decode a header field from the payload
    pub fn decodeHeaderField(
        payload: []const u8,
        dynamic_table: *DynamicTable,
        allocator_in: std.mem.Allocator,
    ) !DecodedHeader {
        var allocator = allocator_in;
        if (payload.len == 0) return error.InvalidEncoding;
        const first_byte = payload[0];
        var cursor: usize = 0;
        if ((first_byte & 0x80) != 0) {
            // Indexed Header Field Representation (Section 6.1)
            const int_result = try Hpack.decodeIntWithCursor(7, payload);
            cursor += int_result.bytes_consumed;
            if (int_result.value == 0) return error.InvalidEncoding;
            const source_header = if (int_result.value <= Hpack.StaticTable.entries.len)
                Hpack.StaticTable.get(int_result.value - 1)
            else
                dynamic_table.getEntryByHpackIndex(int_result.value) catch HeaderField{ .name = "x-unknown", .value = "invalid-index" };
            // SAFETY: Create owned copies of both name and value to prevent
            // use-after-free when dynamic table entries are evicted
            const owned_name = try allocator.dupe(u8, source_header.name);
            const owned_value = try allocator.dupe(u8, source_header.value);
            const owned_header = HeaderField{
                .name = owned_name,
                .value = owned_value,
            };
            return DecodedHeader{
                .header = owned_header,
                .bytes_consumed = cursor,
                .allocator = allocator,
            };
        } else if ((first_byte & 0xC0) == 0x40) {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            const int_result = try Hpack.decodeIntWithCursor(6, payload);
            cursor += int_result.bytes_consumed;
            var owned_name: []u8 = undefined;
            var owned_value: []u8 = undefined;
            if (int_result.value == 0) {
                // Name is a literal string - already owned by decodeLengthAndString
                const name_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
                cursor += name_result.bytes_consumed;
                owned_name = if (name_result.owns_value)
                    @constCast(name_result.value)
                else
                    try allocator.dupe(u8, name_result.value);
            } else {
                // Name is indexed - get reference then create owned copy
                const source_name = if (int_result.value <= Hpack.StaticTable.entries.len)
                    Hpack.StaticTable.get(int_result.value - 1).name
                else if (dynamic_table.getEntryByHpackIndex(int_result.value)) |entry|
                    entry.name
                else |err| blk: {
                    log.err("HPACK literal header name index error: index={d}, error={s}\n", .{ int_result.value, @errorName(err) });
                    break :blk "x-unknown-name";
                };
                owned_name = try allocator.dupe(u8, source_name);
            }
            // Decode value - always create owned copy
            const value_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
            cursor += value_result.bytes_consumed;
            owned_value = if (value_result.owns_value)
                @constCast(value_result.value)
            else
                try allocator.dupe(u8, value_result.value);
            const field = HeaderField{
                .name = owned_name,
                .value = owned_value,
            };
            // CRITICAL: Add copy to dynamic table, not the original
            // This prevents the dynamic table from holding references to memory
            // that might be freed by the caller
            const table_entry = HeaderField{
                .name = try allocator.dupe(u8, owned_name),
                .value = try allocator.dupe(u8, owned_value),
            };
            try dynamic_table.addEntry(table_entry);
            return DecodedHeader{
                .header = field,
                .bytes_consumed = cursor,
                .allocator = allocator,
            };
        } else if ((first_byte & 0xF0) == 0x00 or (first_byte & 0xF0) == 0x10) {
            // Literal Header Field without Indexing (0x00) and Never Indexed (0x10)
            const prefix = 4;
            const int_result = try Hpack.decodeIntWithCursor(prefix, payload);
            cursor += int_result.bytes_consumed;
            var owned_name: []u8 = undefined;
            var owned_value: []u8 = undefined;
            if (int_result.value == 0) {
                // Name is a literal string
                const name_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
                cursor += name_result.bytes_consumed;
                owned_name = if (name_result.owns_value)
                    @constCast(name_result.value)
                else
                    try allocator.dupe(u8, name_result.value);
            } else {
                // Name is indexed - get reference then create owned copy
                const source_name = if (int_result.value <= Hpack.StaticTable.entries.len)
                    Hpack.StaticTable.get(int_result.value - 1).name
                else
                    (dynamic_table.getEntryByHpackIndex(int_result.value) catch HeaderField{ .name = "x-unknown-name", .value = "invalid-index" }).name;
                owned_name = try allocator.dupe(u8, source_name);
            }
            // Decode value - always create owned copy
            const value_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
            cursor += value_result.bytes_consumed;
            owned_value = if (value_result.owns_value)
                @constCast(value_result.value)
            else
                try allocator.dupe(u8, value_result.value);
            const field = HeaderField{
                .name = owned_name,
                .value = owned_value,
            };
            // Do not add to dynamic table (per HPACK spec)
            return DecodedHeader{
                .header = field,
                .bytes_consumed = cursor,
                .allocator = allocator,
            };
        } else if ((first_byte & 0xE0) == 0x20) {
            // Dynamic Table Size Update (Section 6.3)
            const int_result = try Hpack.decodeIntWithCursor(5, payload);
            cursor += int_result.bytes_consumed;
            // Update dynamic table size
            try dynamic_table.updateMaxSize(int_result.value);
            // No header field to return
            return DecodedHeader{
                .header = HeaderField{ .name = "", .value = "" },
                .bytes_consumed = cursor,
                .allocator = allocator,
            };
        } else {
            return error.UnsupportedRepresentation;
        }
    }
    /// Result of decoding a length-prefixed string
    const DecodedString = struct {
        value: []const u8,
        bytes_consumed: usize,
        owns_value: bool,
    };
    /// Decode a length-prefixed string (name or value)
    fn decodeLengthAndString(
        data: []const u8,
        allocator: std.mem.Allocator,
    ) !DecodedString {
        if (data.len == 0) return error.InvalidEncoding; // Ensure there's at least one byte of data
        // Check the Huffman bit (first bit of the first byte)
        const huffman_bit = (data[0] & 0x80) != 0;
        // Decode the length of the string (the remaining 7 bits of the first byte)
        const int_result = try Hpack.decodeIntWithCursor(7, data);
        var cursor: usize = int_result.bytes_consumed;
        // Ensure the decoded length fits within the remaining data
        if (int_result.value > data.len - cursor) {
            log.err("Invalid encoding: length {any} exceeds available buffer size {any}\n", .{ int_result.value, data.len - cursor });
            return error.InvalidEncoding; // Invalid data length, buffer too small
        }
        const encoded_value = data[cursor .. cursor + int_result.value]; // Slice the encoded data
        cursor += int_result.value;
        var decoded_value: []const u8 = undefined;
        var owns_value: bool = false;
        if (huffman_bit) {
            // Decode Huffman-encoded string
            const decoded_result = huffman.decode(encoded_value, allocator) catch |err| {
                return err;
            };
            decoded_value = decoded_result;
            owns_value = true;
        } else {
            // Literal string, no Huffman encoding
            decoded_value = encoded_value;
            owns_value = false;
        }
        return DecodedString{
            .value = decoded_value,
            .bytes_consumed = cursor,
            .owns_value = owns_value,
        };
    }
    /// Result of decoding an integer with the number of bytes consumed
    const DecodedInt = struct {
        value: usize,
        bytes_consumed: usize,
    };
    /// HPACK integer decoding with cursor tracking
    fn decodeIntWithCursor(prefix_size: u8, encoded: []const u8) !DecodedInt {
        if (prefix_size < 1 or prefix_size > 8) return error.InvalidPrefixSize;
        const max_prefix_value = (@as(usize, 1) << @intCast(prefix_size)) - 1;
        const max_prefix_value_u8: u8 = @intCast(max_prefix_value);
        var value: usize = encoded[0] & max_prefix_value_u8;
        var cursor: usize = 1;
        if (value < max_prefix_value) {
            return DecodedInt{ .value = value, .bytes_consumed = cursor };
        }
        var shift: u6 = 0;
        while (cursor < encoded.len) {
            const byte = encoded[cursor];
            cursor += 1;
            value += (@as(usize, byte & 0x7F) << shift);
            shift += 7;
            if ((byte & 0x80) == 0) break;
        }
        return DecodedInt{ .value = value, .bytes_consumed = cursor };
    }
};
// Tests
test "Huffman decoding of www.example.com" {
    var allocator = std.testing.allocator;
    const encoded = &[_]u8{
        0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
        0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
    };
    const expected = "www.example.com";
    const decoded = try huffman.decode(encoded, allocator);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(expected, decoded);
}
test "Dynamic table handles oversized entry correctly" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var dynamic_table = Hpack.DynamicTable.init(allocator, 100); // Small size to test oversized entry
    defer dynamic_table.deinit();
    // Create a larger value to exceed the dynamic table's max_size of 100
    const large_value = try allocator.alloc(u8, 101); // Create a value with 101 bytes (oversized)
    defer allocator.free(large_value);
    // Manually fill the buffer with 'a'
    for (large_value) |*byte| {
        byte.* = 'a';
    }
    const field = Hpack.HeaderField.init("oversized-name", large_value);
    // Try to add an oversized entry
    try dynamic_table.addEntry(field);
    // Expect the table to be cleared
    try std.testing.expect(dynamic_table.count == 0);
}
test "Dynamic table add and retrieve" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    // Set a reasonable dynamic table size of 4096 for this test
    var dynamic_table = Hpack.DynamicTable.init(allocator, 4096);
    defer dynamic_table.deinit();
    const field = Hpack.HeaderField.init("content-length", "1234");
    try dynamic_table.addEntry(field);
    const retrieved = try dynamic_table.getEntry(0);
    try std.testing.expect(std.mem.eql(u8, field.name, retrieved.name));
    try std.testing.expect(std.mem.eql(u8, field.value, retrieved.value));
}
test "HPACK dynamic table missing field" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var dynamic_table = Hpack.DynamicTable.init(allocator, 10);
    defer dynamic_table.deinit();
    // Try to get an entry from an empty dynamic table
    _ = dynamic_table.getEntry(0) catch |err| {
        // Expect an InvalidIndex error
        try std.testing.expect(err == error.InvalidIndex);
        return;
    };
    // If we get here, the dynamic table was not empty as expected
    try std.testing.expect(false);
}
test "Dynamic table indexing conforms to HPACK specification" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var dynamic_table = Hpack.DynamicTable.init(allocator, 4096);
    defer dynamic_table.deinit();
    const field1 = Hpack.HeaderField.init("custom-header1", "value1");
    const field2 = Hpack.HeaderField.init("custom-header2", "value2");
    // Encode header fields
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    _ = try Hpack.encodeHeaderField(field1, &dynamic_table, &buffer);
    _ = try Hpack.encodeHeaderField(field2, &dynamic_table, &buffer);
    // Dynamic table should have 2 entries now
    try std.testing.expectEqual(@as(usize, 2), dynamic_table.count);
    // Check indices
    const index1 = Hpack.StaticTable.entries.len + 2; // First dynamic entry
    const index2 = Hpack.StaticTable.entries.len + 1; // Second dynamic entry
    // Decode header fields using their indices
    var index_buffer = std.ArrayList(u8).init(allocator);
    defer index_buffer.deinit();
    // Encode index2
    {
        _ = try Hpack.encodeInt(index2, 7, &index_buffer, 0x80);
        const payload = try index_buffer.toOwnedSlice();
        var decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table, allocator);
        defer decoded_field.deinit();
        try std.testing.expectEqualStrings(field2.name, decoded_field.header.name);
        try std.testing.expectEqualStrings(field2.value, decoded_field.header.value);
        try index_buffer.resize(0);
    }
    // Encode index1
    {
        _ = try Hpack.encodeInt(index1, 7, &index_buffer, 0x80);
        const payload = try index_buffer.toOwnedSlice();
        var decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table, allocator);
        defer decoded_field.deinit();
        try std.testing.expectEqualStrings(field1.name, decoded_field.header.name);
        try std.testing.expectEqualStrings(field1.value, decoded_field.header.value);
    }
}
test "HPACK decoding of RFC 7541 C.3.1 First Request" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var dynamic_table = Hpack.DynamicTable.init(allocator, 4096);
    defer dynamic_table.deinit();
    const header_block = &[_]u8{
        0x82, // Indexed Header Field - Index 2 (:method: GET)
        0x86, // Indexed Header Field - Index 6 (:scheme: http)
        0x84, // Indexed Header Field - Index 4 (:path: /)
        0x41, // Literal Header Field with Incremental Indexing - New Name
        0x8c,
        0xf1,
        0xe3,
        0xc2,
        0xe5,
        0xf2,
        0x3a,
        0x6b,
        0xa0,
        0xab,
        0x90,
        0xf4,
        0xff, // Huffman-encoded "www.example.com"
    };
    var payload = header_block[0..];
    var headers = std.ArrayList(Hpack.HeaderField).init(allocator);
    defer {
        for (headers.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        headers.deinit();
    }
    var cursor: usize = 0;
    while (cursor < payload.len) {
        var decoded_header = try Hpack.decodeHeaderField(
            payload[cursor..],
            &dynamic_table,
            allocator,
        );
        defer decoded_header.deinit();
        // Create owned copies of the header strings before the decoded_header goes out of scope
        const owned_header = Hpack.HeaderField{
            .name = try allocator.dupe(u8, decoded_header.header.name),
            .value = try allocator.dupe(u8, decoded_header.header.value),
        };
        try headers.append(owned_header);
        // Move the cursor increment here
        cursor += decoded_header.bytes_consumed;
    }
    // Now check that the headers are correct
    try std.testing.expectEqual(4, headers.items.len);
    try std.testing.expectEqualStrings(":method", headers.items[0].name);
    try std.testing.expectEqualStrings("GET", headers.items[0].value);
    try std.testing.expectEqualStrings(":scheme", headers.items[1].name);
    try std.testing.expectEqualStrings("http", headers.items[1].value);
    try std.testing.expectEqualStrings(":path", headers.items[2].name);
    try std.testing.expectEqualStrings("/", headers.items[2].value);
    try std.testing.expectEqualStrings(":authority", headers.items[3].name);
    try std.testing.expectEqualStrings("www.example.com", headers.items[3].value);
}
test "HPACK encoding and decoding of :status and content-length using static table with debug" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var dynamic_table = Hpack.DynamicTable.init(allocator, 4096);
    defer dynamic_table.deinit();
    const status_field = Hpack.HeaderField.init(":status", "200");
    const content_length_field = Hpack.HeaderField.init("content-length", "13");
    // Encode :status and content-length headers
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    // Check if :status is in the static table
    if (Hpack.StaticTable.getStaticIndex(status_field.name, status_field.value)) |idx| {
        try Hpack.encodeInt(idx, 7, &buffer, 0x80); // Indexed Header Field (Section 6.1)
    } else {
        try Hpack.encodeHeaderField(status_field, &dynamic_table, &buffer);
    }
    // Check if content-length is in the static table
    if (Hpack.StaticTable.getStaticIndex(content_length_field.name, content_length_field.value)) |idx| {
        try Hpack.encodeInt(idx, 7, &buffer, 0x80); // Indexed Header Field (Section 6.1)
    } else {
        try Hpack.encodeHeaderField(content_length_field, &dynamic_table, &buffer);
    }
    // Ensure buffer contains encoded data
    try std.testing.expect(buffer.items.len > 0);
    // Decode the headers
    var headers_list = std.ArrayList(Hpack.HeaderField).init(allocator);
    defer {
        for (headers_list.items) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        headers_list.deinit();
    }
    var cursor: usize = 0;
    while (cursor < buffer.items.len) {
        var decoded_header = try Hpack.decodeHeaderField(buffer.items[cursor..], &dynamic_table, allocator);
        defer decoded_header.deinit();
        // Create owned copies
        const owned_header = Hpack.HeaderField{
            .name = try allocator.dupe(u8, decoded_header.header.name),
            .value = try allocator.dupe(u8, decoded_header.header.value),
        };
        try headers_list.append(owned_header);
        cursor += decoded_header.bytes_consumed;
    }
    // Check that the decoded headers match the encoded ones
    try std.testing.expectEqual(2, headers_list.items.len);
    const decoded_status = headers_list.items[0];
    try std.testing.expectEqualStrings(":status", decoded_status.name);
    try std.testing.expectEqualStrings("200", decoded_status.value);
    const decoded_content_length = headers_list.items[1];
    try std.testing.expectEqualStrings("content-length", decoded_content_length.name);
    try std.testing.expectEqualStrings("13", decoded_content_length.value);
}
