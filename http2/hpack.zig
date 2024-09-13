const std = @import("std");
const assert = std.debug.assert;

const huffman = @import("huffman.zig").Huffman;

/// HPACK: Header Compression for HTTP/2
///
/// This module provides encoding and decoding of HTTP/2 header fields using the HPACK format.
pub const Hpack = struct {
    /// Static Table as defined by the HPACK specification
    pub const StaticTable = struct {
        const entries = &[_]HeaderField{
            HeaderField{ .name = ":authority", .value = "" },
            HeaderField{ .name = ":method", .value = "GET" },
            HeaderField{ .name = ":method", .value = "POST" },
            HeaderField{ .name = ":path", .value = "/" },
            HeaderField{ .name = ":path", .value = "/index.html" },
            HeaderField{ .name = ":scheme", .value = "http" },
            HeaderField{ .name = ":scheme", .value = "https" },
            HeaderField{ .name = ":status", .value = "200" },
            HeaderField{ .name = ":status", .value = "204" },
            HeaderField{ .name = ":status", .value = "206" },
            HeaderField{ .name = ":status", .value = "304" },
            HeaderField{ .name = ":status", .value = "400" },
            HeaderField{ .name = ":status", .value = "404" },
            HeaderField{ .name = ":status", .value = "500" },
            HeaderField{ .name = "accept-charset", .value = "" },
            HeaderField{ .name = "accept-encoding", .value = "gzip, deflate" },
            HeaderField{ .name = "accept-language", .value = "" },
            HeaderField{ .name = "accept-ranges", .value = "" },
            HeaderField{ .name = "accept", .value = "" },
            HeaderField{ .name = "access-control-allow-origin", .value = "" },
            HeaderField{ .name = "age", .value = "" },
            HeaderField{ .name = "allow", .value = "" },
            HeaderField{ .name = "authorization", .value = "" },
            HeaderField{ .name = "cache-control", .value = "" },
            HeaderField{ .name = "content-disposition", .value = "" },
            HeaderField{ .name = "content-encoding", .value = "" },
            HeaderField{ .name = "content-language", .value = "" },
            HeaderField{ .name = "content-length", .value = "" },
            HeaderField{ .name = "content-location", .value = "" },
            HeaderField{ .name = "content-range", .value = "" },
            HeaderField{ .name = "content-type", .value = "" },
            HeaderField{ .name = "cookie", .value = "" },
            HeaderField{ .name = "date", .value = "" },
            HeaderField{ .name = "etag", .value = "" },
            HeaderField{ .name = "expect", .value = "" },
            HeaderField{ .name = "expires", .value = "" },
            HeaderField{ .name = "from", .value = "" },
            HeaderField{ .name = "host", .value = "" },
            HeaderField{ .name = "if-match", .value = "" },
            HeaderField{ .name = "if-modified-since", .value = "" },
            HeaderField{ .name = "if-none-match", .value = "" },
            HeaderField{ .name = "if-range", .value = "" },
            HeaderField{ .name = "if-unmodified-since", .value = "" },
            HeaderField{ .name = "last-modified", .value = "" },
            HeaderField{ .name = "link", .value = "" },
            HeaderField{ .name = "location", .value = "" },
            HeaderField{ .name = "max-forwards", .value = "" },
            HeaderField{ .name = "proxy-authenticate", .value = "" },
            HeaderField{ .name = "proxy-authorization", .value = "" },
            HeaderField{ .name = "range", .value = "" },
            HeaderField{ .name = "referer", .value = "" },
            HeaderField{ .name = "refresh", .value = "" },
            HeaderField{ .name = "retry-after", .value = "" },
            HeaderField{ .name = "server", .value = "" },
            HeaderField{ .name = "set-cookie", .value = "" },
            HeaderField{ .name = "strict-transport-security", .value = "" },
            HeaderField{ .name = "transfer-encoding", .value = "" },
            HeaderField{ .name = "user-agent", .value = "" },
            HeaderField{ .name = "vary", .value = "" },
            HeaderField{ .name = "via", .value = "" },
            HeaderField{ .name = "www-authenticate", .value = "" },
        };

        /// Get a static table entry by index
        pub fn get(index: usize) HeaderField {
            assert(index < entries.len);
            return entries[index];
        }

        /// Find the index of a header field in the static table based on name and value
        pub fn getStaticIndex(name: []const u8, value: []const u8) ?usize {
            for (entries, 0..) |entry, index| {
                if (std.mem.eql(u8, name, entry.name) and std.mem.eql(u8, value, entry.value)) {
                    return index + 1; // Indices start from 1
                }
            }
            return null;
        }
    };

    /// Dynamic Table for HPACK
    pub const DynamicTable = struct {
        table: std.ArrayList(HeaderField),
        max_size: usize,

        /// Initialize a dynamic table with a given maximum size
        pub fn init(allocator: *std.mem.Allocator, max_size: usize) !DynamicTable {
            return DynamicTable{
                .table = std.ArrayList(HeaderField).init(allocator.*),
                .max_size = max_size,
            };
        }

        /// Add an entry to the dynamic table
        pub fn addEntry(self: *DynamicTable, entry: HeaderField) !void {
            const entry_size = entry.name.len + entry.value.len + 32; // HPACK spec overhead

            if (entry_size > self.max_size) {
                // Clear table if entry size exceeds the table's maximum size.
                try self.table.resize(0); // Clear entire table
                return; // Do not add the oversized entry
            }

            // Evict entries until there's enough space for the new one
            while (self.getSize() + entry_size > self.max_size and self.table.items.len > 0) {
                _ = self.table.pop();
            }

            // Add the new entry to the front (most recent at index 0)
            try self.table.insert(0, entry);
        }

        fn getSize(self: *DynamicTable) usize {
            var size: usize = 0;
            for (self.table.items) |entry| {
                size += entry.name.len + entry.value.len + 32;
            }
            return size;
        }

        /// Get an entry from the dynamic table by index
        pub fn getEntry(self: *DynamicTable, index: usize) !HeaderField {
            if (index >= self.table.items.len) {
                return error.InvalidIndex;
            }
            // Entries are ordered from most recent to oldest
            return self.table.items[index];
        }

        /// Get an entry from the dynamic table by HPACK index
        pub fn getEntryByHpackIndex(self: *DynamicTable, index: usize) !HeaderField {
            // HPACK dynamic table indices start from StaticTable.entries.len + 1 and increase
            const position = index - Hpack.StaticTable.entries.len - 1;
            if (position >= self.table.items.len) {
                return error.InvalidIndex;
            }
            // Entries are ordered from most recent to oldest
            return self.table.items[position];
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

    // HPACK integer decoding based on RFC 7541 (Section 5.1)
    pub fn decodeInt(prefix_size: u8, encoded: []const u8) !usize {
        if (prefix_size < 1 or prefix_size > 8) return error.InvalidPrefixSize;

        const max_prefix_value = (@as(usize, 1) << @intCast(prefix_size)) - 1;
        const max_prefix_value_u8: u8 = @intCast(max_prefix_value);
        var value: usize = encoded[0] & max_prefix_value_u8;

        if (value < max_prefix_value) return value;

        var shift: u6 = 0;
        var cursor: usize = 1;
        while (cursor < encoded.len) {
            const byte = encoded[cursor];
            cursor += 1;

            value += (@as(usize, byte & 0x7F) << shift);
            shift += 7;
            if ((byte & 0x80) == 0) break;
        }

        return value;
    }

    // HPACK integer encoding based on RFC 7541 (Section 5.1)
    pub fn encodeInt(value: usize, prefix_size: u8) ![]u8 {
        if (prefix_size < 1 or prefix_size > 8) return error.InvalidPrefixSize;

        var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
        defer buffer.deinit();

        const prefix_size_u6: u6 = @intCast(prefix_size);
        const max_prefix_value = (@as(usize, 1) << prefix_size_u6) - 1;

        if (value < max_prefix_value) {
            try buffer.append(@intCast(value));
        } else {
            try buffer.append(@intCast(max_prefix_value));
            var remainder = value - max_prefix_value;
            while (remainder >= 128) {
                try buffer.append(@intCast((remainder % 128) + 128));
                remainder = remainder / 128;
            }
            try buffer.append(@intCast(remainder));
        }
        return buffer.toOwnedSlice();
    }

    pub fn encodeHeaderField(field: HeaderField, dynamic_table: *DynamicTable) ![]u8 {
        const allocator = std.heap.page_allocator;
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        const static_index = Hpack.StaticTable.getStaticIndex(field.name, field.value);
        if (static_index) |idx| {
            // Indexed Header Field Representation (Section 6.1)
            var encoded_index = try Hpack.encodeInt(idx, 7);
            encoded_index[0] |= 0x80; // Set the first bit to 1
            try buffer.appendSlice(encoded_index);
        } else {
            // Literal Header Field with Incremental Indexing (Section 6.2)
            try buffer.append(0x40); // Literal with incremental indexing, first byte

            // Encode the header name
            var name_buffer = std.ArrayList(u8).init(allocator);
            defer name_buffer.deinit();

            // Encode the length of the name
            const name_len_encoded = try Hpack.encodeInt(field.name.len, 7);

            // Append the encoded length
            try name_buffer.appendSlice(name_len_encoded);

            // Append the name bytes
            try name_buffer.appendSlice(field.name);

            // Encode the header value
            var value_buffer = std.ArrayList(u8).init(allocator);
            defer value_buffer.deinit();

            // Encode the length of the value
            const value_len_encoded = try Hpack.encodeInt(field.value.len, 7);

            // Append the encoded length
            try value_buffer.appendSlice(value_len_encoded);

            // Append the value bytes
            try value_buffer.appendSlice(field.value);

            // Append name and value to the buffer
            try buffer.appendSlice(name_buffer.items);
            try buffer.appendSlice(value_buffer.items);

            // Add the header field to the dynamic table
            try dynamic_table.addEntry(field);
        }

        return buffer.toOwnedSlice();
    }

    pub fn decodeHeaderField(payload: []const u8, dynamic_table: *DynamicTable) !HeaderField {
        if (payload.len == 0) return error.InvalidEncoding;

        const first_byte = payload[0];

        if ((first_byte & 0x80) != 0) {
            // Indexed Header Field Representation (Section 6.1)
            const index = try Hpack.decodeInt(7, payload);

            if (index == 0) return error.InvalidEncoding;

            if (index <= Hpack.StaticTable.entries.len) {
                return Hpack.StaticTable.get(index - 1);
            } else {
                return try dynamic_table.getEntryByHpackIndex(index);
            }
        } else if ((first_byte & 0x40) != 0) {
            // Literal Header Field with Incremental Indexing (Section 6.2)
            var cursor: usize = 1;

            // Decode name
            const name_len = try Hpack.decodeInt(7, payload[cursor..]);
            cursor += 1; // Adjust cursor for name length byte(s)
            const name = payload[cursor .. cursor + name_len];
            cursor += name_len;

            // Decode value
            const value_len = try Hpack.decodeInt(7, payload[cursor..]);
            cursor += 1; // Adjust cursor for value length byte(s)
            const value = payload[cursor .. cursor + value_len];

            const field = HeaderField{ .name = name, .value = value };
            try dynamic_table.addEntry(field);

            return field;
        } else {
            // Other representations not implemented
            return error.UnsupportedRepresentation;
        }
    }
};

// Tests

test "Dynamic table handles oversized entry correctly" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 100); // Small size to test oversized entry
    defer dynamic_table.table.deinit();

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
    try std.testing.expect(dynamic_table.table.items.len == 0);
}

test "Dynamic table add and retrieve" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();

    // Set a reasonable dynamic table size of 4096 for this test
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);

    const field = Hpack.HeaderField.init("content-length", "1234");
    try dynamic_table.addEntry(field);

    const retrieved = try dynamic_table.getEntry(0);
    try std.testing.expect(std.mem.eql(u8, field.name, retrieved.name));
    try std.testing.expect(std.mem.eql(u8, field.value, retrieved.value));
}

test "HPACK dynamic table missing field" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);
    defer dynamic_table.table.deinit();

    // Try to get an entry from an empty dynamic table
    _ = dynamic_table.getEntry(0) catch |err| {
        // Expect an InvalidIndex error
        try std.testing.expect(err == error.InvalidIndex);
        return;
    };

    // If we get here, the dynamic table was not empty as expected
    try std.testing.expect(false);
}

// Adjusted unit test covering the dynamic table indexing issue
test "Dynamic table indexing conforms to HPACK specification" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);
    defer dynamic_table.table.deinit();

    const field1 = Hpack.HeaderField.init("custom-header1", "value1");
    const field2 = Hpack.HeaderField.init("custom-header2", "value2");

    // Encode header fields
    _ = try Hpack.encodeHeaderField(field1, &dynamic_table);
    _ = try Hpack.encodeHeaderField(field2, &dynamic_table);

    // Dynamic table should have 2 entries now
    try std.testing.expectEqual(@as(usize, 2), dynamic_table.table.items.len);

    // Check indices
    const index1 = Hpack.StaticTable.entries.len + 2; // First dynamic entry
    const index2 = Hpack.StaticTable.entries.len + 1; // Second dynamic entry

    // Decode header fields using their indices
    var index_buffer = std.ArrayList(u8).init(allocator);
    defer index_buffer.deinit();

    // Encode index2
    {
        var encoded_index = try Hpack.encodeInt(index2, 7);
        encoded_index[0] |= 0x80; // Set the first bit to 1
        try index_buffer.appendSlice(encoded_index);
        const payload = try index_buffer.toOwnedSlice();
        const decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table);

        try std.testing.expectEqualStrings(field2.name, decoded_field.name);
        try std.testing.expectEqualStrings(field2.value, decoded_field.value);
        try index_buffer.resize(0);
    }

    // Encode index1
    {
        var encoded_index = try Hpack.encodeInt(index1, 7);
        encoded_index[0] |= 0x80; // Set the first bit to 1
        try index_buffer.appendSlice(encoded_index);
        const payload = try index_buffer.toOwnedSlice();
        const decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table);
        try std.testing.expectEqualStrings(field1.name, decoded_field.name);
        try std.testing.expectEqualStrings(field1.value, decoded_field.value);
    }
}
