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

        /// Find the index of a header name in the static table
        pub fn getNameIndex(name: []const u8) ?usize {
            for (entries, 0..) |entry, index| {
                if (std.mem.eql(u8, name, entry.name)) {
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
        max_allowed_size: usize,

        /// Initialize a dynamic table with a given maximum size
        pub fn init(allocator: *std.mem.Allocator, max_size: usize) !DynamicTable {
            return DynamicTable{
                .table = std.ArrayList(HeaderField).init(allocator.*),
                .max_size = max_size,
                .max_allowed_size = max_size,
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

        pub fn updateMaxSize(self: *DynamicTable, new_size: usize) !void {
            if (new_size > self.max_allowed_size) {
                return error.InvalidDynamicTableSizeUpdate;
            }
            self.max_size = new_size;

            // Evict entries if necessary
            while (self.getSize() > self.max_size and self.table.items.len > 0) {
                _ = self.table.pop();
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

    pub fn encodeHeaderField(
        field: HeaderField,
        dynamic_table: *DynamicTable,
        buffer: *std.ArrayList(u8),
    ) ![]u8 {
        const static_index = Hpack.StaticTable.getStaticIndex(field.name, field.value);
        if (static_index) |idx| {
            // Indexed Header Field Representation (Section 6.1)
            var encoded_index = try Hpack.encodeInt(idx, 7);
            encoded_index[0] |= 0x80; // Set the first bit to 1
            try buffer.appendSlice(encoded_index);
        } else {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            try buffer.append(0x40); // Literal with incremental indexing

            // Check if name is in the static table
            const name_index = Hpack.StaticTable.getNameIndex(field.name);
            if (name_index) |idx| {
                // Name is indexed
                const name_idx_encoded = try Hpack.encodeInt(idx, 6);
                try buffer.appendSlice(name_idx_encoded);
            } else {
                // Name is a literal string
                // Encode length and string
                const name_len_encoded = try Hpack.encodeInt(field.name.len, 7);
                try buffer.appendSlice(name_len_encoded);
                try buffer.appendSlice(field.name);
            }

            // Encode the header value
            const value_len_encoded = try Hpack.encodeInt(field.value.len, 7);
            try buffer.appendSlice(value_len_encoded);
            try buffer.appendSlice(field.value);

            // Add the header field to the dynamic table
            try dynamic_table.addEntry(field);
        }

        return buffer.toOwnedSlice();
    }

    /// Result of decoding a header field, including bytes consumed
    pub const DecodedHeader = struct {
        header: HeaderField,
        bytes_consumed: usize,
        allocator: ?*std.mem.Allocator,
        owns_name: bool,
        owns_value: bool,

        pub fn deinit(self: *DecodedHeader) void {
            if (self.allocator) |allocator| {
                if (self.owns_name and self.header.name.len > 0) {
                    allocator.free(self.header.name);
                }
                if (self.owns_value and self.header.value.len > 0) {
                    allocator.free(self.header.value);
                }
            }
        }
    };

    /// Decode a header field from the payload
    pub fn decodeHeaderField(
        payload: []const u8,
        dynamic_table: *DynamicTable,
        allocator: *std.mem.Allocator,
    ) !DecodedHeader {
        if (payload.len == 0) return error.InvalidEncoding;

        const first_byte = payload[0];
        var cursor: usize = 0;
        var owns_name: bool = false;
        var owns_value: bool = false;

        if ((first_byte & 0x80) != 0) {
            // Indexed Header Field Representation (Section 6.1)
            const int_result = try Hpack.decodeIntWithCursor(7, payload);
            cursor += int_result.bytes_consumed;

            if (int_result.value == 0) return error.InvalidEncoding;

            var header: HeaderField = undefined;

            if (int_result.value <= Hpack.StaticTable.entries.len) {
                header = Hpack.StaticTable.get(int_result.value - 1);
            } else {
                header = try dynamic_table.getEntryByHpackIndex(int_result.value);
            }

            return DecodedHeader{
                .header = header,
                .bytes_consumed = cursor,
                .allocator = null,
                .owns_name = false,
                .owns_value = false,
            };
        } else if ((first_byte & 0xC0) == 0x40) {
            // Literal Header Field with Incremental Indexing (Section 6.2.1)
            const int_result = try Hpack.decodeIntWithCursor(6, payload);
            cursor += int_result.bytes_consumed;

            var header_name: []const u8 = undefined;

            if (int_result.value == 0) {
                // Name is a literal string
                const name_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
                cursor += name_result.bytes_consumed;
                header_name = name_result.value;
                owns_name = name_result.owns_value;
            } else {
                // Name is indexed
                if (int_result.value <= Hpack.StaticTable.entries.len) {
                    header_name = Hpack.StaticTable.get(int_result.value - 1).name;
                } else {
                    const entry = try dynamic_table.getEntryByHpackIndex(int_result.value);
                    header_name = entry.name;
                }
                owns_name = false;
            }

            // Decode value
            const value_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
            cursor += value_result.bytes_consumed;
            owns_value = value_result.owns_value;

            const field = HeaderField{
                .name = header_name,
                .value = value_result.value,
            };
            // Add to dynamic table
            try dynamic_table.addEntry(field);

            return DecodedHeader{
                .header = field,
                .bytes_consumed = cursor,
                .allocator = allocator,
                .owns_name = owns_name,
                .owns_value = owns_value,
            };
        } else if ((first_byte & 0xF0) == 0x00 or (first_byte & 0xF0) == 0x10) {
            // Literal Header Field without Indexing (0x00) and Never Indexed (0x10)
            const prefix = 4;
            const int_result = try Hpack.decodeIntWithCursor(prefix, payload);
            cursor += int_result.bytes_consumed;

            var header_name: []const u8 = undefined;

            if (int_result.value == 0) {
                // Name is a literal string
                const name_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
                cursor += name_result.bytes_consumed;
                header_name = name_result.value;
                owns_name = name_result.owns_value;
            } else {
                // Name is indexed
                if (int_result.value <= Hpack.StaticTable.entries.len) {
                    header_name = Hpack.StaticTable.get(int_result.value - 1).name;
                } else {
                    const entry = try dynamic_table.getEntryByHpackIndex(int_result.value);
                    header_name = entry.name;
                }
                owns_name = false;
            }

            // Decode value
            const value_result = try Hpack.decodeLengthAndString(payload[cursor..], allocator);
            cursor += value_result.bytes_consumed;
            owns_value = value_result.owns_value;

            const field = HeaderField{
                .name = header_name,
                .value = value_result.value,
            };
            // Do not add to dynamic table

            return DecodedHeader{
                .header = field,
                .bytes_consumed = cursor,
                .allocator = allocator,
                .owns_name = owns_name,
                .owns_value = owns_value,
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
                .allocator = null,
                .owns_name = false,
                .owns_value = false,
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
        allocator: *std.mem.Allocator,
    ) !DecodedString {
        if (data.len == 0) return error.InvalidEncoding;

        const huffman_bit = (data[0] & 0x80) != 0;
        const int_result = try Hpack.decodeIntWithCursor(7, data);
        var cursor: usize = int_result.bytes_consumed;

        if (data.len < cursor + int_result.value) {
            return error.InvalidEncoding;
        }

        const encoded_value = data[cursor .. cursor + int_result.value];
        cursor += int_result.value;

        var decoded_value: []const u8 = undefined;
        var owns_value: bool = false;

        if (huffman_bit) {
            // Use the provided allocator
            const decoded_result = huffman.decode(encoded_value, allocator) catch |err| {
                return err;
            };
            decoded_value = decoded_result;
            owns_value = true;
        } else {
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
    const decoded = try huffman.decode(encoded, &allocator);
    defer allocator.free(decoded);

    try std.testing.expectEqualStrings(expected, decoded);
}

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

test "Dynamic table indexing conforms to HPACK specification" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);
    defer dynamic_table.table.deinit();

    const field1 = Hpack.HeaderField.init("custom-header1", "value1");
    const field2 = Hpack.HeaderField.init("custom-header2", "value2");

    // Encode header fields
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    _ = try Hpack.encodeHeaderField(field1, &dynamic_table, &buffer);
    _ = try Hpack.encodeHeaderField(field2, &dynamic_table, &buffer);

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

        var decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table, &allocator);
        defer decoded_field.deinit();

        try std.testing.expectEqualStrings(field2.name, decoded_field.header.name);
        try std.testing.expectEqualStrings(field2.value, decoded_field.header.value);
        try index_buffer.resize(0);
    }

    // Encode index1
    {
        var encoded_index = try Hpack.encodeInt(index1, 7);
        encoded_index[0] |= 0x80; // Set the first bit to 1
        try index_buffer.appendSlice(encoded_index);

        const payload = try index_buffer.toOwnedSlice();

        var decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table, &allocator);
        defer decoded_field.deinit();

        try std.testing.expectEqualStrings(field1.name, decoded_field.header.name);
        try std.testing.expectEqualStrings(field1.value, decoded_field.header.value);
    }
}

test "HPACK decoding of RFC 7541 C.3.1 First Request" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);
    defer dynamic_table.table.deinit();

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
    defer headers.deinit();

    var decoded_headers = std.ArrayList(Hpack.DecodedHeader).init(allocator);
    defer for (decoded_headers.items) |*decoded_header| {
        decoded_header.deinit();
    };
    defer decoded_headers.deinit();

    var cursor: usize = 0;
    while (cursor < payload.len) {
        const decoded_header = try Hpack.decodeHeaderField(
            payload[cursor..],
            &dynamic_table,
            &allocator,
        );
        // Append the decoded header to keep it alive
        try decoded_headers.append(decoded_header);

        try headers.append(decoded_header.header);

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
