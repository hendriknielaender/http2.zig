const std = @import("std");
const assert = std.debug.assert;

const log = std.log.scoped(.hpack);

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
            const entry_size = entry.name.len + entry.value.len + 32;

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
                try buffer.append(@intCast((remainder % 128) + 128));
                remainder = remainder / 128;
            }
            try buffer.append(@intCast(remainder));
        }
    }

    pub fn encodeString(str: []const u8, buffer: *std.ArrayList(u8)) !void {
        log.debug("Encoding string: {s}, length: {d}\n", .{ str, str.len });

        // For simplicity, we're not using Huffman encoding here.
        // Set the Huffman bit to 0.
        const huffman_bit: u8 = 0;

        // Ensure the length is encoded correctly
        log.debug("Encoding string length: {d}\n", .{str.len});
        try Hpack.encodeInt(str.len, 7, buffer, huffman_bit);

        try buffer.appendSlice(str);

        log.debug("Encoded string: {any}\n", .{buffer.items});
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

        // Debugging output to show the buffer state before decoding
        log.debug("Decoding header at cursor position {any}, payload length: {any}\n", .{ cursor, payload.len });

        if ((first_byte & 0x80) != 0) {
            // Indexed Header Field Representation (Section 6.1)
            const int_result = try Hpack.decodeIntWithCursor(7, payload);
            cursor += int_result.bytes_consumed;

            log.debug("Indexed header field: decoded index={any}, cursor={any}\n", .{ int_result.value, cursor });

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

            log.debug("Literal header field: decoded name index={any}, cursor={any}\n", .{ int_result.value, cursor });

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

            log.debug("Decoded header field name: {s}, value: {s}\n", .{ header_name, value_result.value });

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
        if (data.len == 0) return error.InvalidEncoding; // Ensure there's at least one byte of data

        // Check the Huffman bit (first bit of the first byte)
        const huffman_bit = (data[0] & 0x80) != 0;

        // Decode the length of the string (the remaining 7 bits of the first byte)
        const int_result = try Hpack.decodeIntWithCursor(7, data);
        var cursor: usize = int_result.bytes_consumed;

        // Debugging output to check the state
        log.debug("Decoding string: huffman_bit={any}, decoded length={any}, cursor={any}\n", .{ huffman_bit, int_result.value, cursor });

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
            // Debugging Huffman decoding step
            log.debug("Decoding Huffman-encoded string of length {any}...\n", .{int_result.value});

            // Decode Huffman-encoded string
            const decoded_result = huffman.decode(encoded_value, allocator) catch |err| {
                return err;
            };
            decoded_value = decoded_result;
            owns_value = true;

            // Debugging output for Huffman decoding result
            log.debug("Decoded Huffman string: {s}\n", .{decoded_value});
        } else {
            // Literal string, no Huffman encoding
            decoded_value = encoded_value;
            owns_value = false;

            // Debugging output for literal string decoding
            log.debug("Decoded literal string: {s}\n", .{decoded_value});
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

        log.debug("Initial byte value: {any}, max_prefix_value: {any}, initial value: {any}, cursor: {any}\n", .{ encoded[0], max_prefix_value_u8, value, cursor });

        if (value < max_prefix_value) {
            log.debug("Decoded integer with value={any}, bytes_consumed={any}\n", .{ value, cursor });
            return DecodedInt{ .value = value, .bytes_consumed = cursor };
        }

        var shift: u6 = 0;
        while (cursor < encoded.len) {
            const byte = encoded[cursor];
            cursor += 1;

            log.debug("Decoding byte: {any}, current value: {any}, shift: {any}\n", .{ byte, value, shift });

            value += (@as(usize, byte & 0x7F) << shift);
            shift += 7;
            if ((byte & 0x80) == 0) break;
        }

        log.debug("Final decoded value={any}, bytes_consumed={any}\n", .{ value, cursor });

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
        _ = try Hpack.encodeInt(index2, 7, &index_buffer, 0x80);

        const payload = try index_buffer.toOwnedSlice();

        var decoded_field = try Hpack.decodeHeaderField(payload, &dynamic_table, &allocator);
        defer decoded_field.deinit();

        try std.testing.expectEqualStrings(field2.name, decoded_field.header.name);
        try std.testing.expectEqualStrings(field2.value, decoded_field.header.value);
        try index_buffer.resize(0);
    }

    // Encode index1
    {
        _ = try Hpack.encodeInt(index1, 7, &index_buffer, 0x80);

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

test "HPACK encoding and decoding of :status and content-length using static table with debug" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);
    defer dynamic_table.table.deinit();

    const status_field = Hpack.HeaderField.init(":status", "200");
    const content_length_field = Hpack.HeaderField.init("content-length", "13");

    // Encode :status and content-length headers
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    // Debug output

    // Check if :status is in the static table
    if (Hpack.StaticTable.getStaticIndex(status_field.name, status_field.value)) |idx| {
        try Hpack.encodeInt(idx, 7, &buffer, 0x80); // Indexed Header Field (Section 6.1)
    } else {
        try Hpack.encodeHeaderField(status_field, &dynamic_table, &buffer);
    }

    // Debug output

    // Check if content-length is in the static table
    if (Hpack.StaticTable.getStaticIndex(content_length_field.name, content_length_field.value)) |idx| {
        try Hpack.encodeInt(idx, 7, &buffer, 0x80); // Indexed Header Field (Section 6.1)
    } else {
        try Hpack.encodeHeaderField(content_length_field, &dynamic_table, &buffer);
    }

    // Ensure buffer contains encoded data
    try std.testing.expect(buffer.items.len > 0);

    // Debug output

    // Decode the headers
    var decoded_headers = std.ArrayList(Hpack.DecodedHeader).init(allocator);
    defer for (decoded_headers.items) |*decoded_header| {
        decoded_header.deinit();
    };
    defer decoded_headers.deinit();

    var cursor: usize = 0;
    while (cursor < buffer.items.len) {
        const decoded_header = try Hpack.decodeHeaderField(buffer.items[cursor..], &dynamic_table, &allocator);
        try decoded_headers.append(decoded_header);
        cursor += decoded_header.bytes_consumed;
    }

    // Check that the decoded headers match the encoded ones
    try std.testing.expectEqual(2, decoded_headers.items.len);

    const decoded_status = decoded_headers.items[0].header;
    try std.testing.expectEqualStrings(":status", decoded_status.name);
    try std.testing.expectEqualStrings("200", decoded_status.value);

    const decoded_content_length = decoded_headers.items[1].header;
    try std.testing.expectEqualStrings("content-length", decoded_content_length.name);
    try std.testing.expectEqualStrings("13", decoded_content_length.value);

}
