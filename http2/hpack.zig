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
        pub fn getStaticIndex(name: []const u8, value: []const u8) ?u8 {
            for (entries, 0..) |entry, index| {
                if (std.mem.eql(u8, name, entry.name) and std.mem.eql(u8, value, entry.value)) {
                    return @intCast(index + 1); // Cast index to u8 for correct return type
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
            const entry_size = entry.name.len + entry.value.len + 32; // HPACK specification overhead

            std.debug.print("Attempting to add entry: {s}: {s} with size: {d}, Current table size: {d}, Max size: {d}\n", .{ entry.name, entry.value, entry_size, self.getSize(), self.max_size });

            // Handle oversized entry
            if (entry_size > self.max_size) {
                std.debug.print("Entry size {d} exceeds the maximum table size {d}, cannot add entry\n", .{ entry_size, self.max_size });
                return; // Ignore oversized entries
            }

            // Evict entries until there's enough space
            while (self.getSize() + entry_size > self.max_size and self.table.items.len > 0) {
                _ = self.table.pop();
            }

            std.debug.print("Table size after eviction: {d}, remaining items: {d}\n", .{ self.getSize(), self.table.items.len });

            try self.table.append(entry);
            std.debug.print("Successfully added entry. New table size: {d}, Total items: {d}\n", .{ self.getSize(), self.table.items.len });
        }

        fn getSize(self: *DynamicTable) usize {
            var size: usize = 0;
            for (self.table.items) |entry| {
                size += entry.name.len + entry.value.len + 32;
            }
            return size;
        }

        /// Get an entry from the dynamic table by index
        pub fn getEntry(self: *DynamicTable, index: usize) HeaderField {
            assert(index < self.table.items.len);
            return self.table.items[index];
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
        if (prefix_size < 1 or prefix_size > 8) {
            return error.InvalidPrefixSize;
        }

        // Cast prefix_size to u6 to match the expected RHS type
        const prefix: u6 = @intCast(prefix_size);
        const max_prefix_value = (@as(usize, 1) << prefix) - 1;
        var cursor: usize = 0;

        var value: usize = encoded[0] & max_prefix_value;
        if (value < max_prefix_value) {
            return value;
        }

        var shift: u8 = 0;
        while (true) {
            cursor += 1;
            if (cursor >= encoded.len) {
                return error.InvalidEncoding;
            }
            const byte = encoded[cursor];
            // Cast shift to u6 to match the expected type for shift operation
            const s: u6 = @intCast(shift);
            value += @as(usize, byte & 0x7F) << s;
            if ((byte & 0x80) == 0) {
                break;
            }
            shift += 7;
        }
        return value;
    }

    pub fn decodeHeaderField(encoded: []const u8, dynamic_table: *DynamicTable) !HeaderField {
        const first_byte = encoded[0];
        const index = first_byte & 0x7F; // Extract the 7-bit index

        const max_static_index = StaticTable.entries.len;
        const max_dynamic_index = dynamic_table.table.items.len;
        const total_max_index = max_static_index + max_dynamic_index;

        // Validate the index is within bounds
        std.debug.print("Decoding header field: {x}, Max valid index: {d}, Static: {d}, Dynamic: {d}\n", .{ encoded, total_max_index, max_static_index, max_dynamic_index });

        if (index == 0 or index > total_max_index) {
            std.debug.print("Invalid index during decoding: {d} (Max valid index: {d}). Aborting decode.\n", .{ index, total_max_index });
            return error.InvalidEncoding;
        }

        // Handle indexed header field (bit 7 is set)
        if ((first_byte & 0x80) != 0) {
            if (index <= max_static_index) {
                std.debug.print("Decoding static table entry for index: {d}\n", .{index});
                return StaticTable.get(index - 1);
            } else {
                const dynamic_index = index - max_static_index - 1;
                if (dynamic_index >= dynamic_table.table.items.len) {
                    std.debug.print("Invalid dynamic table index: {d}, max valid dynamic index: {d}\n", .{ dynamic_index, dynamic_table.table.items.len });
                    return error.InvalidEncoding;
                }
                std.debug.print("Decoding dynamic table entry for index: {d}\n", .{dynamic_index});
                return dynamic_table.getEntry(dynamic_index);
            }
        }

        // Literal with incremental indexing (0x40)
        if ((first_byte & 0x40) != 0) {
            std.debug.print("Decoding literal with incremental indexing\n", .{});

            var alloc = std.heap.page_allocator;
            const name = try huffman.decode(encoded[1..], &alloc);
            const value = try huffman.decode(encoded[1 + name.len + 1 ..], &alloc);

            try dynamic_table.addEntry(HeaderField{ .name = name, .value = value });
            return HeaderField{ .name = name, .value = value };
        }

        return error.InvalidEncoding;
    }

    pub fn encodeHeaderField(field: HeaderField, dynamic_table: *DynamicTable) ![]u8 {
        var allocator = std.heap.page_allocator;
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        std.debug.print("Encoding field: {s}: {s}\n", .{ field.name, field.value });

        // Check static table for the field
        const static_index = Hpack.StaticTable.getStaticIndex(field.name, field.value);
        if (static_index) |idx| {
            // Encode static index
            const encoded_idx: u8 = @intCast(0x80 | idx);
            try buffer.append(encoded_idx);
        } else {
            // Literal with incremental indexing (0x40)
            try buffer.append(0x40);

            const encoded_name = try huffman.encode(field.name, &allocator);
            defer allocator.free(encoded_name);

            const encoded_value = try huffman.encode(field.value, &allocator);
            defer allocator.free(encoded_value);

            try buffer.appendSlice(encoded_name);
            try buffer.append(@as(u8, 0x3A));
            try buffer.appendSlice(encoded_value);

            const dynamic_index = dynamic_table.table.items.len + 1;
            if (dynamic_index > 62) {
                std.debug.print("Dynamic index {d} exceeds max allowed (62), using literal encoding\n", .{dynamic_index});
                return buffer.toOwnedSlice(); // Return without dynamic table indexing
            }

            try dynamic_table.addEntry(field);
            std.debug.print("Dynamic table size: {d}\n", .{dynamic_table.table.items.len});
        }

        return buffer.toOwnedSlice();
    }
};

test "HPACK encode and decode header field" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);
    defer dynamic_table.table.deinit();

    const field = Hpack.HeaderField.init("content-type", "text/html");

    // Encoding and logging
    const encoded = try Hpack.encodeHeaderField(field, &dynamic_table);
    std.debug.print("Encoded header field: {x}\n", .{encoded});

    // Decoding and logging
    const decoded = try Hpack.decodeHeaderField(encoded, &dynamic_table);
    std.debug.print("Decoded header field: {s}: {s}\n", .{ decoded.name, decoded.value });

    try std.testing.expect(std.mem.eql(u8, field.name, decoded.name));
    try std.testing.expect(std.mem.eql(u8, field.value, decoded.value));
}

test "Dynamic table add and retrieve" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();

    // Set a reasonable dynamic table size of 4096 for this test
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 4096);

    const field = Hpack.HeaderField.init("content-length", "1234");
    try dynamic_table.addEntry(field);

    const retrieved = dynamic_table.getEntry(0);
    try std.testing.expect(std.mem.eql(u8, field.name, retrieved.name));
    try std.testing.expect(std.mem.eql(u8, field.value, retrieved.value));
}

test "HPACK encode and decode :method and :status headers using static table" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);
    defer dynamic_table.table.deinit();

    // Test encoding of `:method = GET` from the static table
    const method_field = Hpack.HeaderField.init(":method", "GET");

    // Check that `:method = GET` uses the static table index
    const method_index = Hpack.StaticTable.getStaticIndex(method_field.name, method_field.value) orelse return error.InvalidEncoding;

    const method_encoded = [1]u8{0x80 | method_index}; // HPACK indexed field
    const method_decoded = try Hpack.decodeHeaderField(&method_encoded, &dynamic_table);
    try std.testing.expect(std.mem.eql(u8, method_field.name, method_decoded.name));
    try std.testing.expect(std.mem.eql(u8, method_field.value, method_decoded.value));

    // Test encoding of `:status = 200` from the static table
    const status_field = Hpack.HeaderField.init(":status", "200");

    // Check that `:status = 200` uses the static table index
    const status_index = Hpack.StaticTable.getStaticIndex(status_field.name, status_field.value) orelse return error.InvalidEncoding;

    const status_encoded = [1]u8{0x80 | status_index}; // HPACK indexed field
    const status_decoded = try Hpack.decodeHeaderField(&status_encoded, &dynamic_table);
    try std.testing.expect(std.mem.eql(u8, status_field.name, status_decoded.name));
    try std.testing.expect(std.mem.eql(u8, status_field.value, status_decoded.value));
}

test "HPACK invalid static table index" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);
    defer dynamic_table.table.deinit();

    // Construct an invalid HPACK encoded header field with an out-of-bounds index
    const invalid_index_encoded = [1]u8{0x80 | 100}; // 100 is out of range for the static table
    const result = Hpack.decodeHeaderField(&invalid_index_encoded, &dynamic_table);

    // Expect an error due to invalid index
    try std.testing.expect(result == error.InvalidEncoding);
}

test "HPACK dynamic table missing field" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);
    defer dynamic_table.table.deinit();

    // Try to get an entry from an empty dynamic table
    const result = blk: {
        if (dynamic_table.table.items.len > 0) {
            break :blk dynamic_table.getEntry(0);
        } else {
            break :blk null; // Or handle in another way based on your design
        }
    };

    // Expect a null result or a proper failure case
    try std.testing.expect(result == null);
}

test "HPACK Huffman encoding and decoding" {
    var allocator = std.heap.page_allocator;

    const original_name = "content-type";
    const original_value = "text/html";

    // Encode the original name and value
    const encoded_name = try huffman.encode(original_name, &allocator);
    defer allocator.free(encoded_name);
    const encoded_value = try huffman.encode(original_value, &allocator);
    defer allocator.free(encoded_value);

    std.debug.print("Original name: {s}, Encoded name (hex): {x}\n", .{ original_name, encoded_name });
    std.debug.print("Original value: {s}, Encoded value (hex): {x}\n", .{ original_value, encoded_value });

    // Decode the encoded name and value
    const decoded_name_with_null = try huffman.decode(encoded_name, &allocator);
    defer allocator.free(decoded_name_with_null);
    const decoded_value_with_null = try huffman.decode(encoded_value, &allocator);
    defer allocator.free(decoded_value_with_null);

    // Remove null terminators from decoded values
    const decoded_name = decoded_name_with_null[0 .. decoded_name_with_null.len - 1];
    const decoded_value = decoded_value_with_null[0 .. decoded_value_with_null.len - 1];

    std.debug.print("Decoded name: {s}, Decoded value: {s}\n", .{ decoded_name, decoded_value });

    // Assert that the decoded values match the original
    try std.testing.expect(std.mem.eql(u8, decoded_name, original_name));
    try std.testing.expect(std.mem.eql(u8, decoded_value, original_value));
}

test "HPACK invalid index during encoding" {
    var allocator = std.testing.allocator;
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 1); // Small table to trigger invalid index faster
    defer dynamic_table.table.deinit();

    const field = Hpack.HeaderField.init("content-type", "text/html");

    // Try to encode a header field, expecting an error when the index exceeds 62
    const result = Hpack.encodeHeaderField(field, &dynamic_table);
    try std.testing.expect(result == error.InvalidEncoding);
}

test "HPACK invalid index detection during decoding" {
    var allocator = std.testing.allocator;
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);
    defer dynamic_table.table.deinit();

    // Create encoded data with an invalid index (100)
    const invalid_encoded: []const u8 = &[_]u8{0x80 | 100}; // 100 is out of range
    const result = Hpack.decodeHeaderField(invalid_encoded, &dynamic_table);

    try std.testing.expect(result == error.InvalidEncoding);
}
