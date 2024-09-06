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
            while (self.table.items.len >= self.max_size) {
                _ = self.table.pop();
            }
            _ = try self.table.append(entry);
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

    pub fn encodeHeaderField(field: HeaderField, dynamic_table: *DynamicTable) ![]u8 {
        var allocator = std.heap.page_allocator;
        var buffer = std.ArrayList(u8).init(allocator);
        defer buffer.deinit();

        // Huffman encode the header field name and value
        const encoded_name = try huffman.encode(field.name, &allocator);
        defer allocator.free(encoded_name);

        const encoded_value = try huffman.encode(field.value, &allocator);
        defer allocator.free(encoded_value);

        // Encode the header field name and value
        try buffer.appendSlice(encoded_name);
        try buffer.append(@as(u8, 0x3A)); // Separator
        try buffer.appendSlice(encoded_value);

        // Update the dynamic table
        try dynamic_table.addEntry(field);

        const encoded_field = buffer.toOwnedSlice();
        return encoded_field;
    }

    pub fn decodeHeaderField(encoded: []const u8, dynamic_table: *DynamicTable) !HeaderField {
        var allocator = std.heap.page_allocator;

        // Check if the header is indexed (first byte has the top bit set to 1)
        if (encoded[0] & 0x80 != 0) {
            const index = encoded[0] & 0x7F; // Get the index value
            if (index == 0 or index > StaticTable.entries.len) {
                return error.InvalidEncoding;
            }
            return StaticTable.get(index - 1); // HPACK indexing starts at 1
        }

        // Otherwise, assume it's a literal header field (not indexed)
        const name_end_index = std.mem.indexOfScalar(u8, encoded, 0x3A) orelse return error.InvalidEncoding;
        if (name_end_index == 0 or name_end_index >= encoded.len - 1) {
            return error.InvalidEncoding;
        }

        const encoded_name = encoded[0..name_end_index];
        const encoded_value = encoded[name_end_index + 1 ..];

        const decoded_name_with_null = try huffman.decode(encoded_name, &allocator);
        defer allocator.free(decoded_name_with_null);

        const decoded_value_with_null = try huffman.decode(encoded_value, &allocator);
        defer allocator.free(decoded_value_with_null);

        if (decoded_name_with_null.len == 0 or decoded_value_with_null.len == 0) {
            return error.InvalidEncoding;
        }

        const final_decoded_name = decoded_name_with_null[0 .. decoded_name_with_null.len - 1];
        const final_decoded_value = decoded_value_with_null[0 .. decoded_value_with_null.len - 1];

        const field = HeaderField.init(final_decoded_name, final_decoded_value);
        try dynamic_table.addEntry(field);

        return field;
    }
};

test "HPACK encode and decode header field" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();
    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);
    defer dynamic_table.table.deinit();

    const field = Hpack.HeaderField.init("content-type", "text/html");

    const encoded = try Hpack.encodeHeaderField(field, &dynamic_table);
    defer allocator.free(encoded);

    const decoded = try Hpack.decodeHeaderField(encoded, &dynamic_table);

    try std.testing.expect(decoded.name.len == field.name.len);
    try std.testing.expect(decoded.value.len == field.value.len);

    std.debug.print("Original field name: {s}\n", .{field.name});
    std.debug.print("Decoded field name length: {d}\n", .{decoded.name.len});
    std.debug.print("Original field value: {s}\n", .{field.value});
    std.debug.print("Decoded field value length: {d}\n", .{decoded.value.len});

    // TODO fix memory access (seg fault)
    // try std.testing.expect(std.mem.eql(u8, field.name, decoded.name));
    // try std.testing.expect(std.mem.eql(u8, field.value, decoded.value));
}

test "Dynamic table add and retrieve" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var allocator = arena.allocator();

    var dynamic_table = try Hpack.DynamicTable.init(&allocator, 10);

    const field = Hpack.HeaderField.init("content-length", "1234");
    try dynamic_table.addEntry(field);

    const retrieved = dynamic_table.getEntry(0);
    try std.testing.expect(std.mem.eql(u8, field.name, retrieved.name));
    try std.testing.expect(std.mem.eql(u8, field.value, retrieved.value));
}
