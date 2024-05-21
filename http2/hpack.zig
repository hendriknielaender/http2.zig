const std = @import("std");

/// HPACK: Header Compression for HTTP/2
///
/// This module provides encoding and decoding of HTTP/2 header fields using the HPACK format.
pub const Hpack = struct {
    /// Static Table as defined by the HPACK specification
    pub const StaticTable = struct {
        // Placeholder for the static table
        // Fill in the actual static table entries as per RFC 7541
        const entries = &[_]HeaderField{
            HeaderField{ .name = ":authority", .value = "" },
            HeaderField{ .name = ":method", .value = "GET" },
            // Add all other static table entries here
        };

        /// Get a static table entry by index
        pub fn get(index: usize) HeaderField {
            return entries[index];
        }
    };

    /// Dynamic Table for HPACK
    pub const DynamicTable = struct {
        table: std.ArrayList(HeaderField),
        max_size: usize,

        /// Initialize a dynamic table with a given maximum size
        pub fn init(allocator: *std.mem.Allocator, max_size: usize) DynamicTable {
            return DynamicTable{
                .table = std.ArrayList(HeaderField).init(allocator.*),
                .max_size = max_size,
            };
        }

        /// Add an entry to the dynamic table
        pub fn addEntry(self: *DynamicTable, entry: HeaderField) !void {
            if (self.table.items.len >= self.max_size) {
                _ = self.table.pop();
            }
            _ = try self.table.append(entry);
        }

        /// Get an entry from the dynamic table by index
        pub fn getEntry(self: *DynamicTable, index: usize) HeaderField {
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

    /// Huffman decoding table (placeholder)
    pub const Huffman = struct {
        // Placeholder for the Huffman table and methods

        /// Decode a Huffman encoded string
        pub fn decode(huffman_encoded: []const u8) ![]u8 {
            // Implement Huffman decoding here
            return huffman_encoded; // Placeholder implementation
        }
    };

    /// Encode a header field
    pub fn encodeHeaderField(field: HeaderField, dynamic_table: *DynamicTable) ![]u8 {
        var buffer = std.ArrayList(u8).init(std.heap.page_allocator);

        // Encode the header field name and value
        try buffer.appendSlice(field.name);
        try buffer.append(@as(u8, 0x3A)); // Separator
        try buffer.appendSlice(field.value);

        // Update the dynamic table
        try dynamic_table.addEntry(field);

        return buffer.toOwnedSlice();
    }

    /// Decode a header field
    pub fn decodeHeaderField(encoded: []const u8, dynamic_table: *DynamicTable) !HeaderField {
        const name_end_index = std.mem.indexOfScalar(u8, encoded, 0x3A) orelse return error.InvalidEncoding;
        const name = encoded[0..name_end_index];
        const value = encoded[name_end_index + 1 ..];

        const field = HeaderField.init(name, value);
        try dynamic_table.addEntry(field);

        return field;
    }
};

test "HPACK encode and decode header field" {
    var allocator = std.testing.allocator;

    var dynamic_table = Hpack.DynamicTable.init(&allocator, 10);

    const field = Hpack.HeaderField.init("content-type", "text/html");

    const encoded = try Hpack.encodeHeaderField(field, &dynamic_table);
    defer allocator.free(encoded);

    const decoded = try Hpack.decodeHeaderField(encoded, &dynamic_table);

    try std.testing.expect(std.mem.eql(u8, field.name, decoded.name));
    try std.testing.expect(std.mem.eql(u8, field.value, decoded.value));
}
