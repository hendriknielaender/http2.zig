//! Standard I/O adapters for libxev async connections.
//! These adapters expose std.Io.Reader and std.Io.Writer interfaces.

const std = @import("std");

/// Create std.Io compatible reader/writer for a connection type.
pub fn createStdIoAdapters(comptime ConnectionType: type) type {
    return struct {
        pub const Reader = struct {
            conn: *ConnectionType,
            status: Status = .ok,
            interface: std.Io.Reader = .{
                .vtable = &.{
                    .stream = stream,
                },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },

            pub const Status = enum {
                ok,
                would_block,
                connection_closed,
                failed,
            };

            pub fn init(conn: *ConnectionType) Reader {
                return .{ .conn = conn };
            }

            pub fn reader(self: *Reader) *std.Io.Reader {
                return &self.interface;
            }

            pub fn lastStatus(self: *const Reader) Status {
                return self.status;
            }

            fn stream(io_reader: *std.Io.Reader, io_writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
                const self: *Reader = @fieldParentPtr("interface", io_reader);
                const conn = self.conn;

                if (!conn.active) {
                    self.status = .connection_closed;
                    return error.EndOfStream;
                }

                std.debug.assert(conn.read_start <= conn.read_pos);
                const available = conn.read_pos - conn.read_start;
                if (available == 0) {
                    self.status = .would_block;
                    return 0;
                }

                const to_copy = limit.minInt(available);
                const read_start: usize = @intCast(conn.read_start);
                try io_writer.writeAll(conn.read_buffer[read_start .. read_start + to_copy]);
                conn.read_start += @intCast(to_copy);
                if (conn.read_start == conn.read_pos) {
                    conn.read_start = 0;
                    conn.read_pos = 0;
                }
                self.status = .ok;
                return to_copy;
            }
        };

        pub const Writer = struct {
            conn: *ConnectionType,
            status: Status = .ok,
            interface: std.Io.Writer = .{
                .vtable = &.{
                    .drain = drain,
                },
                .buffer = &.{},
            },

            pub const Status = enum {
                ok,
                would_block,
                connection_closed,
                failed,
            };

            pub fn init(conn: *ConnectionType) Writer {
                return .{ .conn = conn };
            }

            pub fn writer(self: *Writer) *std.Io.Writer {
                return &self.interface;
            }

            pub fn lastStatus(self: *const Writer) Status {
                return self.status;
            }

            fn drain(io_writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
                const self: *Writer = @fieldParentPtr("interface", io_writer);
                const conn = self.conn;

                if (!conn.active) {
                    self.status = .connection_closed;
                    return error.WriteFailed;
                }

                var total_written: usize = 0;
                for (data[0 .. data.len - 1]) |chunk| {
                    try self.writeChunk(chunk);
                    total_written += chunk.len;
                }

                const pattern = data[data.len - 1];
                for (0..splat) |_| {
                    try self.writeChunk(pattern);
                    total_written += pattern.len;
                }

                return total_written;
            }

            fn writeChunk(self: *Writer, chunk: []const u8) std.Io.Writer.Error!void {
                const conn = self.conn;

                conn.writeData(chunk) catch {
                    self.status = .would_block;
                    return error.WriteFailed;
                };

                if (!conn.write_active.load(.acquire)) {
                    conn.startWriting();
                }

                self.status = .ok;
            }
        };
    };
}
