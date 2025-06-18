//! Standard I/O adapters for libxev async connections
//! These adapters implement std.io.Reader and std.io.Writer interfaces

const std = @import("std");

/// Create std.io compatible reader/writer for a connection type
pub fn createStdIoAdapters(comptime ConnectionType: type) type {
    return struct {
        /// std.io.Reader compatible adapter
        pub const Reader = struct {
            conn: *ConnectionType,
            
            pub const ReadError = anyerror;
            
            pub fn read(self: *Reader, buffer: []u8) ReadError!usize {
                const conn = self.conn;
                
                // Check if connection is still active
                if (!conn.active) {
                    return error.ConnectionClosed;
                }
                
                // Check if we have buffered data
                const available = conn.read_pos;
                if (available == 0) {
                    return error.WouldBlock;
                }
                
                // Copy from read buffer
                const to_copy = @min(buffer.len, available);
                @memcpy(buffer[0..to_copy], conn.read_buffer[0..to_copy]);
                
                // Shift remaining data
                if (to_copy < available) {
                    std.mem.copyForwards(u8, conn.read_buffer[0..available - to_copy], conn.read_buffer[to_copy..available]);
                }
                conn.read_pos -= @intCast(to_copy);
                
                return to_copy;
            }
            
            pub fn reader(self: *Reader) std.io.GenericReader(*Reader, ReadError, read) {
                return .{ .context = self };
            }
        };
        
        /// std.io.Writer compatible adapter
        pub const Writer = struct {
            conn: *ConnectionType,
            
            pub const WriteError = anyerror;
            
            pub fn write(self: *Writer, data: []const u8) WriteError!usize {
                const conn = self.conn;
                
                if (!conn.active) {
                    return error.ConnectionClosed;
                }
                
                // For TLS connections, use the async TLS write system
                if (conn.tls_conn != null) {
                    conn.writeData(data) catch |err| switch (err) {
                        error.WriteBufferFull => {
                            // Write buffer full - set pending flag and return WouldBlock
                            conn.tls_write_pending.store(true, .release);
                            return error.WouldBlock;
                        },
                        error.OutOfMemory => {
                            return error.BrokenPipe;
                        },
                    };
                    return data.len;
                }
                
                // For non-TLS connections, use direct buffer write
                const available_space = conn.write_buffer.len - conn.write_pos;
                if (available_space < data.len) {
                    return error.WouldBlock;
                }
                
                // Copy to write buffer (accumulate frames)
                @memcpy(conn.write_buffer[conn.write_pos..conn.write_pos + data.len], data);
                conn.write_pos += @intCast(data.len);
                
                // Only trigger write if not already active
                if (!conn.write_active.load(.acquire)) {
                    conn.startWriting();
                }
                
                return data.len;
            }
            
            pub fn writer(self: *Writer) std.io.GenericWriter(*Writer, WriteError, write) {
                return .{ .context = self };
            }
        };
    };
}