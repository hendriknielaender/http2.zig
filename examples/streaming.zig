//! Finite, pull-based HTTP/2 response streaming without runtime allocation.
//!
//! HTTP/2 does not use HTTP/1.1 `Transfer-Encoding: chunked`. The connection
//! turns each bounded producer read into flow-controlled DATA frames and owns
//! the single final END_STREAM. The payload exceeds the fixed pull buffer so
//! running this example exercises multiple reads and DATA frames.

const std = @import("std");
const http2 = @import("http2");

const chunk_repetitions = 120;
const chunks = [_][]const u8{
    "first application chunk\n" ** chunk_repetitions,
    "second application chunk\n" ** chunk_repetitions,
    "third and final application chunk\n" ** chunk_repetitions,
};

const ChunkSource = struct {
    chunk_index: usize = 0,
    chunk_offset: usize = 0,

    /// Fill the offered buffer across logical chunks unless this read finishes
    /// the source. This runs on the connection task and must never wait for I/O.
    pub fn read(self: *@This(), output: []u8) !http2.StreamReadResult {
        std.debug.assert(output.len > 0);

        var written: usize = 0;
        while (written < output.len and self.chunk_index < chunks.len) {
            const chunk = chunks[self.chunk_index];
            const remaining = chunk[self.chunk_offset..];
            if (remaining.len == 0) {
                self.advanceChunk();
                continue;
            }

            const count = @min(output.len - written, remaining.len);
            std.mem.copyForwards(
                u8,
                output[written..][0..count],
                remaining[0..count],
            );
            written += count;
            self.chunk_offset += count;
            if (self.chunk_offset == chunk.len) self.advanceChunk();
        }

        return .{ .bytes_written = written };
    }

    /// The library derives END_STREAM from this state after every read.
    pub fn isFinished(self: *const @This()) bool {
        return self.chunk_index == chunks.len;
    }

    fn advanceChunk(self: *@This()) void {
        self.chunk_index += 1;
        self.chunk_offset = 0;
    }
};

fn handleRequest(ctx: *const http2.Context) !http2.Response {
    if (ctx.method != .get) {
        return ctx.response.text(.method_not_allowed, "use GET\n");
    }
    if (!std.mem.eql(u8, ctx.path, "/stream")) {
        return ctx.response.text(.not_found, "try GET /stream\n");
    }

    // Every ChunkSource field is copied inline into fixed stream-owned storage.
    // Pointer and slice fields are rejected recursively at comptime.
    return ctx.response.stream(
        .{ .status = .ok, .mime = .text },
        ChunkSource{},
    );
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try http2.init(allocator);
    defer http2.deinit();

    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 8080);
    var server = try http2.Server.init(allocator, .{
        .address = address,
        .dispatcher = http2.RequestDispatcher.fromHandlerWithoutHeaders(handleRequest),
        .max_connections = 100,
    });
    defer server.deinit();

    http2.freeze();
    std.log.info("Streaming HTTP/2 server listening on {f}", .{address});
    std.log.info("curl --http2-prior-knowledge --no-buffer http://127.0.0.1:8080/stream", .{});
    try server.run();
}
