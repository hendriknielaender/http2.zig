//! Transport-neutral HTTP/2 connection entry points.
//!
//! TLS integrations live outside the core package. An adapter such as
//! `http2-boring` should accept TCP/TLS, verify ALPN, and pass the resulting
//! application-data reader and writer to `serveConnection`.

const std = @import("std");

const Connection = @import("connection.zig").Connection;
const handler = @import("handler.zig");

/// Options for serving one accepted HTTP/2 server connection.
pub const ServeConnectionOptions = struct {
    /// Request dispatcher for application routing or request handling.
    dispatcher: handler.RequestDispatcher,

    /// Optional caller-owned stream storage.
    ///
    /// Adapters with a connection pool can provide this to avoid per-connection
    /// stream-storage allocation. If omitted, the connection allocates its own
    /// storage and frame arena.
    stream_storage: ?*Connection.StreamStorage = null,

    /// Optional output populated before return, including error returns after
    /// the HTTP/2 connection has been initialized.
    completed_responses_out: ?*u32 = null,
};

/// Serve one already-accepted server-side HTTP/2 connection.
///
/// The caller owns the underlying transport and must keep `reader` and `writer`
/// alive until this function returns. TLS adapters are expected to complete the
/// TLS handshake and enforce ALPN `h2` before calling this function.
pub fn serveConnection(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: ServeConnectionOptions,
) !u32 {
    var connection: Connection = undefined;

    if (options.stream_storage) |stream_storage| {
        try Connection.initServerInPlace(
            &connection,
            stream_storage,
            allocator,
            reader,
            writer,
        );
    } else {
        connection = try Connection.init(allocator, reader, writer, true);
    }

    defer connection.deinit();
    connection.bindRequestDispatcher(options.dispatcher);

    connection.handle_connection() catch |err| {
        const completed_responses = connection.takeCompletedResponses();
        if (options.completed_responses_out) |out| {
            out.* = completed_responses;
        }
        return err;
    };

    const completed_responses = connection.takeCompletedResponses();
    if (options.completed_responses_out) |out| {
        out.* = completed_responses;
    }
    return completed_responses;
}
