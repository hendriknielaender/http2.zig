//! Transport-neutral HTTP/2 connection entry points.
//!
//! TLS integrations live outside the core package. An adapter such as
//! `http2-boring` should accept TCP/TLS, verify ALPN, and pass the resulting
//! application-data reader and writer to `serveConnection`.
//!
//! The adapter also owns RFC 9113 § 9.2: TLS 1.2 or higher, no renegotiation,
//! no compression, and on TLS 1.3 no post-handshake auth (RFC 8740).

const std = @import("std");

const Connection = @import("connection.zig").Connection;
const handler = @import("handler.zig");

/// Options for serving one accepted HTTP/2 server connection.
pub const ServeConnectionOptions = struct {
    /// Request dispatcher for application routing or request handling.
    dispatcher: handler.RequestDispatcher,

    /// Caller-owned stream storage from a startup-sized connection pool.
    stream_storage: *Connection.StreamStorage,

    /// Optional output populated before return, including error returns after
    /// the HTTP/2 connection has been initialized.
    completed_responses_out: ?*u32 = null,
};

/// Serve one already-accepted server-side HTTP/2 connection.
///
/// The caller owns the transport and keeps `reader` and `writer` alive until
/// return. Adapters finish the handshake, ALPN `h2`, and § 9.2 beforehand.
pub fn serveConnection(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    options: ServeConnectionOptions,
) !u32 {
    var connection: Connection = undefined;

    try Connection.initServerInPlace(
        &connection,
        options.stream_storage,
        reader,
        writer,
    );

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
