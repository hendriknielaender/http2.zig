const std = @import("std");
const http2 = @import("http2");

/// Main request handler for the root path.
fn indexHandler(ctx: *const http2.Context) !http2.Response {
    const body =
        \\ <!DOCTYPE html>
        \\ <html>
        \\ <head>
        \\     <title>HTTP/2 Server</title>
        \\ </head>
        \\ <body>
        \\     <h1>Hello, World!</h1>
        \\     <p>This is an HTTP/2 server built with Zig!</p>
        \\ </body>
        \\ </html>
    ;

    return ctx.response.apply(.{
        .status = .ok,
        .mime = .html,
        .body = body[0..],
    });
}

/// API endpoint handler.
fn apiHandler(ctx: *const http2.Context) !http2.Response {
    const json_response =
        \\{
        \\  "message": "Hello from HTTP/2 API!",
        \\  "method": "GET",
        \\  "path": "/"
        \\}
    ;

    return ctx.response.apply(.{
        .status = .ok,
        .mime = .json,
        .body = json_response,
    });
}

/// 404 handler for unmatched routes.
fn notFoundHandler(ctx: *const http2.Context) !http2.Response {
    const body =
        \\ <!DOCTYPE html>
        \\ <html>
        \\ <body>
        \\     <h1>404 - Not Found</h1>
        \\     <p>The requested path was not found.</p>
        \\ </body>
        \\ </html>
    ;

    return ctx.response.apply(.{
        .status = .not_found,
        .mime = .html,
        .body = body,
    });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize HTTP/2 system
    try http2.init(allocator);
    defer http2.deinit();

    // Set up request router
    var router = http2.Router.init(allocator);
    defer router.deinit();

    // Register routes
    try router.get("/", indexHandler);
    try router.get("/api/hello", apiHandler);
    try router.post("/api/hello", apiHandler);
    router.setFallback(notFoundHandler);

    // Configure server
    const config = http2.Server.Config{
        .address = try std.net.Address.resolveIp("127.0.0.1", 8443),
        .router = &router,
        .max_connections = 100,
        .buffer_size = 32 * 1024,
    };

    // Initialize TLS context for HTTPS
    var tls_ctx = try http2.tls.TlsServerContext.init(allocator, "cert.pem", "key.pem");
    defer tls_ctx.deinit();

    // Create and run server
    var server = try http2.Server.initWithTLS(allocator, config, &tls_ctx);
    defer server.deinit();

    std.log.info("HTTP/2 over TLS server listening on {f}", .{config.address});
    std.log.info("Routes:", .{});
    std.log.info("  GET  / - Main page", .{});
    std.log.info("  GET  /api/hello - API endpoint", .{});
    std.log.info("  POST /api/hello - API endpoint", .{});
    try server.run();
}
