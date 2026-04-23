const std = @import("std");
const core = @import("turboapi-core");
const http2 = @import("http2");
const tls_server = @import("tls-server");

const route_index = "index";
const route_api_hello = "api_hello";
const route_user_show = "user_show";

const App = struct {
    router: core.Router,

    fn init(target: *App, allocator: std.mem.Allocator) !void {
        target.* = .{
            .router = core.Router.init(allocator),
        };
        errdefer target.deinit();

        try target.router.addRoute("GET", "/", route_index);
        try target.router.addRoute("GET", "/api/hello", route_api_hello);
        try target.router.addRoute("POST", "/api/hello", route_api_hello);
        try target.router.addRoute("GET", "/users/{id}", route_user_show);
    }

    fn deinit(self: *App) void {
        self.router.deinit();
    }

    fn dispatch(self: *const App, ctx: *const http2.Context) !http2.Response {
        if (self.router.findRoute(ctx.method.bytes(), ctx.path)) |match_result| {
            var match = match_result;
            defer match.deinit();
            return dispatchRouteMatch(ctx, &match);
        }

        return notFoundHandler(ctx);
    }
};

fn dispatchRouteMatch(
    ctx: *const http2.Context,
    match: *const core.RouteMatch,
) !http2.Response {
    if (std.mem.eql(u8, match.handler_key, route_index)) {
        return indexHandler(ctx);
    }
    if (std.mem.eql(u8, match.handler_key, route_api_hello)) {
        return apiHandler(ctx);
    }
    if (std.mem.eql(u8, match.handler_key, route_user_show)) {
        return userHandler(ctx, &match.params);
    }

    return ctx.response.text(.internal_server_error, "unknown route key\n");
}

fn indexHandler(ctx: *const http2.Context) !http2.Response {
    const body =
        \\<!DOCTYPE html>
        \\<html>
        \\<head>
        \\    <title>HTTP/2 Server</title>
        \\</head>
        \\<body>
        \\    <h1>Hello, World!</h1>
        \\    <p>Routing is provided by turboapi-core.</p>
        \\    <p>Try GET /api/hello or GET /users/42?format=html.</p>
        \\</body>
        \\</html>
    ;

    return ctx.response.html(.ok, body);
}

fn apiHandler(ctx: *const http2.Context) !http2.Response {
    if (ctx.method == .get) {
        const get_response =
            \\{
            \\  "message": "Hello from HTTP/2 over TLS!",
            \\  "router": "turboapi-core"
            \\}
        ;
        return ctx.response.json(.ok, get_response);
    }
    if (ctx.method == .post) {
        const post_response =
            \\{
            \\  "message": "Created through turboapi-core dispatch",
            \\  "status": "accepted"
            \\}
        ;
        return ctx.response.json(.created, post_response);
    }

    return ctx.response.text(.method_not_allowed, "method not allowed\n");
}

fn userHandler(
    ctx: *const http2.Context,
    params: *const core.RouteParams,
) !http2.Response {
    const user_id = params.get("id") orelse {
        return ctx.response.text(.bad_request, "missing route parameter\n");
    };
    const format = core.http.queryStringGet(ctx.query, "format");

    if (std.mem.eql(u8, user_id, "42")) {
        if (format) |requested_format| {
            if (std.mem.eql(u8, requested_format, "html")) {
                const html_body =
                    \\<!DOCTYPE html>
                    \\<html>
                    \\<body>
                    \\    <h1>User 42</h1>
                    \\    <p>turboapi-core matched the {id} parameter.</p>
                    \\</body>
                    \\</html>
                ;
                return ctx.response.html(.ok, html_body);
            }
        }

        const json_body =
            \\{
            \\  "user": "42",
            \\  "role": "admin"
            \\}
        ;
        return ctx.response.json(.ok, json_body);
    }

    return ctx.response.text(.not_found, "user not found\n");
}

fn notFoundHandler(ctx: *const http2.Context) !http2.Response {
    const body =
        \\<!DOCTYPE html>
        \\<html>
        \\<body>
        \\    <h1>404 - Not Found</h1>
        \\    <p>The requested path was not found.</p>
        \\</body>
        \\</html>
    ;

    return ctx.response.html(.not_found, body);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try http2.init(allocator);
    defer http2.deinit();

    var app: App = undefined;
    try App.init(&app, allocator);
    defer app.deinit();

    const config = tls_server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 8443),
        .dispatcher = http2.RequestDispatcher.bind(App, &app, App.dispatch),
        .max_connections = 100,
    };

    var server = try tls_server.Server.init(allocator, config);
    defer server.deinit();

    std.log.info("HTTP/2 over TLS server listening on {f}", .{config.address});
    std.log.info("Routes powered by turboapi-core:", .{});
    std.log.info("  GET  /", .{});
    std.log.info("  GET  /api/hello", .{});
    std.log.info("  POST /api/hello", .{});
    std.log.info("  GET  /users/{{id}}", .{});
    try server.run();
}
