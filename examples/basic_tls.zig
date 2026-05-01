const std = @import("std");
const http2 = @import("http2");
const tls_server = @import("tls-server");

const HandlerKey = enum(u8) {
    index,
    api_hello,
    user_show,
};

const RouteStyle = enum(u8) {
    exact,
    user_by_id,
};

const Match = struct {
    handler_key: HandlerKey,
    user_id: ?[]const u8 = null,
};

const RouteLookup = union(enum) {
    handler: Match,
    method_not_allowed,
    not_found,
};

const Route = struct {
    handler_key: HandlerKey,
    method: http2.Method,
    path: []const u8,
    style: RouteStyle,
};

const Router = struct {
    routes_storage: [8]Route,
    routes_count: u8,

    fn init() Router {
        return .{
            .routes_storage = undefined,
            .routes_count = 0,
        };
    }

    fn addExact(
        self: *Router,
        method: http2.Method,
        path: []const u8,
        handler_key: HandlerKey,
    ) !void {
        try self.add(.exact, method, path, handler_key);
    }

    fn addUserById(
        self: *Router,
        method: http2.Method,
        handler_key: HandlerKey,
    ) !void {
        try self.add(.user_by_id, method, "/users/{id}", handler_key);
    }

    fn add(
        self: *Router,
        style: RouteStyle,
        method: http2.Method,
        path: []const u8,
        handler_key: HandlerKey,
    ) !void {
        std.debug.assert(path.len > 0);
        std.debug.assert(path[0] == '/');

        if (self.routes_count >= self.routes_storage.len) {
            return error.TooManyRoutes;
        }

        self.routes_storage[@intCast(self.routes_count)] = .{
            .handler_key = handler_key,
            .method = method,
            .path = path,
            .style = style,
        };
        self.routes_count += 1;
    }

    fn lookup(self: *const Router, method: http2.Method, path: []const u8) RouteLookup {
        std.debug.assert(path.len > 0);
        std.debug.assert(path[0] == '/');

        var route_index: u8 = 0;
        var path_matched = false;

        while (route_index < self.routes_count) : (route_index += 1) {
            const route = self.routes_storage[@intCast(route_index)];

            if (routeMatch(route, path)) |match| {
                if (route.method == method) {
                    return .{ .handler = match };
                }
                path_matched = true;
            }
        }

        if (path_matched) {
            return .method_not_allowed;
        }
        return .not_found;
    }
};

const App = struct {
    router: Router,

    fn init(target: *App) !void {
        target.* = .{
            .router = Router.init(),
        };

        try target.router.addExact(.get, "/", .index);
        try target.router.addExact(.get, "/api/hello", .api_hello);
        try target.router.addExact(.post, "/api/hello", .api_hello);
        try target.router.addUserById(.get, .user_show);
    }

    fn dispatch(self: *const App, ctx: *const http2.Context) !http2.Response {
        return switch (self.router.lookup(ctx.method, ctx.path)) {
            .handler => |match| dispatchRouteMatch(ctx, match),
            .method_not_allowed => ctx.response.text(.method_not_allowed, "method not allowed\n"),
            .not_found => notFoundHandler(ctx),
        };
    }
};

fn routeMatch(route: Route, path: []const u8) ?Match {
    return switch (route.style) {
        .exact => matchExactRoute(route, path),
        .user_by_id => matchUserRoute(route, path),
    };
}

fn matchExactRoute(route: Route, path: []const u8) ?Match {
    if (!std.mem.eql(u8, route.path, path)) {
        return null;
    }

    return .{
        .handler_key = route.handler_key,
    };
}

fn matchUserRoute(route: Route, path: []const u8) ?Match {
    const user_id = matchUserPath(path) orelse {
        return null;
    };

    return .{
        .handler_key = route.handler_key,
        .user_id = user_id,
    };
}

fn matchUserPath(path: []const u8) ?[]const u8 {
    const prefix = "/users/";

    if (!std.mem.startsWith(u8, path, prefix)) {
        return null;
    }

    const user_id = path[prefix.len..];
    if (user_id.len == 0) {
        return null;
    }
    if (std.mem.indexOfScalar(u8, user_id, '/')) |_| {
        return null;
    }
    return user_id;
}

fn dispatchRouteMatch(ctx: *const http2.Context, match: Match) !http2.Response {
    return switch (match.handler_key) {
        .index => indexHandler(ctx),
        .api_hello => apiHandler(ctx),
        .user_show => userHandler(ctx, match.user_id.?),
    };
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
        \\    <p>Routing is provided by a small Zig router in this example.</p>
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
            \\  "router": "basic-zig"
            \\}
        ;
        return ctx.response.json(.ok, get_response);
    }
    if (ctx.method == .post) {
        const post_response =
            \\{
            \\  "message": "Created through the basic Zig router",
            \\  "status": "accepted"
            \\}
        ;
        return ctx.response.json(.created, post_response);
    }

    return ctx.response.text(.method_not_allowed, "method not allowed\n");
}

fn userHandler(
    ctx: *const http2.Context,
    user_id: []const u8,
) !http2.Response {
    const format = ctx.getQueryParam("format");

    if (std.mem.eql(u8, user_id, "42")) {
        if (format) |requested_format| {
            if (std.mem.eql(u8, requested_format, "html")) {
                const html_body =
                    \\<!DOCTYPE html>
                    \\<html>
                    \\<body>
                    \\    <h1>User 42</h1>
                    \\    <p>The local Zig router matched /users/{id}.</p>
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
    try App.init(&app);

    const config = tls_server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 8443),
        .dispatcher = http2.RequestDispatcher.bind(App, &app, App.dispatch),
        .max_connections = 100,
    };

    var server = try tls_server.Server.init(allocator, config);
    defer server.deinit();

    http2.freeze();

    std.log.info("HTTP/2 over TLS server listening on {f}", .{config.address});
    std.log.info("Routes powered by a local Zig router:", .{});
    std.log.info("  GET  /", .{});
    std.log.info("  GET  /api/hello", .{});
    std.log.info("  POST /api/hello", .{});
    std.log.info("  GET  /users/{{id}}", .{});
    try server.run();
}
