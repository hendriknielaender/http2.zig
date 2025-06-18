//! HTTP/2 Request Handler API
//! 
//! Provides a clean, type-safe interface for handling HTTP/2 requests
//! with zero-allocation patterns and optimal performance.

const std = @import("std");
const http2 = @import("http2.zig");

/// HTTP status codes commonly used in responses.
pub const Status = enum(u16) {
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    moved_permanently = 301,
    found = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    conflict = 409,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,

    pub fn phrase(self: Status) []const u8 {
        return switch (self) {
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .not_modified => "Not Modified",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .conflict => "Conflict",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
        };
    }
};

/// Common MIME types for HTTP responses.
pub const Mime = enum {
    html,
    json,
    text,
    css,
    javascript,
    png,
    jpeg,
    gif,
    svg,
    pdf,
    octet_stream,

    pub fn value(self: Mime) []const u8 {
        return switch (self) {
            .html => "text/html; charset=utf-8",
            .json => "application/json; charset=utf-8",
            .text => "text/plain; charset=utf-8",
            .css => "text/css; charset=utf-8",
            .javascript => "application/javascript; charset=utf-8",
            .png => "image/png",
            .jpeg => "image/jpeg",
            .gif => "image/gif",
            .svg => "image/svg+xml",
            .pdf => "application/pdf",
            .octet_stream => "application/octet-stream",
        };
    }
};

/// HTTP methods supported by the server.
pub const Method = enum {
    get,
    post,
    put,
    delete,
    head,
    options,
    patch,

    pub fn fromBytes(bytes: []const u8) ?Method {
        if (std.mem.eql(u8, bytes, "GET")) return .get;
        if (std.mem.eql(u8, bytes, "POST")) return .post;
        if (std.mem.eql(u8, bytes, "PUT")) return .put;
        if (std.mem.eql(u8, bytes, "DELETE")) return .delete;
        if (std.mem.eql(u8, bytes, "HEAD")) return .head;
        if (std.mem.eql(u8, bytes, "OPTIONS")) return .options;
        if (std.mem.eql(u8, bytes, "PATCH")) return .patch;
        return null;
    }
};

/// HTTP request context providing access to request data and response builder.
pub const Context = struct {
    method: Method,
    path: []const u8,
    query: []const u8,
    headers: HeaderMap,
    body: []const u8,
    response: ResponseBuilder,
    allocator: std.mem.Allocator,
    
    const Self = @This();

    /// Initialize a new request context.
    pub fn init(
        allocator: std.mem.Allocator,
        method: Method,
        path: []const u8,
        query: []const u8,
        body: []const u8,
    ) Self {
        return Self{
            .method = method,
            .path = path,
            .query = query,
            .headers = HeaderMap.init(),
            .body = body,
            .response = ResponseBuilder.init(allocator),
            .allocator = allocator,
        };
    }

    /// Get header value by name (case-insensitive).
    pub fn getHeader(self: *const Self, name: []const u8) ?[]const u8 {
        return self.headers.get(name);
    }

    /// Parse query parameter by name.
    pub fn getQueryParam(self: *const Self, name: []const u8) ?[]const u8 {
        var query_iter = std.mem.splitSequence(u8, self.query, "&");
        while (query_iter.next()) |param| {
            if (std.mem.indexOf(u8, param, "=")) |eq_pos| {
                const param_name = param[0..eq_pos];
                const param_value = param[eq_pos + 1..];
                if (std.mem.eql(u8, param_name, name)) {
                    return param_value;
                }
            }
        }
        return null;
    }
};

/// Simple header map for request headers.
pub const HeaderMap = struct {
    entries: [32]HeaderEntry,
    count: u32,

    const HeaderEntry = struct {
        name: []const u8,
        value: []const u8,
    };

    const Self = @This();

    pub fn init() Self {
        return Self{
            .entries = std.mem.zeroes([32]HeaderEntry),
            .count = 0,
        };
    }

    pub fn put(self: *Self, name: []const u8, value: []const u8) void {
        std.debug.assert(self.count < 32);
        if (self.count >= 32) return;
        
        self.entries[self.count] = HeaderEntry{
            .name = name,
            .value = value,
        };
        self.count += 1;
    }

    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.entries[0..self.count]) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                return entry.value;
            }
        }
        return null;
    }
};

/// Response configuration for building HTTP responses.
pub const ResponseConfig = struct {
    status: Status = .ok,
    mime: ?Mime = null,
    body: []const u8 = "",
    headers: ?[]const HeaderPair = null,
};

/// Header name-value pair for custom response headers.
pub const HeaderPair = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP response data structure.
pub const Response = struct {
    status: Status,
    headers: std.ArrayList(HeaderPair),
    body: []const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, status: Status) Self {
        return Self{
            .status = status,
            .headers = std.ArrayList(HeaderPair).init(allocator),
            .body = "",
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all allocated header values
        for (self.headers.items) |header| {
            if (std.mem.eql(u8, header.name, "content-length")) {
                self.allocator.free(header.value);
            }
        }
        self.headers.deinit();
    }

    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        try self.headers.append(HeaderPair{ .name = name, .value = value });
    }

    pub fn setBody(self: *Self, body: []const u8) void {
        self.body = body;
    }
};

/// Builder for constructing HTTP responses.
pub const ResponseBuilder = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    /// Create a response with the given configuration.
    pub fn apply(self: *const Self, config: ResponseConfig) !Response {
        std.debug.assert(config.body.len <= 1024 * 1024); // 1MB max body size
        
        var response = Response.init(self.allocator, config.status);

        // Add content-type header if mime type is specified.
        if (config.mime) |mime_type| {
            try response.addHeader("content-type", mime_type.value());
        }

        // Add content-length header.
        var content_length_buf: [32]u8 = undefined;
        const content_length_str = try std.fmt.bufPrint(
            &content_length_buf, 
            "{d}", 
            .{config.body.len}
        );
        const content_length_copy = try self.allocator.dupe(u8, content_length_str);
        try response.addHeader("content-length", content_length_copy);

        // Add custom headers if provided.
        if (config.headers) |headers| {
            for (headers) |header| {
                try response.addHeader(header.name, header.value);
            }
        }

        response.setBody(config.body);
        return response;
    }

    /// Create a simple text response.
    pub fn text(self: *const Self, status: Status, body: []const u8) !Response {
        return self.apply(.{
            .status = status,
            .mime = .text,
            .body = body,
        });
    }

    /// Create a JSON response.
    pub fn json(self: *const Self, status: Status, body: []const u8) !Response {
        return self.apply(.{
            .status = status,
            .mime = .json,
            .body = body,
        });
    }

    /// Create an HTML response.
    pub fn html(self: *const Self, status: Status, body: []const u8) !Response {
        return self.apply(.{
            .status = status,
            .mime = .html,
            .body = body,
        });
    }
};

/// Request handler function type.
pub const HandlerFn = *const fn (ctx: *const Context) anyerror!Response;

/// Route definition for mapping paths to handlers.
pub const Route = struct {
    method: Method,
    path: []const u8,
    handler: HandlerFn,

    const Self = @This();

    pub fn init(method: Method, path: []const u8, handler: HandlerFn) Self {
        std.debug.assert(path.len > 0);
        std.debug.assert(path[0] == '/');
        
        return Self{
            .method = method,
            .path = path,
            .handler = handler,
        };
    }
};

/// Simple router for matching requests to handlers.
pub const Router = struct {
    routes: std.ArrayList(Route),
    allocator: std.mem.Allocator,
    fallback_handler: ?HandlerFn,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .routes = std.ArrayList(Route).init(allocator),
            .allocator = allocator,
            .fallback_handler = null,
        };
    }

    pub fn deinit(self: *Self) void {
        self.routes.deinit();
    }

    /// Add a route for GET requests.
    pub fn get(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.get, path, handler);
    }

    /// Add a route for POST requests.
    pub fn post(self: *Self, path: []const u8, handler: HandlerFn) !void {
        try self.addRoute(.post, path, handler);
    }

    /// Add a route for any HTTP method.
    pub fn addRoute(self: *Self, method: Method, path: []const u8, handler: HandlerFn) !void {
        std.debug.assert(path.len > 0);
        std.debug.assert(path[0] == '/');
        
        try self.routes.append(Route.init(method, path, handler));
    }

    /// Set a fallback handler for unmatched requests.
    pub fn setFallback(self: *Self, handler: HandlerFn) void {
        self.fallback_handler = handler;
    }

    /// Find handler for the given method and path.
    pub fn findHandler(self: *const Self, method: Method, path: []const u8) ?HandlerFn {
        std.debug.assert(path.len > 0);
        
        for (self.routes.items) |route| {
            if (route.method == method) {
                if (std.mem.eql(u8, route.path, path)) {
                    return route.handler;
                }
            }
        }
        
        return self.fallback_handler;
    }
};

test "status phrase lookup" {
    try std.testing.expectEqualStrings("OK", Status.ok.phrase());
    try std.testing.expectEqualStrings("Not Found", Status.not_found.phrase());
}

test "mime type values" {
    try std.testing.expectEqualStrings("text/html; charset=utf-8", Mime.html.value());
    try std.testing.expectEqualStrings("application/json; charset=utf-8", Mime.json.value());
}

test "method parsing" {
    try std.testing.expectEqual(Method.get, Method.fromBytes("GET").?);
    try std.testing.expectEqual(Method.post, Method.fromBytes("POST").?);
    try std.testing.expect(Method.fromBytes("INVALID") == null);
}

test "header map operations" {
    var headers = HeaderMap.init();
    headers.put("content-type", "text/html");
    headers.put("content-length", "1024");
    
    try std.testing.expectEqualStrings("text/html", headers.get("content-type").?);
    try std.testing.expectEqualStrings("text/html", headers.get("Content-Type").?);
    try std.testing.expect(headers.get("nonexistent") == null);
}

test "router path matching" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    var router = Router.init(allocator);
    defer router.deinit();
    
    const test_handler: HandlerFn = struct {
        fn handler(ctx: *const Context) !Response {
            return ctx.response.text(.ok, "test");
        }
    }.handler;
    
    try router.get("/", test_handler);
    try router.get("/test", test_handler);
    
    try testing.expect(router.findHandler(.get, "/") != null);
    try testing.expect(router.findHandler(.get, "/test") != null);
    try testing.expect(router.findHandler(.get, "/nonexistent") == null);
    try testing.expect(router.findHandler(.post, "/") == null);
}

test "response builder" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const builder = ResponseBuilder.init(allocator);
    
    var response = try builder.html(.ok, "<h1>Hello</h1>");
    defer response.deinit();
    
    try testing.expectEqual(Status.ok, response.status);
    try testing.expectEqualStrings("<h1>Hello</h1>", response.body);
}