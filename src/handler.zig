//! HTTP/2 Request Handler API
//!
//! Provides a clean, type-safe interface for handling HTTP/2 requests
//! with zero-allocation patterns and optimal performance.

const std = @import("std");
const Hpack = @import("hpack.zig").Hpack;

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

    pub fn fromBytes(method_bytes: []const u8) ?Method {
        if (std.mem.eql(u8, method_bytes, "GET")) return .get;
        if (std.mem.eql(u8, method_bytes, "POST")) return .post;
        if (std.mem.eql(u8, method_bytes, "PUT")) return .put;
        if (std.mem.eql(u8, method_bytes, "DELETE")) return .delete;
        if (std.mem.eql(u8, method_bytes, "HEAD")) return .head;
        if (std.mem.eql(u8, method_bytes, "OPTIONS")) return .options;
        if (std.mem.eql(u8, method_bytes, "PATCH")) return .patch;
        return null;
    }

    pub fn bytes(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .post => "POST",
            .put => "PUT",
            .delete => "DELETE",
            .head => "HEAD",
            .options => "OPTIONS",
            .patch => "PATCH",
        };
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
    // Pre-allocated scratch for the handler to format small response bodies
    // into. Backed by stream-attached storage with stable address, so a slice
    // returned via `Response.body` survives the dispatcher returning by value.
    // Use `ctx.allocator` only when the body cannot fit here.
    response_body_buffer: []u8,

    const Self = @This();

    /// Initialize a new request context.
    pub fn init(
        allocator: std.mem.Allocator,
        method: Method,
        path: []const u8,
        query: []const u8,
        headers: []const RequestHeader,
        body: []const u8,
        response_body_buffer: []u8,
    ) Self {
        std.debug.assert(response_body_buffer.len > 0);
        return Self{
            .method = method,
            .path = path,
            .query = query,
            .headers = HeaderMap.init(headers),
            .body = body,
            .response = ResponseBuilder.init(allocator),
            .allocator = allocator,
            .response_body_buffer = response_body_buffer,
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
                const param_value = param[eq_pos + 1 ..];
                if (std.mem.eql(u8, param_name, name)) {
                    return param_value;
                }
            }
        }
        return null;
    }
};

/// Simple header map for request headers.
pub const RequestHeader = Hpack.HeaderField;

pub const HeaderMap = struct {
    entries: []const RequestHeader,

    const Self = @This();

    pub fn init(entries: []const RequestHeader) Self {
        return .{ .entries = entries };
    }

    pub fn get(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (entry.name.len == 0) continue;
            if (entry.name[0] == ':') continue;
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
    headers_storage: [32]HeaderPair,
    headers_count: u8,
    body: []const u8,
    content_length_storage: [32]u8,

    const Self = @This();

    pub fn init(status: Status) Self {
        return Self{
            .status = status,
            .headers_storage = undefined,
            .headers_count = 0,
            .body = "",
            .content_length_storage = undefined,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        std.debug.assert(name.len > 0);
        if (!isAllLowercaseHeaderName(name)) return error.InvalidHeaderName;
        if (self.headers_count >= self.headers_storage.len) return error.TooManyResponseHeaders;

        self.headers_storage[self.headers_count] = .{
            .name = name,
            .value = value,
        };
        self.headers_count += 1;
    }

    pub fn headers(self: *const Self) []const HeaderPair {
        return self.headers_storage[0..self.headers_count];
    }

    pub fn setBody(self: *Self, body: []const u8) !void {
        std.debug.assert(body.len <= 1024 * 1024);
        self.body = body;
        try self.ensureContentLength();
    }

    fn ensureContentLength(self: *Self) !void {
        if (self.findHeader("content-length")) |value| {
            const content_length = std.fmt.parseInt(usize, value, 10) catch {
                return error.InvalidContentLength;
            };
            if (content_length != self.body.len) return error.InvalidContentLength;
            return;
        }

        const content_length = try std.fmt.bufPrint(
            &self.content_length_storage,
            "{d}",
            .{self.body.len},
        );
        try self.addHeader("content-length", content_length);
    }

    fn findHeader(self: *const Self, name: []const u8) ?[]const u8 {
        for (self.headers()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }
};

/// Builder for constructing HTTP responses.
pub const ResponseBuilder = struct {
    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        _ = allocator;
        return Self{};
    }

    /// Create a response with the given configuration.
    pub fn apply(self: *const Self, config: ResponseConfig) !Response {
        _ = self;
        std.debug.assert(config.body.len <= 1024 * 1024); // 1MB max body size

        var response = Response.init(config.status);

        // Add content-type header if mime type is specified.
        if (config.mime) |mime_type| {
            try response.addHeader("content-type", mime_type.value());
        }

        // Add custom headers if provided.
        if (config.headers) |headers| {
            for (headers) |header| {
                try response.addHeader(header.name, header.value);
            }
        }

        try response.setBody(config.body);
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

pub const RequestDispatcherFn = *const fn (
    state: ?*const anyopaque,
    ctx: *const Context,
) anyerror!Response;

/// Request dispatcher hook for plugging in any router or application policy.
pub const RequestDispatcher = struct {
    state: ?*const anyopaque,
    dispatch_fn: RequestDispatcherFn,
    needs_headers: bool,

    const Self = @This();

    pub fn init(state: ?*const anyopaque, dispatch_fn: RequestDispatcherFn) Self {
        if (state) |non_null_state| {
            std.debug.assert(@intFromPtr(non_null_state) != 0);
        }

        return .{
            .state = state,
            .dispatch_fn = dispatch_fn,
            .needs_headers = true,
        };
    }

    pub fn fromHandler(comptime handler: HandlerFn) Self {
        const Adapter = struct {
            fn dispatch(_: ?*const anyopaque, ctx: *const Context) anyerror!Response {
                return handler(ctx);
            }
        };

        return .{
            .state = null,
            .dispatch_fn = Adapter.dispatch,
            .needs_headers = true,
        };
    }

    pub fn fromHandlerWithoutHeaders(comptime handler: HandlerFn) Self {
        const Adapter = struct {
            fn dispatch(_: ?*const anyopaque, ctx: *const Context) anyerror!Response {
                return handler(ctx);
            }
        };

        return .{
            .state = null,
            .dispatch_fn = Adapter.dispatch,
            .needs_headers = false,
        };
    }

    pub fn bind(
        comptime DispatcherState: type,
        state: *const DispatcherState,
        comptime dispatch_fn: *const fn (
            state: *const DispatcherState,
            ctx: *const Context,
        ) anyerror!Response,
    ) Self {
        const Adapter = struct {
            fn dispatch(raw_state: ?*const anyopaque, ctx: *const Context) anyerror!Response {
                std.debug.assert(raw_state != null);
                const typed_state: *const DispatcherState = @ptrCast(@alignCast(raw_state.?));
                return dispatch_fn(typed_state, ctx);
            }
        };

        return .{
            .state = state,
            .dispatch_fn = Adapter.dispatch,
            .needs_headers = true,
        };
    }

    pub fn call(self: Self, ctx: *const Context) anyerror!Response {
        return self.dispatch_fn(self.state, ctx);
    }
};

fn isAllLowercaseHeaderName(name: []const u8) bool {
    for (name) |byte| {
        if (std.ascii.isUpper(byte)) {
            return false;
        }
    }
    return true;
}

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

test "method bytes" {
    try std.testing.expectEqualStrings("GET", Method.get.bytes());
    try std.testing.expectEqualStrings("POST", Method.post.bytes());
    try std.testing.expectEqualStrings("PATCH", Method.patch.bytes());
}

test "header map operations" {
    const entries = [_]RequestHeader{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "content-type", .value = "text/html" },
        .{ .name = "content-length", .value = "1024" },
    };
    const headers = HeaderMap.init(&entries);

    try std.testing.expectEqualStrings("text/html", headers.get("content-type").?);
    try std.testing.expectEqualStrings("text/html", headers.get("Content-Type").?);
    try std.testing.expect(headers.get(":method") == null);
    try std.testing.expect(headers.get("nonexistent") == null);
}

test "request dispatcher wraps a stateless handler" {
    const allocator = std.testing.allocator;

    const test_handler: HandlerFn = struct {
        fn handler(ctx: *const Context) !Response {
            return ctx.response.text(.ok, "stateless");
        }
    }.handler;

    const dispatcher = RequestDispatcher.fromHandler(test_handler);
    var body_scratch: [32]u8 = undefined;
    var context = Context.init(allocator, .get, "/", "", &.{}, "", &body_scratch);
    var response = try dispatcher.call(&context);
    defer response.deinit();

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings("stateless", response.body);
}

test "request dispatcher binds typed state" {
    const allocator = std.testing.allocator;

    const App = struct {
        body: []const u8,

        fn dispatch(self: *const @This(), ctx: *const Context) !Response {
            return ctx.response.text(.ok, self.body);
        }
    };

    const app = App{ .body = "bound" };
    const dispatcher = RequestDispatcher.bind(App, &app, App.dispatch);
    var body_scratch: [32]u8 = undefined;
    var context = Context.init(allocator, .get, "/", "", &.{}, "", &body_scratch);
    var response = try dispatcher.call(&context);
    defer response.deinit();

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings("bound", response.body);
}

test "response builder" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const builder = ResponseBuilder.init(allocator);

    var response = try builder.html(.ok, "<h1>Hello</h1>");
    defer response.deinit();

    try testing.expectEqual(Status.ok, response.status);
    try testing.expectEqualStrings("<h1>Hello</h1>", response.body);
    try testing.expectEqual(@as(usize, 2), response.headers().len);
}
