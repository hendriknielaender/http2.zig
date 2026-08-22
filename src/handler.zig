//! HTTP/2 Request Handler API
//!
//! Provides a clean, type-safe interface for handling HTTP/2 requests
//! with zero-allocation patterns and optimal performance.

const std = @import("std");
const Hpack = @import("hpack.zig").Hpack;
const memory_budget = @import("memory_budget.zig");

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
    // Pre-allocated scratch for the handler to format small response bodies
    // into. Backed by stream-attached storage with stable address, so a slice
    // returned via `Response.body` survives the dispatcher returning by value.
    // Handlers must return a bounded error when the body cannot fit here.
    response_body_buffer: []u8,

    const Self = @This();

    /// Initialize a new request context.
    pub fn init(
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
            .response = ResponseBuilder.init(),
            .response_body_buffer = response_body_buffer,
        };
    }

    pub fn initWithStreamStorage(
        method: Method,
        path: []const u8,
        query: []const u8,
        headers: []const RequestHeader,
        body: []const u8,
        response_storage: *StreamStateStorage,
    ) Self {
        return .{
            .method = method,
            .path = path,
            .query = query,
            .headers = HeaderMap.init(headers),
            .body = body,
            .response = ResponseBuilder.initWithStreamStorage(response_storage),
            .response_body_buffer = &response_storage.bytes,
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

/// Comptime-only configuration for an unknown-length response body.
/// Header names and values therefore have static lifetime.
pub const StreamResponseConfig = struct {
    status: Status = .ok,
    mime: ?Mime = null,
    headers: ?[]const HeaderPair = null,
};

/// Result of one bounded producer read.
///
/// The producer writes only into the supplied output buffer. It advances its
/// own state and fills the buffer unless those bytes finish the source.
pub const StreamReadResult = struct {
    bytes_written: usize,
};

/// Stream-owned state storage shared by the handler and response lifecycle.
///
/// The response-body scratch and a streaming producer are mutually exclusive,
/// so the same fixed bytes serve both uses without adding a DATA-frame buffer.
pub const StreamStateStorage = struct {
    pub const capacity = memory_budget.MemBudget.stream_response_body_capacity_bytes;
    pub const alignment = 16;

    bytes: [capacity]u8 align(alignment),
    generation: u32,
    active: bool,

    pub fn init(generation_seed: u32) StreamStateStorage {
        return .{
            .bytes = undefined,
            .generation = generation_seed,
            .active = false,
        };
    }

    /// Initializes in place, leaving `bytes` untouched.
    ///
    /// Assigning the result of `init` would copy the whole struct, and a
    /// whole-struct store lets the backend fold the scratch bytes into an
    /// adjacent zero-fill. `bytes` carries no meaning until a source claims
    /// it, so writing it is wasted work on the per-stream path.
    pub fn initInPlace(self: *StreamStateStorage, generation_seed: u32) void {
        self.generation = generation_seed;
        self.active = false;
    }

    fn claim(self: *StreamStateStorage) !u32 {
        if (self.active) return error.StreamStateStorageInUse;
        self.generation +%= 1;
        if (self.generation == 0) self.generation = 1;
        self.active = true;
        return self.generation;
    }

    fn owns(self: *const StreamStateStorage, generation: u32) bool {
        return self.active and self.generation == generation;
    }

    fn release(self: *StreamStateStorage, generation: u32) void {
        if (!self.owns(generation)) return;
        self.active = false;
    }
};

/// Type-erased finite producer stored in `StreamStateStorage`.
///
/// State is owned inline: pointers, slices, and other reference-bearing fields
/// are rejected recursively at comptime. State types declare
/// `read(self, output)`, `isFinished(self)`, and may declare `deinit(self)`.
/// Reads run on the connection task and must not block.
pub const StreamSource = struct {
    storage: *StreamStateStorage,
    generation: u32,
    read_fn: *const fn (*anyopaque, []u8) anyerror!StreamReadResult,
    is_finished_fn: *const fn (*const anyopaque) bool,
    deinit_fn: *const fn (*anyopaque) void,

    const Self = @This();

    /// Claim storage and move an inline-owned state value into it.
    ///
    /// Claim is the final fallible operation. The caller retains ownership when
    /// this returns an error; on success, `deinit()` owns the installed state.
    fn initInPlace(storage: *StreamStateStorage, initial_state: anytype) !Self {
        const State = @TypeOf(initial_state);
        validateStreamState(State);

        const generation = try storage.claim();
        const typed_state = streamStatePointer(State, storage);
        typed_state.* = initial_state;
        const Adapter = StreamSourceAdapter(State);
        return .{
            .storage = storage,
            .generation = generation,
            .read_fn = Adapter.read,
            .is_finished_fn = Adapter.isFinished,
            .deinit_fn = Adapter.deinit,
        };
    }

    pub fn read(self: *Self, output: []u8) !StreamReadResult {
        if (!self.storage.owns(self.generation)) return error.StreamSourceInactive;
        if (output.len == 0) return error.StreamSourceBufferEmpty;

        const result = try self.read_fn(self.state(), output);
        if (result.bytes_written > output.len) return error.StreamSourceOverflow;
        if (result.bytes_written < output.len and !try self.isFinished()) {
            if (result.bytes_written == 0) return error.StreamSourceStalled;
            return error.StreamSourceShortRead;
        }
        return result;
    }

    pub fn isFinished(self: *const Self) !bool {
        if (!self.storage.owns(self.generation)) return error.StreamSourceInactive;
        return self.is_finished_fn(self.stateConst());
    }

    pub fn deinit(self: *Self) void {
        if (!self.storage.owns(self.generation)) return;
        self.deinit_fn(self.state());
        self.storage.release(self.generation);
    }

    fn state(self: *Self) *anyopaque {
        return @ptrCast(&self.storage.bytes);
    }

    fn stateConst(self: *const Self) *const anyopaque {
        return @ptrCast(&self.storage.bytes);
    }
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
    stream_source: ?StreamSource,
    content_length_storage: [32]u8,

    const Self = @This();

    pub fn init(status: Status) Self {
        return Self{
            .status = status,
            .headers_storage = undefined,
            .headers_count = 0,
            .body = "",
            .stream_source = null,
            .content_length_storage = undefined,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.stream_source) |*source| source.deinit();
        self.stream_source = null;
    }

    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        std.debug.assert(name.len > 0);
        if (self.stream_source != null) return error.StreamHeadersMustBeConfigured;
        if (!isAllLowercaseHeaderName(name)) return error.InvalidHeaderName;
        if (isConnectionSpecificResponseHeader(name)) {
            return error.ConnectionSpecificResponseHeader;
        }
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
        if (self.stream_source != null) return error.ResponseBodyAlreadySet;
        self.body = body;
        try self.ensureContentLength();
    }

    pub fn hasStream(self: *const Self) bool {
        return self.stream_source != null;
    }

    pub fn take(self: *Self) Self {
        const result = self.*;
        self.stream_source = null;
        return result;
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

    fn installStream(self: *Self, source: StreamSource) void {
        std.debug.assert(self.body.len == 0);
        std.debug.assert(self.stream_source == null);
        std.debug.assert(self.findHeader("content-length") == null);
        self.stream_source = source;
    }
};

/// Builder for constructing HTTP responses.
pub const ResponseBuilder = struct {
    stream_state_storage: ?*StreamStateStorage,

    const Self = @This();

    pub fn init() Self {
        return .{ .stream_state_storage = null };
    }

    pub fn initWithStreamStorage(storage: *StreamStateStorage) Self {
        return .{ .stream_state_storage = storage };
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

    /// Create an unknown-length response from bounded stream-owned state.
    ///
    /// The state and every nested field must be inline-owned. Pointers, slices,
    /// allocators, and other reference-bearing values are rejected at comptime.
    /// Configuration is comptime-only so borrowed header strings are static.
    /// Every fallible configuration check runs before the storage claim, and
    /// installation after the claim is infallible. Thus, an error leaves the
    /// caller owning the state and never invokes its `deinit()`. On success, the
    /// response owns the state and cleans it on completion or teardown.
    pub fn stream(
        self: *const Self,
        comptime config: StreamResponseConfig,
        initial_state: anytype,
    ) !Response {
        if (responseStatusDisallowsBody(config.status)) {
            return error.ResponseStatusDisallowsBody;
        }

        var response = Response.init(config.status);
        if (config.mime) |mime_type| {
            try response.addHeader("content-type", mime_type.value());
        }
        if (config.headers) |headers| {
            for (headers) |header| try response.addHeader(header.name, header.value);
        }
        if (response.findHeader("content-length") != null) {
            return error.ContentLengthNotAllowedForStream;
        }

        const storage = self.stream_state_storage orelse {
            return error.StreamStateStorageUnavailable;
        };
        const source = try StreamSource.initInPlace(storage, initial_state);
        response.installStream(source);
        return response;
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

    fn fromHandlerInternal(comptime handler: HandlerFn, comptime needs_headers: bool) Self {
        const Adapter = struct {
            fn dispatch(_: ?*const anyopaque, ctx: *const Context) anyerror!Response {
                return handler(ctx);
            }
        };

        return .{
            .state = null,
            .dispatch_fn = Adapter.dispatch,
            .needs_headers = needs_headers,
        };
    }

    pub fn fromHandler(comptime handler: HandlerFn) Self {
        return fromHandlerInternal(handler, true);
    }

    pub fn fromHandlerWithoutHeaders(comptime handler: HandlerFn) Self {
        return fromHandlerInternal(handler, false);
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

pub fn isAllLowercaseHeaderName(name: []const u8) bool {
    for (name) |byte| {
        if (std.ascii.isUpper(byte)) {
            return false;
        }
    }
    return true;
}

fn responseStatusDisallowsBody(status: Status) bool {
    return status == .no_content or status == .not_modified;
}

fn isConnectionSpecificResponseHeader(name: []const u8) bool {
    const prohibited = [_][]const u8{
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    };
    for (prohibited) |header_name| {
        if (std.mem.eql(u8, name, header_name)) return true;
    }
    return false;
}

fn validateStreamState(comptime State: type) void {
    comptime {
        switch (@typeInfo(State)) {
            .@"struct" => {},
            else => @compileError("stream source state must be a struct"),
        }
        if (@sizeOf(State) > StreamStateStorage.capacity) {
            @compileError("stream source state exceeds fixed storage capacity");
        }
        if (@alignOf(State) > StreamStateStorage.alignment) {
            @compileError("stream source state alignment exceeds fixed storage alignment");
        }
        if (!streamStateIsInlineOwned(State)) {
            @compileError(
                "stream source state must contain only inline-owned values; " ++
                    "pointers, slices, functions, frames, and opaque values are forbidden",
            );
        }
        if (!@hasDecl(State, "read")) {
            @compileError("stream source state must declare read(self, output)");
        }
        if (!@hasDecl(State, "isFinished")) {
            @compileError("stream source state must declare isFinished(self)");
        }
    }
}

fn streamStateIsInlineOwned(comptime Value: type) bool {
    return switch (@typeInfo(Value)) {
        .pointer, .@"fn", .@"opaque", .frame, .@"anyframe" => false,
        .array => |array| streamStateIsInlineOwned(array.child),
        .vector => |vector| streamStateIsInlineOwned(vector.child),
        .optional => |optional| streamStateIsInlineOwned(optional.child),
        .error_union => |error_union| streamStateIsInlineOwned(error_union.payload),
        .@"struct" => |structure| owned: {
            for (structure.fields) |field| {
                if (!streamStateIsInlineOwned(field.type)) break :owned false;
            }
            break :owned true;
        },
        .@"union" => |union_info| owned: {
            for (union_info.fields) |field| {
                if (!streamStateIsInlineOwned(field.type)) break :owned false;
            }
            break :owned true;
        },
        else => true,
    };
}

fn streamStatePointer(
    comptime State: type,
    storage: *StreamStateStorage,
) *State {
    return @ptrCast(@alignCast(&storage.bytes));
}

fn StreamSourceAdapter(comptime State: type) type {
    return struct {
        fn read(raw_state: *anyopaque, output: []u8) anyerror!StreamReadResult {
            const state: *State = @ptrCast(@alignCast(raw_state));
            return State.read(state, output);
        }

        fn isFinished(raw_state: *const anyopaque) bool {
            const state: *const State = @ptrCast(@alignCast(raw_state));
            return State.isFinished(state);
        }

        fn deinit(raw_state: *anyopaque) void {
            const state: *State = @ptrCast(@alignCast(raw_state));
            if (@hasDecl(State, "deinit")) State.deinit(state);
            state.* = undefined;
        }
    };
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
    const test_handler: HandlerFn = struct {
        fn handler(ctx: *const Context) !Response {
            return ctx.response.text(.ok, "stateless");
        }
    }.handler;

    const dispatcher = RequestDispatcher.fromHandler(test_handler);
    var body_scratch: [32]u8 = undefined;
    var context = Context.init(.get, "/", "", &.{}, "", &body_scratch);
    var response = try dispatcher.call(&context);
    defer response.deinit();

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings("stateless", response.body);
}

test "request dispatcher binds typed state" {
    const App = struct {
        body: []const u8,

        fn dispatch(self: *const @This(), ctx: *const Context) !Response {
            return ctx.response.text(.ok, self.body);
        }
    };

    const app = App{ .body = "bound" };
    const dispatcher = RequestDispatcher.bind(App, &app, App.dispatch);
    var body_scratch: [32]u8 = undefined;
    var context = Context.init(.get, "/", "", &.{}, "", &body_scratch);
    var response = try dispatcher.call(&context);
    defer response.deinit();

    try std.testing.expectEqual(Status.ok, response.status);
    try std.testing.expectEqualStrings("bound", response.body);
}

test "response builder" {
    const testing = std.testing;

    const builder = ResponseBuilder.init();

    var response = try builder.html(.ok, "<h1>Hello</h1>");
    defer response.deinit();

    try testing.expectEqual(Status.ok, response.status);
    try testing.expectEqualStrings("<h1>Hello</h1>", response.body);
    try testing.expectEqual(@as(usize, 2), response.headers().len);
}

threadlocal var test_stream_cleanup_count: u32 = 0;

const TestChunkSource = struct {
    payload: [6]u8 = .{ 'a', 'b', 'c', 'd', 'e', 'f' },
    offset: usize = 0,

    pub fn read(self: *@This(), output: []u8) !StreamReadResult {
        const remaining = self.payload[self.offset..];
        const count = @min(output.len, remaining.len);
        std.mem.copyForwards(u8, output[0..count], remaining[0..count]);
        self.offset += count;
        return .{ .bytes_written = count };
    }

    pub fn isFinished(self: *const @This()) bool {
        return self.offset == self.payload.len;
    }

    pub fn deinit(_: *@This()) void {
        test_stream_cleanup_count += 1;
    }
};

test "stream builder owns inline payload across pulls and cleans it once" {
    test_stream_cleanup_count = 0;
    var storage = StreamStateStorage.init(1);
    var context = Context.initWithStreamStorage(.get, "/", "", &.{}, "", &storage);
    var response = try context.response.stream(
        .{ .status = .ok, .mime = .text },
        TestChunkSource{},
    );

    try std.testing.expect(response.hasStream());
    try std.testing.expect(response.findHeader("content-length") == null);

    var output: [4]u8 = undefined;
    const first = try response.stream_source.?.read(&output);
    try std.testing.expectEqual(@as(usize, 4), first.bytes_written);
    try std.testing.expectEqualStrings("abcd", output[0..first.bytes_written]);
    try std.testing.expect(!try response.stream_source.?.isFinished());
    const second = try response.stream_source.?.read(&output);
    try std.testing.expectEqual(@as(usize, 2), second.bytes_written);
    try std.testing.expectEqualStrings("ef", output[0..second.bytes_written]);
    try std.testing.expect(try response.stream_source.?.isFinished());

    response.deinit();
    response.deinit();
    try std.testing.expectEqual(@as(u32, 1), test_stream_cleanup_count);
    try std.testing.expect(!storage.active);
}

test "stream state ownership validation rejects nested references" {
    const InlineState = struct {
        payload: [16]u8,
        cursor: usize,
        phase: ?enum { first, second },
    };
    const NestedSlice = struct { nested: struct { bytes: []const u8 } };
    const OptionalPointer = struct { value: ?*const u8 };
    const FunctionPointer = struct { callback: *const fn () void };
    const AllocatorState = struct { allocator: std.mem.Allocator };

    comptime {
        if (!streamStateIsInlineOwned(InlineState)) @compileError("inline state rejected");
        if (streamStateIsInlineOwned(NestedSlice)) @compileError("nested slice accepted");
        if (streamStateIsInlineOwned(OptionalPointer)) @compileError("pointer accepted");
        if (streamStateIsInlineOwned(FunctionPointer)) @compileError("function accepted");
        if (streamStateIsInlineOwned(AllocatorState)) @compileError("allocator accepted");
    }
}

test "stream source rejects overflow, zero progress, and short reads" {
    const InvalidSource = struct {
        mode: enum { overflow, stalled, short_read },

        pub fn read(self: *@This(), output: []u8) !StreamReadResult {
            return .{ .bytes_written = switch (self.mode) {
                .overflow => output.len + 1,
                .stalled => 0,
                .short_read => 1,
            } };
        }

        pub fn isFinished(_: *const @This()) bool {
            return false;
        }
    };

    var storage = StreamStateStorage.init(1);
    var output: [8]u8 = undefined;
    var overflow = try StreamSource.initInPlace(&storage, InvalidSource{ .mode = .overflow });
    try std.testing.expectError(error.StreamSourceOverflow, overflow.read(&output));
    overflow.deinit();
    var stalled = try StreamSource.initInPlace(&storage, InvalidSource{ .mode = .stalled });
    try std.testing.expectError(error.StreamSourceStalled, stalled.read(&output));
    stalled.deinit();
    var short = try StreamSource.initInPlace(&storage, InvalidSource{ .mode = .short_read });
    try std.testing.expectError(error.StreamSourceShortRead, short.read(&output));
    short.deinit();
}

test "stream builder rejects HTTP/1 transfer framing and content length" {
    test_stream_cleanup_count = 0;
    var storage = StreamStateStorage.init(1);
    var builder = ResponseBuilder.initWithStreamStorage(&storage);
    const transfer_encoding = [_]HeaderPair{
        .{ .name = "transfer-encoding", .value = "chunked" },
    };
    try std.testing.expectError(
        error.ConnectionSpecificResponseHeader,
        builder.stream(.{ .headers = &transfer_encoding }, TestChunkSource{}),
    );

    const content_length = [_]HeaderPair{
        .{ .name = "content-length", .value = "0" },
    };
    try std.testing.expectError(
        error.ContentLengthNotAllowedForStream,
        builder.stream(.{ .headers = &content_length }, TestChunkSource{}),
    );

    const unavailable_builder = ResponseBuilder.init();
    try std.testing.expectError(
        error.StreamStateStorageUnavailable,
        unavailable_builder.stream(.{}, TestChunkSource{}),
    );
    try std.testing.expectEqual(@as(u32, 0), test_stream_cleanup_count);
    try std.testing.expect(!storage.active);

    var response = try builder.stream(.{}, TestChunkSource{});
    defer response.deinit();
    try std.testing.expectError(
        error.StreamHeadersMustBeConfigured,
        response.addHeader("x-runtime", "forbidden"),
    );
}
