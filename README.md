> [!WARNING]  
> Still work in progress.

<h1 align="center">
   <img src="docs/images/logo.png" width="40%" height="40%" alt="http2.zig logo" title="http2.zig logo">
</h1>

<div align="center">

**A high-performance HTTP/2 protocol implementation in Zig**

Cross-platform protocol core • Static event-loop runtime

[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/LICENSE)
[![Zig 0.16.0](https://img.shields.io/badge/zig-0.16.0-orange.svg)](https://ziglang.org)
[![std.Io](https://img.shields.io/badge/powered%20by-std.Io-brightgreen.svg)](https://ziglang.org/)

</div>

---

## Features

- 🌍 **Cross-platform protocol core** with caller-owned readers, writers, and stream storage
- 💾 **Static Zig memory on Linux and the BSDs** - bounded pools replace hot-path heap growth
- 🔒 **Bounded concurrency** - fixed connection, stream, and event-loop task capacities
- 🧩 **Bring your own router** - plug in any dispatcher or router you want
- ✅ **RFC 9113-aligned HTTP/2 server core**, with **RFC 9218** extensible prioritization

## Quick Start

### Installation

Add http2.zig to your `build.zig.zon`:

```zig
.{
    .name = "my-project",
    .version = "1.0.0",
    .dependencies = .{
        .http2 = .{
            .url = "https://github.com/hendriknielaender/http2.zig/archive/main.tar.gz",
            .hash = "1220...", // Use `zig fetch` to get the hash
        },
    },
}
```

Import in your `build.zig`:

```zig
const http2_dep = b.dependency("http2", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("http2", http2_dep.module("http2"));
```

### Hello World Server

```zig
const std = @import("std");
const http2 = @import("http2");

fn handleRequest(ctx: *const http2.Context) !http2.Response {
    if (ctx.method == .get) {
        if (std.mem.eql(u8, ctx.path, "/")) {
            return ctx.response.text(.ok, "hello from http2.zig\n");
        }
    }

    return ctx.response.text(.not_found, "not found\n");
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize the HTTP/2 system
    try http2.init(allocator);
    defer http2.deinit();

    // Configure and create server
    const config = http2.Server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 3000),
        .dispatcher = http2.RequestDispatcher.fromHandler(handleRequest),
    };

    var server = try http2.Server.init(allocator, config);
    defer server.deinit();

    // Seal the startup allocator after every server, client pool, and
    // application resource has been created.
    http2.freeze();

    std.log.info("HTTP/2 server listening on {f}", .{config.address});

    // Run the server
    try server.run();
}
```

### Bring Your Own Router With turboapi-core

The core library stays router-agnostic. If you want radix-tree routing, path params, and HTTP
helpers, add `turboapi-core` to your application:

```bash
zig fetch --save=turboapi_core "git+https://github.com/justrach/turboapi-core.git#main"
```

Wire it into `build.zig`:

```zig
const core_dep = b.dependency("turboapi_core", .{
    .target = target,
    .optimize = optimize,
});
const core_mod = core_dep.module("turboapi-core");
exe.root_module.addImport("turboapi-core", core_mod);
```

Then bridge your router into `http2.zig` with a typed dispatcher:

```zig
const std = @import("std");
const core = @import("turboapi-core");
const http2 = @import("http2");

const App = struct {
    router: core.Router,

    fn init(target: *App, allocator: std.mem.Allocator) !void {
        target.* = .{
            .router = core.Router.init(allocator),
        };
        errdefer target.deinit();

        try target.router.addRoute("GET", "/", "index");
        try target.router.addRoute("GET", "/users/{id}", "user_show");
    }

    fn deinit(self: *App) void {
        self.router.deinit();
    }

    fn dispatch(self: *const App, ctx: *const http2.Context) !http2.Response {
        if (self.router.findRoute(ctx.method.bytes(), ctx.path)) |match_result| {
            var match = match_result;
            defer match.deinit();

            if (std.mem.eql(u8, match.handler_key, "index")) {
                return ctx.response.text(.ok, "hello\n");
            }
            if (std.mem.eql(u8, match.handler_key, "user_show")) {
                _ = match.params.get("id");
                return ctx.response.text(.ok, "user\n");
            }
        }

        return ctx.response.text(.not_found, "not found\n");
    }
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try http2.init(allocator);
    defer http2.deinit();

    var app: App = undefined;
    try App.init(&app, allocator);
    defer app.deinit();

    const config = http2.Server.Config{
        .address = try std.Io.net.IpAddress.parse("127.0.0.1", 3000),
        .dispatcher = http2.RequestDispatcher.bind(App, &app, App.dispatch),
    };

    var server = try http2.Server.init(allocator, config);
    defer server.deinit();

    // The router must also finish any startup allocation before this point.
    http2.freeze();
    try server.run();
}
```

Repository examples:

- `examples/basic_tls.zig` shows the same dispatcher API with a small custom Zig router over TLS.
- `examples/turboapi.zig` shows the `turboapi-core` integration over TLS.

### TLS With http2-boring

The core module does not own TLS or link BoringSSL. A TLS adapter package, such as
`http2-boring`, configures BoringSSL, completes the TLS handshake, verifies ALPN `h2`, and then
passes the decrypted application-data stream into the core connection entry point:

```zig
try http2.serveConnection(
    tls_conn.reader(),
    tls_conn.writer(),
    .{
        .dispatcher = dispatcher,
        .stream_storage = &connection_slots[slot_index].stream_storage,
    },
);
```

The repository examples and benchmarks use this shape through `examples/tls_server.zig`;
the core library target remains TLS-provider agnostic.
By default, the build fetches the `boring` release package and loads
`http2-boring` from that package. Override it with
`-Dhttp2-boring-root=/path/to/http2-boring` when testing a local adapter checkout.
The `boring` release source archive does not include the BoringSSL submodule, so
this build passes the local `boringssl` checkout as its source by default; use
`-Dboringssl-source-path=/path/to/boringssl` to point at another checkout.
For pooled servers, the adapter can pass caller-owned stream storage through
`http2.ServeConnectionOptions.stream_storage` to avoid per-connection stream-storage allocation.

## Streaming Responses

HTTP/2 does not use HTTP/1.1 `Transfer-Encoding: chunked`. An unknown-length response is a
sequence of flow-controlled DATA frames, with `END_STREAM` on the final frame. Use the pull-based
response API instead of calling the explicitly low-level `sendDataFrameUnsafe()` primitive:

```zig
const payload = "streamed body\n";

const Source = struct {
    bytes: [payload.len]u8 = payload.*,
    offset: usize = 0,

    pub fn read(self: *@This(), output: []u8) !http2.StreamReadResult {
        const remaining = self.bytes[self.offset..];
        const count = @min(output.len, remaining.len);
        @memcpy(output[0..count], remaining[0..count]);
        self.offset += count;
        return .{ .bytes_written = count };
    }

    pub fn isFinished(self: *const @This()) bool {
        return self.offset == self.bytes.len;
    }
};

return ctx.response.stream(
    .{ .status = .ok, .mime = .text },
    Source{},
);
```

The source value and all nested fields must fit inline in 256 bytes of aligned state owned by the
HTTP/2 stream. Pointers, slices, allocators, and other reference-bearing fields are rejected
recursively at comptime. All fallible checks precede the storage claim, so `stream()` leaves the
state caller-owned on every error and does not invoke its optional `deinit()`; after success, the
response owns cleanup. The response config is also comptime-only: custom header strings must be
static, and headers cannot be appended after the stream source is installed.
`read()` must fill the offered buffer unless that read finishes the source, must not block, and must
always make progress. The connection bounds every pull by its fixed scratch, the peer frame limit,
and both flow-control windows. It also owns scheduling, resets, and the single final `END_STREAM`.
Application chunks are not wire-frame boundaries.

Run the complete cleartext example with:

```bash
zig build run-streaming
curl --http2-prior-knowledge --no-buffer http://127.0.0.1:8080/stream
```

This API is for finite, immediately-readable producers. A long-lived SSE or externally-driven
source needs a bounded readiness/wakeup API; blocking or returning zero bytes before completion is
rejected instead of being polled.

## Static Memory Lifecycle

The memory model follows
[TigerBeetle's static-allocation design](https://tigerbeetle.com/blog/2022-10-12-a-database-without-dynamic-memory/)
and [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md),
adapted to an HTTP/2 server and client rather than a database. The bounded resources are HTTP/2
connections, concurrent streams, frame/header/body buffers, HPACK state, event-loop fibers, wait
registrations, and worker threads.

`RuntimePlan` uses checked arithmetic for the configured connection, thread, fiber, I/O-buffer,
and per-thread wait-registration counts. The published core ceiling covers the maximum accepted
configuration, including all event-loop allocator storage and OS worker-stack reservations—not just
the default two threads. Per-thread HPACK scratch is also charged to the plan. The TLS example
separately checks its larger, adapter-specific connection slot layout against the same system
ceiling.

The lifecycle has four explicit phases:

1. Call `http2.init(backing_allocator)` to open startup allocation.
2. Construct application state, server or client pools, TLS configuration, and support threads.
   Server configuration determines the exact runtime resource counts.
3. Call `http2.freeze()` before serving traffic. `Server.run()` also seals the allocator if the
   application has not already done so. Allocation, resize, remap, or free through the HTTP/2
   allocator after this point is an unconditional failure, including in `ReleaseFast` builds.
4. Call `Server.stop()`, wait for `Server.run()` to return, destroy every server or client pool,
   then call `http2.deinit()`. Teardown enters the deinitialization phase before releasing
   startup-owned pools. Calling `Server.deinit()` while its run loop or tasks are live is a
   release-safe panic rather than a use-after-free.

`Server.stop()` interrupts the accept wait without closing the listener from another thread. The
run thread unpublishes and closes the listener before `Server.run()` returns, so a stopped server
can restart without inheriting a stale cancellation or descriptor.

Capacity exhaustion is an overload condition, not permission to grow the heap. A server rejects
connections when its connection slots or event-loop tasks are full; a connection rejects excess
streams and oversized frames or header blocks through bounded protocol errors. Client code uses
`Connection.initClientInPlace` with caller-owned `Connection.StreamStorage` allocated during
startup.

The static guarantee covers memory obtained through http2.zig's phase-gated Zig allocator. The
in-tree event loop (`src/io/EventLoop.zig`) preallocates worker threads, fibers, and
wait-registration maps before the freeze boundary. It is derived from `std.Io.Kqueue`, because the
native `std.Io` backends allocate a fiber per task at runtime—`std.Io.Kqueue` and `std.Io.Uring`
both fall back to the general-purpose allocator when their free list is empty, and spawn worker
threads lazily—which a sealed allocator rejects.

Readiness polling is the only platform-specific part, and lives behind a small seam in
`src/io/poll/`: kqueue on macOS and the BSDs, epoll on Linux. The two pollers present the same
normalized event stream, so the scheduler above them is platform-neutral. Epoll carries one
interest mask per descriptor rather than one registration per direction, so its poller arms both
directions at once and fans a readiness event out to the waiting readers, writers, or both; it
also has no user-triggered filter, so out-of-band signals are a bitmask published before an
eventfd write, which keeps distinct signals from coalescing.

The bundled server fails with `StaticBackendUnavailable` on platforms with neither poller; it does
not silently fall back to `std.Io.Threaded` and its dynamic task pool. The protocol and in-place
client APIs remain transport-neutral. Another server backend must provide an equivalent
startup-allocation contract before it can make the same whole-runtime claim.

TLS has a separate allocator boundary: the `http2-boring` example embeds each adapter connection
and its fixed Zig I/O buffers in a startup-owned connection slot, and creates the I/O backend before
freeze. BoringSSL still creates and releases internal per-connection state during TLS handshakes.
BoringSSL's heap, operating-system resources, application dispatchers, and third-party routers are
not covered by the http2.zig allocator guarantee. A process-wide no-heap claim requires those
components to provide and verify their own bounded allocators.

## Performance

TBD

## API Reference

### Server Configuration

```zig
pub const Server.Config = struct {
    /// Address to bind to
    address: std.Io.net.IpAddress,

    /// Request dispatcher for application routing or request handling
    dispatcher: RequestDispatcher,
    
    /// Maximum concurrent connections (default: 1000)
    max_connections: u32 = 1000,
    
    /// Buffer size per connection (default: 32KB)
    buffer_size: u32 = 32 * 1024,

    /// Total event-loop threads, including the run thread (default: 2)
    worker_count: u16 = 2,
};
```

### Request Dispatcher

`http2.zig` no longer ships with a built-in router. Instead, `Server.Config` takes a
`RequestDispatcher`, which is just a function pointer plus optional typed state.

For stateless handling:

```zig
.dispatcher = http2.RequestDispatcher.fromHandler(handleRequest),
```

For stateful apps, middleware stacks, or third-party routers:

```zig
.dispatcher = http2.RequestDispatcher.bind(App, &app, App.dispatch),
```

This keeps transport, request parsing, and response building inside `http2.zig`, while letting the
application decide how routing, params, middleware, and fallback behavior should work.

The request context passed to handlers exposes:

- `ctx.method`
- `ctx.path`
- `ctx.query`
- `ctx.headers`
- `ctx.body`
- `ctx.response`

### Server Methods

```zig
// Create a new server
pub fn init(allocator: Allocator, config: Config) !Server

// Clean up server resources
pub fn deinit(self: *Server) void

// Run the server event loop (blocks)
pub fn run(self: *Server) !void

// Stop the server
pub fn stop(self: *Server) void

// Get server statistics
pub fn getStats(self: *Server) ServerStats
```

### Statistics

```zig
pub const ServerStats = struct {
    total_connections: u64,
    active_connections: u32,
    requests_processed: u64,
};
```

## Building

### Requirements

- Zig v0.16.0

### Build Commands

```bash
# Build the library
zig build

# Run tests
zig build test

# Enforce formatting, line/function bounds, and the TigerStyle source gate
zig build tigerstyle

# Build with optimizations
zig build -Doptimize=ReleaseFast
```

### Running Examples

```bash
# Generate local cert.pem/key.pem if needed
make cert

# Run the basic HTTP/2 over TLS example with the local Zig router
zig build run

# Run the turboapi-core example
zig build run-turboapi

# Run the benchmark server
zig build benchmark
```

### Benchmarking

```bash
cd benchmarks
./bench.sh
```

## Protocol Compliance

http2.zig implements core HTTP/2 features:

- ✅ HTTP/2 Connection Preface
- ✅ Binary Frame Protocol
- ✅ Stream Multiplexing
- ✅ Flow Control
- ✅ HPACK Header Compression
- ✅ Error Handling with GOAWAY frames
- ✅ SETTINGS frame exchange
- ✅ PING frame handling

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. No runtime allocations are introduced
3. Performance benchmarks show no regression

Areas for contribution:
- Additional frame type implementations
- Enhanced HPACK optimization
- More comprehensive examples
- Performance improvements

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with Zig 0.16 std.Io
- Inspired by [TigerBeetle](https://tigerbeetle.com)'s zero-allocation principles
- HTTP/2 Specification - [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) (obsoletes RFC 7540)
- HPACK Specification - [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
- Extensible Prioritization Scheme - [RFC 9218](https://www.rfc-editor.org/rfc/rfc9218)
