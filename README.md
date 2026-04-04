> [!WARNING]  
> Still work in progress.

<h1 align="center">
   <img src="docs/images/logo.png" width="40%" height="40%" alt="http2.zig logo" title="http2.zig logo">
</h1>

<div align="center">

**A high-performance HTTP/2 protocol implementation in Zig**

Cross-platform • Zero allocations

[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/LICENSE)
[![Zig 0.15.2](https://img.shields.io/badge/zig-0.15.2-orange.svg)](https://ziglang.org)
[![std.Io](https://img.shields.io/badge/powered%20by-std.Io-brightgreen.svg)](https://ziglang.org/)

</div>

---

## Features

- 🌍 **Cross-platform** support via Zig std.Io backends
- 💾 **Zero runtime allocations** - all memory allocated at compile time
- 🔒 **Lock-free** atomic operations for maximum concurrency
- 🧩 **Bring your own router** - plug in any dispatcher or router you want
- ✅ **HTTP/2 RFC 7540** compliant

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
    try server.run();
}
```

Repository examples:

- `examples/basic_tls.zig` shows the same dispatcher API with a small custom Zig router.
- `examples/turboapi.zig` shows the `turboapi-core` integration with TLS.

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

- Zig v0.16.0-dev.2905+5d71e3051

### Build Commands

```bash
# Build the library
zig build

# Run tests
zig build test

# Build with optimizations
zig build -Doptimize=ReleaseFast
```

### Running Examples

```bash
# Run the basic TLS example with the local Zig router
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
- HTTP/2 Specification - [RFC 7540](https://tools.ietf.org/html/rfc7540)
- HPACK Specification - [RFC 7541](https://tools.ietf.org/html/rfc7541)
