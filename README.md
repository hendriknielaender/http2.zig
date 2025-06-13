> [!WARNING]  
> Still work in progress.

<h1 align="center">
   <img src="docs/images/logo.png" width="40%" height="40%" alt="http2.zig logo" title="http2.zig logo">
</h1>

<div align="center">

**A high-performance HTTP/2 protocol implementation in Zig**

RFC 7540 compliant • Zero dependencies

[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/LICENSE)
[![Zig 0.14.0](https://img.shields.io/badge/zig-0.14.0-orange.svg)](https://ziglang.org)
[![h2spec Conformance](https://img.shields.io/badge/h2spec-50%2F64%20tests%20passing-green)](https://github.com/summerwind/h2spec)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/CONTRIBUTING.md)

</div>

---

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
const http2_module = b.dependency("http2", .{
    .target = target,
    .optimize = optimize,
}).module("http2");

exe.root_module.addImport("http2", http2_module);
```

### Hello World Server

```zig
const std = @import("std");
const http2 = @import("http2");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const address = try std.net.Address.resolveIp("127.0.0.1", 9001);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("HTTP/2 server listening on 127.0.0.1:9001\\n", .{});

    while (true) {
        var conn = listener.accept() catch continue;
        defer conn.stream.close();

        // Create HTTP/2 connection
        var server_conn = http2.Connection(
            std.io.AnyReader,
            std.io.AnyWriter
        ).init(
            allocator,
            conn.stream.reader().any(),
            conn.stream.writer().any(),
            true // is_server
        ) catch continue;
        defer server_conn.deinit();

        // Handle HTTP/2 protocol
        server_conn.handle_connection() catch |err| {
            std.debug.print("Connection error: {any}\\n", .{err});
        };
    }
}
```

## Architecture

```
http2.zig/
├── src/
│   ├── http2.zig          # Main entry point and public API
│   ├── connection.zig     # HTTP/2 connection management
│   ├── stream.zig         # Individual stream handling
│   ├── frame.zig          # Frame parsing and serialization
│   ├── hpack.zig          # HPACK header compression
│   ├── error.zig          # Error definitions and handling
│   └── tls.zig           # TLS integration layer
├── example/
│   └── hello-world/       # Complete working example
└── docs/                  # Documentation and guides
```

### Core Components

#### `Connection`
The heart of http2.zig - manages the HTTP/2 connection lifecycle:

```zig
const Connection = http2.Connection(ReaderType, WriterType);

// Initialize server-side connection
var conn = try Connection.init(allocator, reader, writer, true);

// Process HTTP/2 frames
try conn.handle_connection();
```

#### `Stream`
Represents individual HTTP/2 streams with full state management:

```zig
// Get or create a stream
var stream = try conn.get_stream(stream_id);

// Send response
try stream.send_headers(headers, true); // end_stream = true
```

#### `Frame`
Type-safe frame processing with zero-copy parsing:

```zig
// Read incoming frame
var frame = try conn.receive_frame();
defer frame.deinit(allocator);

// Process by type
switch (frame.header.frame_type) {
    FrameTypes.FRAME_TYPE_HEADERS => try handle_headers(frame),
    FrameTypes.FRAME_TYPE_DATA => try handle_data(frame),
    // ...
}
```

## Performance

http2.zig is designed for **maximum performance** with minimal overhead:

- **Zero-copy frame processing** - Direct buffer manipulation
- **Allocation-efficient** - Minimal allocations in hot paths  
- **HPACK optimization** - Efficient header compression/decompression
- **Flow control** - Prevents memory exhaustion under load
- **Concurrent streams** - Handle thousands of multiplexed streams

### Benchmarks

TBD

## Protocol Compliance

http2.zig implements the complete HTTP/2 specification:

### ✅ Implemented Features

- **HTTP/2 Connection Preface** (RFC 7540 §3.5)
- **Binary Frame Protocol** (RFC 7540 §4)
- **Stream States & Multiplexing** (RFC 7540 §5)
- **Flow Control** (RFC 7540 §6.9)
- **HPACK Header Compression** (RFC 7541)
- **Server Push** (RFC 7540 §8.2) - API ready
- **Error Handling** with proper GOAWAY frames

### Frame Types

| Frame Type | Status | Description |
|------------|--------|-------------|
| DATA | ✅ | Stream data with flow control |
| HEADERS | ✅ | HTTP headers with HPACK compression |
| PRIORITY | ✅ | Stream dependency and priority |
| RST_STREAM | ✅ | Stream termination |
| SETTINGS | ✅ | Connection configuration |
| PUSH_PROMISE | ✅ | Server push announcement |
| PING | ✅ | Connection liveness |
| GOAWAY | ✅ | Graceful connection shutdown |
| WINDOW_UPDATE | ✅ | Flow control window management |
| CONTINUATION | ✅ | Header block continuation |

### h2spec Conformance

**Current status: 50/64 tests passing (78%)**

```bash
# Run conformance tests
h2spec http2 -h 127.0.0.1 -p 9001
```

The remaining 14 failing tests are edge cases in error handling and will be addressed in future releases.

## Advanced Usage

### Custom Stream Handling

```zig
const MyHandler = struct {
    pub fn handle_stream(stream: *http2.Stream, headers: []const http2.Header) !void {
        // Custom request processing
        if (std.mem.eql(u8, headers[0].value, "/api/data")) {
            try stream.send_headers(&.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "application/json" },
            }, false);
            try stream.send_data("{\"message\": \"Hello HTTP/2!\"}", true);
        }
    }
};
```

### Error Handling Patterns

```zig
// Graceful error handling
conn.handle_connection() catch |err| switch (err) {
    error.ProtocolError => {
        // Client sent invalid HTTP/2 - GOAWAY already sent
        std.log.warn("Protocol violation from client", .{});
    },
    error.ConnectionResetByPeer => {
        // Normal client disconnect
        std.log.info("Client disconnected", .{});
    },
    else => return err, // Propagate unexpected errors
};
```

### Integration with TLS

```zig
// TLS-enabled HTTP/2 server
const tls_conn = try std.crypto.tls.Server.init(socket, cert, key);
var http2_conn = try http2.Connection(...).init(
    allocator,
    tls_conn.reader().any(),
    tls_conn.writer().any(),
    true
);
```

## Development

### Building

```bash
# Debug build
zig build

# Release build  
zig build -Doptimize=ReleaseFast

# Run example
zig build run
```

### Testing

```bash
# Unit tests
zig build test

# Integration tests
zig build test-integration

# Conformance tests (requires h2spec)
./example/hello-world/enhanced_h2spec.sh
```

### Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

**Areas for contribution:**
- Performance optimizations
- Additional frame type support  
- Enhanced error handling
- Documentation improvements
- More examples and tutorials

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- **HTTP/2 Specification** - [RFC 7540](https://tools.ietf.org/html/rfc7540)
- **HPACK Specification** - [RFC 7541](https://tools.ietf.org/html/rfc7541)
- **h2spec** - Conformance testing framework

