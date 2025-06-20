> [!WARNING]  
> Still work in progress.

<h1 align="center">
   <img src="docs/images/logo.png" width="40%" height="40%" alt="http2.zig logo" title="http2.zig logo">
</h1>

<div align="center">

**A high-performance HTTP/2 protocol implementation in Zig**

Cross-platform • Zero allocations

[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/LICENSE)
[![Zig 0.14.0](https://img.shields.io/badge/zig-0.14.0-orange.svg)](https://ziglang.org)
[![libxev](https://img.shields.io/badge/powered%20by-libxev-brightgreen.svg)](https://github.com/mitchellh/libxev)

</div>

---

## Features

- 🌍 **Cross-platform** support via libxev (io_uring, kqueue, epoll)
- 💾 **Zero runtime allocations** - all memory allocated at compile time
- 🔒 **Lock-free** atomic operations for maximum concurrency
- 📦 **Simple API** - just configure and run
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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize the HTTP/2 system
    try http2.init(allocator);
    defer http2.deinit();

    // Configure and create server
    const config = http2.Server.Config{
        .address = try std.net.Address.resolveIp("127.0.0.1", 3000),
        .max_connections = 1000,
    };

    var server = try http2.Server.init(allocator, config);
    defer server.deinit();

    std.log.info("HTTP/2 server listening on {}", .{config.address});

    // Run the server
    try server.run();
}
```

## Performance

TBD

## API Reference

### Server Configuration

```zig
pub const Server.Config = struct {
    /// Address to bind to
    address: std.net.Address,
    
    /// Maximum concurrent connections (default: 1000)
    max_connections: u32 = 1000,
    
    /// Buffer size per connection (default: 32KB)
    buffer_size: u32 = 32 * 1024,
};
```

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

- Zig 0.14.0 or later
- libxev (included as dependency)

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
# Run the hello world example
zig build run-hello

# Run the benchmark server
cd benchmarks && zig build run
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

- Built with [libxev](https://github.com/mitchellh/libxev) by Mitchell Hashimoto
- Inspired by [TigerBeetle](https://tigerbeetle.com)'s zero-allocation principles
- HTTP/2 Specification - [RFC 7540](https://tools.ietf.org/html/rfc7540)
- HPACK Specification - [RFC 7541](https://tools.ietf.org/html/rfc7541)
