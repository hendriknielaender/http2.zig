> [!WARNING]  
> Still work in progress.

<h1 align="center">
   <img src="logo.png" width="40%" height="40%" alt="http2.zig logo" title="http2.zig logo">
</h1>

<div align="center">A HTTP/2 Zig library according to the HTTP/2 RFCs.</div>
<div align="center">
   
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/LICENSE)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/hendriknielaender/http2.zig)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/hendriknielaender/http2.zig/blob/HEAD/CONTRIBUTING.md)
![h2spec Conformance](https://img.shields.io/badge/h2spec-70%2F74%20tests%20passing-red)

</div>

## Features

- Connection management
- Stream handling
- Frame parsing and serialization
- Compliance with HTTP/2 specifications

## Installation

You can use `zig fetch` to conveniently set the hash in the `build.zig.zon` file and update an existing dependency.

Run the following command to fetch the http2.zig package:
```shell
zig fetch https://github.com/hendriknielaender/http2.zig/archive/<COMMIT>.tar.gz --save
```
Using `zig fetch` simplifies managing dependencies by automatically handling the package hash, ensuring your `build.zig.zon` file is up to date.

### Option 1 (build.zig.zon)

1. Declare http2.zig as a dependency in `build.zig.zon`:

   ```diff
   .{
       .name = "my-project",
       .version = "1.0.0",
       .paths = .{""},
       .dependencies = .{
   +       .http2 = .{
   +           .url = "https://github.com/hendriknielaender/http2.zig/archive/<COMMIT>.tar.gz",
   +       },
       },
   }
   ```

2. Add the module in `build.zig`:

   ```diff
   const std = @import("std");

   pub fn build(b: *std.Build) void {
       const target = b.standardTargetOptions(.{});
       const optimize = b.standardOptimizeOption(.{});

   +   const opts = .{ .target = target, .optimize = optimize };
   +   const http2_module = b.dependency("http2", opts).module("http2");

       const exe = b.addExecutable(.{
           .name = "test",
           .root_source_file = b.path("src/main.zig"),
           .target = target,
           .optimize = optimize,
       });
   +   exe.root_module.addImport("http2", http2_module);
       exe.install();

       ...
   }
   ```

3. Get the package hash:

   ```shell
   $ zig build
   my-project/build.zig.zon:6:20: error: url field is missing corresponding hash field
           .url = "https://github.com/hendriknielaender/http2.zig/archive/<COMMIT>.tar.gz",
                  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   note: expected .hash = "<HASH>",
   ```

4. Update `build.zig.zon` package hash value:

   ```diff
   .{
       .name = "my-project",
       .version = "1.0.0",
       .paths = .{""},
       .dependencies = .{
           .http2 = .{
               .url = "https://github.com/hendriknielaender/http2.zig/archive/<COMMIT>.tar.gz",
   +           .hash = "<HASH>",
           },
       },
   }
   ```

## Usage

### Connection

To create an HTTP/2 connection, use the `Connection` struct. This struct handles the initialization, sending of the HTTP/2 preface, settings, and managing streams.

```zig
const std = @import("std");
const http2 = @import("http2");

const Connection = http2.Connection(std.io.AnyReader, std.io.AnyWriter);

pub fn main() !void {
    const address = try std.net.Address.resolveIp("0.0.0.0", 8081);
    var listener = try address.listen(.{ .reuse_address = true });
    defer listener.deinit();

    std.debug.print("Listening on 127.0.0.1:8081...\n", .{});

    while (true) {
        var conn = try listener.accept();
        defer conn.stream.close(); 

        std.debug.print("Accepted connection from: {any}\n", .{conn.address});

        var server_conn = Connection.init(@constCast(&std.heap.page_allocator), conn.stream.reader().any(), conn.stream.writer().any(), true) catch |err| {
            std.debug.print("Failed to initialize connection: {}\n", .{err});
            continue;
        };
        defer server_conn.deinit();

        // Handle connection and errors during the process
        server_conn.handleConnection() catch |err| {
            std.debug.print("Error handling connection: {}\n", .{err});
        };

        std.debug.print("Connection from {any} closed\n", .{conn.address});
    }
}
```
