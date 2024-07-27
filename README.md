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

</div>

## Features

- Connection management
- Stream handling
- Frame parsing and serialization
- Compliance with HTTP/2 specifications

## Installation

Add `http2.zig` to your Zig project by including it in your build script.

## Usage

### Connection

To create an HTTP/2 connection, use the `Connection` struct. This struct handles the initialization, sending of the HTTP/2 preface, settings, and managing streams.

```zig
const std = @import("std");
const Connection = @import("http2.zig").Connection;

pub fn main() void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);
    const reader = buffer_stream.reader();
    const writer = buffer_stream.writer();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    const conn = try ConnectionType.init(&allocator, reader, writer, false);
}
