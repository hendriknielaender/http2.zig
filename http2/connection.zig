// connection.zig
const std = @import("std");
pub const Stream = @import("stream.zig").Stream;
pub const Frame = @import("frame.zig").Frame;
pub const FrameHeader = @import("frame.zig").FrameHeader;
pub const FrameFlags = @import("frame.zig").FrameFlags;
pub const FrameType = @import("frame.zig").FrameType;
pub const FrameTypes = @import("frame.zig");
pub const Hpack = @import("hpack.zig").Hpack;

const log = std.log.scoped(.connection);
const assert = std.debug.assert;

const http2_preface: []const u8 = "\x50\x52\x49\x20\x2A\x20\x48\x54\x54\x50\x2F\x32\x2E\x30\x0D\x0A\x0D\x0A\x53\x4D\x0D\x0A\x0D\x0A";

pub fn Connection(comptime ReaderType: type, comptime WriterType: type) type {
    return struct {
        allocator: *std.mem.Allocator,
        reader: ReaderType,
        writer: WriterType,
        settings: Settings,
        recv_window_size: i32 = 65535,
        send_window_size: i32 = 65535,
        streams: std.AutoHashMap(u32, *Stream),
        hpack_dynamic_table: Hpack.DynamicTable,
        goaway_sent: bool = false,
        expecting_continuation_stream_id: ?u32 = null,
        last_stream_id: u32 = 0,
        client_settings_received: bool = false,

        pub fn init(allocator: *std.mem.Allocator, reader: ReaderType, writer: WriterType, comptime is_server: bool) !@This() {
            var self = @This(){
                .allocator = allocator,
                .reader = reader,
                .writer = writer,
                .settings = Settings.default(),
                .recv_window_size = 65535,
                .send_window_size = 65535,
                .streams = std.AutoHashMap(u32, *Stream).init(allocator.*),
                .hpack_dynamic_table = try Hpack.DynamicTable.init(allocator, 4096),
            };

            if (is_server) {
                try self.check_server_preface();
            } else {
                try self.send_preface();
            }

            try self.send_settings();
            return self;
        }

        fn check_server_preface(self: *@This()) !void {
            const preface_len = 24;
            var preface_buf: [preface_len]u8 = undefined;
            _ = try self.reader.readAll(&preface_buf);

            if (!std.mem.eql(u8, &preface_buf, http2_preface)) {
                try self.send_goaway(0, 0x1, "Invalid preface: PROTOCOL_ERROR");
                return error.InvalidPreface;
            }
            log.debug("Valid HTTP/2 preface received\n", .{});
        }

        pub fn deinit(self: @This()) void {
            // Deinitialize and free streams
            var it = self.streams.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.*.deinit();
            }
            @constCast(&self.streams).deinit();

            self.hpack_dynamic_table.table.deinit();
            log.debug("Resources deinitialized for connection\n", .{});
        }

        fn send_preface(self: @This()) !void {
            try self.writer.writeAll(http2_preface);
        }

        pub fn highest_stream_id(self: @This()) u32 {
            var stream_id: u32 = 0;

            var it = self.streams.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* > stream_id) {
                    stream_id = entry.key_ptr.*;
                }
            }

            return stream_id;
        }

        /// Sends a RST_STREAM frame for a given stream ID with the specified error code.
        pub fn send_rst_stream(self: *@This(), stream_id: u32, error_code: u32) !void {
            var frame_header = FrameHeader{
                .length = 4,
                .frame_type = FrameTypes.FRAME_TYPE_RST_STREAM, // 3 for RST_STREAM
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = stream_id, // The stream ID for which to send RST_STREAM
            };

            // Write the frame header
            try frame_header.write(self.writer);

            // Write the error code as a 4-byte big-endian integer
            var error_code_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, error_code_bytes[0..4], error_code, .big);
            try self.writer.writeAll(&error_code_bytes);

            log.debug("Sent RST_STREAM frame with error code {d} for stream ID {d}\n", .{ error_code, stream_id });
        }

        /// Adjust frame handling and validation per RFC 9113.
        pub fn handle_connection(self: *@This()) !void {
            // Phase 1: Exchange SETTINGS frames
            while (!self.client_settings_received) {
                var frame = self.receive_frame() catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };
                defer frame.deinit(self.allocator);

                // Classify frame based on stream_id
                if (frame.header.stream_id == 0) {
                    try handle_connection_level_frame(self, frame);
                } else {
                    try handle_stream_level_frame(self, frame);
                }

                // Check if SETTINGS frame with ACK flag was received (if client is acknowledging server's SETTINGS)
                if (frame.header.frame_type == FrameTypes.FRAME_TYPE_SETTINGS and (frame.header.flags.value & FrameFlags.ACK) != 0) {
                    self.client_settings_received = true;
                }
            }

            // Phase 2: Handle other frames
            while (!self.goaway_sent) {
                var frame = self.receive_frame() catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };
                defer frame.deinit(self.allocator);

                if (self.expecting_continuation_stream_id) |stream_id| {
                    if (frame.header.stream_id != stream_id or frame.header.frame_type != FrameTypes.FRAME_TYPE_CONTINUATION) {
                        // Received a frame other than CONTINUATION while expecting CONTINUATION
                        log.err("Received frame type {d} on stream {d} while expecting CONTINUATION frame on stream {d}: PROTOCOL_ERROR\n", .{ frame.header.frame_type, frame.header.stream_id, stream_id });
                        try self.send_goaway(self.highest_stream_id(), 0x1, "Expected CONTINUATION frame: PROTOCOL_ERROR");
                        return error.ProtocolError;
                    }
                }

                if (!is_valid_frame_type(frame.header.frame_type)) {
                    // Unknown frame type, ignore it as per RFC 7540 Section 5.5
                    log.debug("Ignoring unknown frame type {d}\n", .{frame.header.frame_type});
                    continue; // Ignore this frame and continue processing
                }

                log.debug("Received frame of type: {d}, stream ID: {d}\n", .{ frame.header.frame_type, frame.header.stream_id });

                const is_conn_level = is_connection_level_frame(frame.header.frame_type);

                if (is_conn_level) {
                    try handle_connection_level_frame(self, frame);
                } else {
                    try handle_stream_level_frame(self, frame);
                }

                if (self.goaway_sent) {
                    log.debug("GOAWAY has been sent, stopping frame processing.\n", .{});
                    break;
                }
            }

            log.debug("Connection terminated gracefully after GOAWAY.\n", .{});
        }

        pub fn handle_connection2(self: *@This()) !void {
            // Phase 1: Exchange SETTINGS frames
            while (!self.client_settings_received) {
                var frame = self.receive_frame() catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };
                defer frame.deinit(self.allocator);

                // Only SETTINGS and PING frames are allowed in this phase
                if (is_connection_level_frame(frame.header.frame_type)) {
                    switch (frame.header.frame_type) {
                        FrameTypes.FRAME_TYPE_SETTINGS => {
                            try self.apply_frame_settings(frame);
                            // Send SETTINGS ACK
                            try self.send_settings_ack();
                        },
                        FrameTypes.FRAME_TYPE_PING => {
                            try handle_ping_frame(self, frame);
                        },
                        else => {
                            log.err("Received unexpected connection-level frame type {d} before SETTINGS exchange: PROTOCOL_ERROR\n", .{frame.header.frame_type});
                            try self.send_goaway(self.last_stream_id, 0x1, "Unexpected frame before SETTINGS exchange: PROTOCOL_ERROR");
                            return error.ProtocolError;
                        },
                    }
                } else {
                    log.err("Received non-connection-level frame: {any} before SETTINGS exchange: PROTOCOL_ERROR\n", .{frame.header.frame_type});
                    try self.send_goaway(self.last_stream_id, 0x1, "Non-connection-level frame before SETTINGS exchange: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }

                // Check if SETTINGS frame with ACK flag was received (if client is acknowledging server's SETTINGS)
                if (frame.header.frame_type == FrameTypes.FRAME_TYPE_SETTINGS and (frame.header.flags.value & FrameFlags.ACK) != 0) {
                    self.client_settings_received = true;
                }
            }

            // Phase 2: Handle other frames
            while (!self.goaway_sent) {
                var frame = self.receive_frame() catch |err| {
                    self.handle_receive_frame_error(err) catch |handle_err| {
                        return handle_err;
                    };
                    return;
                };
                defer frame.deinit(self.allocator);

                log.debug("Received frame of type: {d}, stream ID: {d}\n", .{ frame.header.frame_type, frame.header.stream_id });

                const is_conn_level = is_connection_level_frame(frame.header.frame_type);

                if (is_conn_level) {
                    try handle_connection_level_frame(self, frame);
                } else {
                    try handle_stream_level_frame(self, frame);
                }

                if (self.goaway_sent) {
                    log.debug("GOAWAY has been sent, stopping frame processing.\n", .{});
                    break;
                }
            }

            log.debug("Connection terminated gracefully after GOAWAY.\n", .{});
        }

        fn handle_goaway_frame(self: *@This(), frame: Frame) !void {
            if (frame.payload.len < 8) {
                log.debug("Invalid GOAWAY frame size, expected at least 8 bytes.\n", .{});
                try self.send_goaway(self.last_stream_id, 0x1, "Invalid GOAWAY frame: PROTOCOL_ERROR");
                return error.ProtocolError;
            }

            // Extract the last_stream_id and error_code
            const last_stream_id = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFFFFFF;
            const error_code = std.mem.readInt(u32, frame.payload[4..8], .big);

            log.debug("Received GOAWAY with last_stream_id={d}, error_code={d}\n", .{ last_stream_id, error_code });

            // Optionally handle debug data if present
            if (frame.payload.len > 8) {
                const debug_data = frame.payload[8..];
                log.debug("GOAWAY debug data: {any}\n", .{debug_data});
            }

            // Set the goaway_sent flag and gracefully close the connection
            self.goaway_sent = true;
            return;
        }

        fn handle_stream_level_frame(self: *@This(), frame: Frame) !void {
            if (!is_valid_frame_type(frame.header.frame_type)) {
                // Unknown frame type, ignore as per RFC 7540 Section 5.5
                log.debug("Ignoring unknown stream-level frame type {d}\n", .{frame.header.frame_type});
                return;
            }

            // Validate that stream-level frames do not have stream ID 0
            if (frame.header.stream_id == 0) {
                log.err("Received stream-level frame {d} with stream ID 0: PROTOCOL_ERROR\n", .{frame.header.frame_type});
                try self.send_goaway(self.last_stream_id, 0x1, "Stream-level frame with stream ID 0: PROTOCOL_ERROR");
                return error.ProtocolError;
            }

            // Retrieve the corresponding stream
            var stream = self.get_stream(frame.header.stream_id) catch |err| {
                if (err == error.ProtocolError) {
                    // Protocol error has been handled in get_stream
                    return;
                } else if (err == error.MaxConcurrentStreamsExceeded) {
                    // Handle exceeding concurrent streams by sending RST_STREAM directly
                    log.err("Cannot create stream {d}: Max concurrent streams exceeded.\n", .{frame.header.stream_id});

                    // **Send RST_STREAM with REFUSED_STREAM (0x7) without creating a temporary stream**
                    try self.send_rst_stream(frame.header.stream_id, 0x7); // REFUSED_STREAM
                    log.debug("Sent RST_STREAM with REFUSED_STREAM (0x7) for stream ID {d}\n", .{frame.header.stream_id});

                    return;
                } else {
                    return err;
                }
            };

            // Handle the frame within the stream
            stream.handleFrame(frame) catch |err| {
                log.err("Error handling frame in stream {d}: {s}\n", .{ frame.header.stream_id, @errorName(err) });

                // If a GOAWAY has been sent, do not send additional frames
                if (self.goaway_sent) {
                    return;
                }

                // Handle specific errors accordingly
                switch (err) {
                    error.CompressionError => {
                        try self.send_goaway(0, 0x9, "Compression error: COMPRESSION_ERROR");
                        return;
                    },
                    error.StreamClosed => {
                        // Do not send RST_STREAM if GOAWAY has been sent
                        if (!self.goaway_sent) {
                            log.debug("Stream {d}: Detected StreamClosed error, sending RST_STREAM with STREAM_CLOSED (0x5)\n", .{frame.header.stream_id});
                            try self.send_rst_stream(frame.header.stream_id, 0x5); // STREAM_CLOSED
                        }
                        return;
                    },
                    error.ProtocolError => {
                        try self.send_goaway(self.last_stream_id, 0x1, "Protocol error: PROTOCOL_ERROR");
                        return err;
                    },
                    error.InvalidStreamState, error.IdleStreamError => {
                        try self.send_goaway(0, 0x1, "Invalid stream state: PROTOCOL_ERROR");
                        return;
                    },
                    else => {
                        // Handle other errors if necessary
                    },
                }
            };

            // If the frame is a HEADERS or PUSH_PROMISE frame without END_HEADERS, set expecting_continuation_stream_id
            if (frame.header.frame_type == FrameTypes.FRAME_TYPE_HEADERS or frame.header.frame_type == FrameTypes.FRAME_TYPE_PUSH_PROMISE) {
                if ((frame.header.flags.value & FrameFlags.END_HEADERS) == 0) {
                    self.expecting_continuation_stream_id = frame.header.stream_id;
                }
            }

            // If the frame is a CONTINUATION frame with END_HEADERS, clear expecting_continuation_stream_id
            if (frame.header.frame_type == FrameTypes.FRAME_TYPE_CONTINUATION) {
                if ((frame.header.flags.value & FrameFlags.END_HEADERS) != 0) {
                    self.expecting_continuation_stream_id = null;
                }
            }

            // If the stream was closed, it will be removed in process_pending_streams
        }

        fn process_pending_streams(self: *@This()) !void {
            var to_remove = std.ArrayList(u32).init(self.allocator.*);
            defer to_remove.deinit();

            var it = self.streams.iterator();
            while (it.next()) |entry| {
                const stream = entry.value_ptr.*;
                if (stream.request_complete and stream.state == .Closed) {
                    try to_remove.append(entry.key_ptr.*);
                }
            }

            // Remove the closed streams from the map
            for (to_remove.items) |stream_id| {
                _ = self.streams.remove(stream_id);
            }
        }

        fn handle_connection_level_frame(self: *@This(), frame: Frame) !void {
            if (!is_valid_frame_type(frame.header.frame_type)) {
                // Unknown frame type, ignore as per RFC 7540 Section 5.5
                log.debug("Ignoring unknown connection-level frame type {d}\n", .{frame.header.frame_type});
                return;
            }

            // Validate that connection-level frames have stream ID 0
            if (frame.header.stream_id != 0) {
                log.err("Received {d} frame with non-zero stream ID {d}: PROTOCOL_ERROR\n", .{ frame.header.frame_type, frame.header.stream_id });
                try self.send_goaway(self.last_stream_id, 0x1, "Frame with invalid stream ID: PROTOCOL_ERROR");
                return error.ProtocolError;
            }

            switch (frame.header.frame_type) {
                FrameTypes.FRAME_TYPE_SETTINGS => {
                    if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                        // Apply client settings
                        try self.apply_frame_settings(frame);
                        // Send SETTINGS ACK
                        try self.send_settings_ack();
                    }
                    // If ACK is set, no action needed
                },
                FrameTypes.FRAME_TYPE_PING => {
                    try handle_ping_frame(self, frame);
                },
                FrameTypes.FRAME_TYPE_WINDOW_UPDATE => {
                    try self.handle_window_update(frame);
                },
                FrameTypes.FRAME_TYPE_GOAWAY => {
                    try handle_goaway_frame(self, frame);
                },
                else => {
                    // Ignore unknown connection-level frame types as per RFC 7540 Section 6
                    log.warn("Received unknown connection-level frame type {d}, ignoring as per RFC 7540 Section 6\n", .{frame.header.frame_type});
                    // No action needed; simply ignore and continue
                },
            }
        }

        fn handle_ping_frame(self: *@This(), frame: Frame) !void {
            if (frame.payload.len != 8) {
                log.debug("Invalid PING frame size, expected 8 bytes.\n", .{});
                return error.InvalidPingPayloadSize;
            }

            // Only respond if ACK flag is not set
            if ((frame.header.flags.value & FrameFlags.ACK) == 0) {
                try self.send_ping(frame.payload, true); // Send PING response with ACK
                log.debug("Responded to PING frame with ACK\n", .{});
            } else {
                log.debug("Received PING frame with ACK flag set, no response sent.\n", .{});
            }
        }

        fn handle_receive_frame_error(self: *@This(), err: anytype) !void {
            switch (err) {
                error.FrameSizeError => {
                    log.err("Frame size exceeded, sending GOAWAY: FRAME_SIZE_ERROR.\n", .{});
                    try self.send_goaway(self.highest_stream_id(), 0x6, "Frame size exceeded: FRAME_SIZE_ERROR");
                    return error.FrameSizeError;
                },
                error.UnexpectedEOF => {
                    log.debug("Client closed the connection (UnexpectedEOF)\n", .{});
                    return error.UnexpectedEOF;
                },
                error.BrokenPipe, error.ConnectionResetByPeer => {
                    log.err("Client disconnected unexpectedly (BrokenPipe/ConnectionResetByPeer)\n", .{});
                    return error.ConnectionReset;
                },
                else => {
                    log.err("Error receiving frame: {s}\n", .{@errorName(err)});
                    return err;
                },
            }
        }

        /// Sends a PING frame over the connection. The opaque data must always be exactly 8 bytes.
        /// If `ack` is true, the ACK flag will be set in the PING frame.
        /// The opaque data should be echoed exactly in case of a PING response.
        pub fn send_ping(self: *@This(), opaque_data: []const u8, ack: bool) !void {
            // Ensure the opaque data is 8 bytes long
            if (opaque_data.len != 8) {
                return error.InvalidPingPayloadSize;
            }

            var frame_header = FrameHeader{
                .length = 8, // PING payload length is always 8
                .frame_type = FrameTypes.FRAME_TYPE_PING,
                .flags = if (ack) FrameFlags{ .value = FrameFlags.ACK } else FrameFlags{ .value = 0 }, // Set ACK flag if true
                .reserved = false,
                .stream_id = 0, // PING frames must always be on stream 0
            };

            // Write the frame header
            try frame_header.write(self.writer);

            // Write the opaque data
            try self.writer.writeAll(opaque_data);

            log.debug("Sent PING frame (flags: {d}, opaque_data: {any})\n", .{ frame_header.flags.value, opaque_data });
        }

        pub fn process_request(self: *@This(), stream: *Stream) !void {
            log.debug("Processing request for stream ID: {d}\n", .{stream.id});

            // Prepare a basic response: "Hello, World!"
            const response_body = "Hello, World!";
            const response_headers = [_]Hpack.HeaderField{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "13" },
            };

            var buffer = std.ArrayList(u8).init(self.allocator.*);
            defer buffer.deinit();

            // Encode headers and write them to the buffer
            for (response_headers) |header| {
                try Hpack.encodeHeaderField(header, &self.hpack_dynamic_table, &buffer);
            }

            const encoded_headers = buffer.items;

            // Send HEADERS frame
            var headers_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(encoded_headers.len),
                    .frame_type = FrameTypes.FRAME_TYPE_HEADERS,
                    .flags = FrameFlags{
                        .value = FrameFlags.END_HEADERS, // Mark end of headers
                    },
                    .reserved = false,
                    .stream_id = stream.id,
                },
                .payload = encoded_headers,
            };
            try headers_frame.write(self.writer);

            // Send DATA frame with "Hello, World!" response
            var data_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(response_body.len),
                    .frame_type = FrameTypes.FRAME_TYPE_DATA,
                    .flags = FrameFlags{
                        .value = FrameFlags.END_STREAM, // Mark end of stream
                    },
                    .reserved = false,
                    .stream_id = stream.id,
                },
                .payload = response_body,
            };
            try data_frame.write(self.writer);

            log.debug("Sent 200 OK response with body: \"Hello, World!\"\n", .{});

            if (stream.state == .Open) {
                stream.state = .HalfClosedLocal;
            } else if (stream.state == .HalfClosedRemote) {
                stream.state = .Closed;
            }
        }

        pub fn send_settings(self: @This()) !void {
            const settings = [_][2]u32{
                .{ 1, self.settings.header_table_size }, // HEADER_TABLE_SIZE
                .{ 3, self.settings.max_concurrent_streams }, // MAX_CONCURRENT_STREAMS
                .{ 4, self.settings.initial_window_size }, // INITIAL_WINDOW_SIZE
                .{ 5, self.settings.max_frame_size }, // MAX_FRAME_SIZE
                .{ 6, self.settings.max_header_list_size }, // MAX_HEADER_LIST_SIZE
            };

            // Define the settings frame header
            var frame_header = FrameHeader{
                .length = @intCast(6 * settings.len), // 6 bytes per setting
                .frame_type = FrameTypes.FRAME_TYPE_SETTINGS,
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = 0, // 0 indicates a connection-level frame
            };

            // Write the frame header first
            try frame_header.write(self.writer);

            var buffer: [6]u8 = undefined;
            for (settings) |setting| {
                // Serialize Setting ID as u16 (big-endian)
                std.mem.writeInt(u16, buffer[0..2], @intCast(setting[0]), .big);
                // Serialize Setting Value as u32 (big-endian)
                std.mem.writeInt(u32, buffer[2..6], setting[1], .big);

                log.debug("Writing setting: ", .{});
                for (buffer) |byte| {
                    log.debug("{any} ", .{byte});
                }
                log.debug("\n", .{});

                try self.writer.writeAll(buffer[0..6]);
            }
        }

        pub fn receive_frame(self: *@This()) !Frame {
            var header_buf: [9]u8 = undefined;

            // Read the frame header (9 bytes) in a loop to handle partial reads
            var header_read: usize = 0;
            while (header_read < 9) {
                const bytes_read = try self.reader.read(header_buf[header_read..]);
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                }
                header_read += bytes_read;
            }

            // Manually parse frame length (first 3 bytes)
            const length: u32 = (@as(u32, header_buf[0]) << 16) | (@as(u32, header_buf[1]) << 8) | @as(u32, header_buf[2]);

            log.debug("Received frame length: {d}, max_frame_size: {d}\n", .{ length, self.settings.max_frame_size });

            // Validate the length against the max_frame_size
            if (length > self.settings.max_frame_size) {
                log.err("Received frame size {d} exceeds SETTINGS_MAX_FRAME_SIZE {d}, sending GOAWAY\n", .{ length, self.settings.max_frame_size });
                return error.FrameSizeError; // Send FRAME_SIZE_ERROR and close the connection
            }

            const frame_type: u8 = header_buf[3];

            const flags = FrameFlags{ .value = header_buf[4] };

            // Parse the stream ID (last 4 bytes of the header) in big-endian
            const stream_id_u32 = std.mem.readInt(u32, header_buf[5..9], .big) & 0x7FFFFFFF;
            const stream_id: u32 = @intCast(stream_id_u32);

            // Read the frame payload in a loop to ensure all data is read
            const payload = try self.allocator.alloc(u8, length);
            var total_read: usize = 0;
            while (total_read < length) {
                const bytes_read = try self.reader.read(payload[total_read..]);
                if (bytes_read == 0) {
                    return error.UnexpectedEOF;
                }
                total_read += bytes_read;
            }

            return Frame{
                .header = FrameHeader{
                    .length = length,
                    .frame_type = frame_type,
                    .flags = flags,
                    .stream_id = stream_id,
                    .reserved = false,
                },
                .payload = payload,
            };
        }

        fn from_int(val: u8) FrameType {
            return std.meta.int_to_enum(FrameType, val) catch undefined;
        }

        // connection.zig

        pub fn apply_frame_settings(self: *@This(), frame: Frame) !void {
            log.debug("Applying settings from frame...\n", .{});

            if (frame.header.frame_type != FrameTypes.FRAME_TYPE_SETTINGS) {
                log.err("Received frame with invalid frame type: {any}\n", .{frame.header.frame_type});
                return error.InvalidFrameType;
            }

            if (frame.header.stream_id != 0) {
                log.err("SETTINGS frame received on a non-zero stream ID: {any}\n", .{frame.header.stream_id});
                return error.InvalidStreamId;
            }

            if ((frame.header.flags.value & FrameFlags.ACK) != 0) {
                if (frame.payload.len != 0) {
                    log.err("SETTINGS frame with ACK flag and non-zero payload length\n", .{});
                    return error.FrameSizeError;
                }
                // Do not apply settings when ACK flag is set
                log.debug("Received SETTINGS ACK, no settings to apply.\n", .{});
                return;
            }

            if (frame.payload.len % 6 != 0) {
                log.err("Invalid SETTINGS frame size: {any}\n", .{frame.payload.len});
                return error.InvalidSettingsFrameSize;
            }

            const buffer = frame.payload;
            const buffer_size: usize = buffer.len;

            var i: usize = 0;
            while (i + 6 <= buffer_size) {
                // Read the setting ID (2 bytes)
                const id_ptr: *const [2]u8 = @ptrCast(&buffer[i]);
                const id = std.mem.readInt(u16, id_ptr, .big);

                // Read the setting value (4 bytes)
                const value_ptr: *const [4]u8 = @ptrCast(&buffer[i + 2]);
                const value = std.mem.readInt(u32, value_ptr, .big);

                log.debug("Setting ID: {d}, Value: {d}\n", .{ id, value });

                switch (id) {
                    1 => { // SETTINGS_HEADER_TABLE_SIZE
                        self.settings.header_table_size = value;
                        log.debug("Updated SETTINGS_HEADER_TABLE_SIZE to {any}\n", .{value});
                        try self.hpack_dynamic_table.updateMaxSize(value);
                    },
                    2 => { // SETTINGS_ENABLE_PUSH
                        if (value != 0 and value != 1) {
                            return error.ProtocolError; // Invalid value for ENABLE_PUSH
                        }
                        self.settings.enable_push = (value == 1);
                        log.debug("Updated SETTINGS_ENABLE_PUSH to {any}\n", .{self.settings.enable_push});
                    },
                    3 => { // SETTINGS_MAX_CONCURRENT_STREAMS
                        self.settings.max_concurrent_streams = value;
                        log.debug("Updated SETTINGS_MAX_CONCURRENT_STREAMS to {d}\n", .{value});
                    },
                    4 => { // SETTINGS_INITIAL_WINDOW_SIZE
                        if (value > 2147483647) {
                            return error.FlowControlError; // Initial window size too large
                        }

                        const old_initial_window_size = self.settings.initial_window_size;
                        self.settings.initial_window_size = value;
                        const value_i32: i32 = @intCast(value);
                        const old_iw_i32: i32 = @intCast(old_initial_window_size);
                        const delta: i32 = value_i32 - old_iw_i32;
                        log.debug("Updated SETTINGS_INITIAL_WINDOW_SIZE to {d}\n", .{value});

                        // Adjust window sizes of all open streams
                        var it = self.streams.iterator();
                        while (it.next()) |entry| {
                            const stream = entry.value_ptr.*;
                            stream.recv_window_size += delta;
                            if (stream.recv_window_size > 2147483647 or stream.recv_window_size < 0) {
                                // The value MUST be treated as a connection error of type FLOW_CONTROL_ERROR.
                                return error.FlowControlError;
                            }
                        }
                    },
                    5 => { // SETTINGS_MAX_FRAME_SIZE
                        if (value < 16384 or value > 16777215) {
                            return error.ProtocolError; // Invalid MAX_FRAME_SIZE
                        }
                        self.settings.max_frame_size = value;
                        log.debug("Updated SETTINGS_MAX_FRAME_SIZE to {d}\n", .{value});
                    },
                    6 => { // SETTINGS_MAX_HEADER_LIST_SIZE
                        self.settings.max_header_list_size = value;
                        log.debug("Updated SETTINGS_MAX_HEADER_LIST_SIZE to {d}\n", .{value});
                    },
                    else => {
                        // Unknown settings should be ignored
                        log.debug("Ignoring unknown setting ID: {d}\n", .{id});
                    },
                }

                i += 6; // Move to the next setting (6 bytes per setting)
            }

            log.debug("Settings applied successfully.\n", .{});
        }

        pub fn send_settings_ack(self: @This()) !void {
            if (self.goaway_sent) return;

            var frame_header = FrameHeader{
                .length = 0,
                .frame_type = FrameTypes.FRAME_TYPE_SETTINGS,
                .flags = FrameFlags{ .value = FrameFlags.ACK }, // Set ACK flag
                .reserved = false,
                .stream_id = 0,
            };

            frame_header.write(self.writer) catch |err| {
                if (err == error.BrokenPipe) {
                    log.err("Client disconnected (BrokenPipe)\n", .{});
                    return err;
                }
                return err;
            };

            log.debug("Sent SETTINGS ACK frame\n", .{});
        }

        pub fn receive_settings(self: *@This()) !void {
            const settings_frame_header_size = 9;
            var frame_header: [settings_frame_header_size]u8 = undefined;
            _ = try self.reader.readAll(&frame_header);
            const length = std.mem.readInt(u24, frame_header[0..3], .big);
            if (length % 6 != 0) return error.InvalidSettingsFrameSize;

            var settings_payload: []u8 = try self.allocator.alloc(u8, length);
            defer self.allocator.free(settings_payload);
            _ = try self.reader.readAll(settings_payload);

            var i: usize = 0;
            while (i < settings_payload.len) {
                const setting = settings_payload[i .. i + 6];
                const id = std.mem.readInt(u16, setting[0..2], .big);
                const value = std.mem.readInt(u32, setting[2..6], .big);
                switch (id) {
                    1 => self.settings.header_table_size = value,
                    3 => self.settings.max_concurrent_streams = value,
                    4 => self.settings.initial_window_size = value,
                    5 => self.settings.max_frame_size = value,
                    6 => self.settings.max_header_list_size = value,
                    else => {},
                }
                i += 6;
            }
        }

        /// Sends a GOAWAY frame with the given parameters.
        pub fn send_goaway(self: *@This(), last_stream_id: u32, error_code: u32, debug_data: []const u8) !void {
            const payload_size = 8 + debug_data.len;

            log.debug("Preparing to send GOAWAY frame with last_stream_id = {d}, error_code = {d}, payload_size = {d}\n", .{ last_stream_id, error_code, payload_size });

            assert(payload_size > 0);

            var payload = self.allocator.alloc(u8, payload_size) catch |err| {
                log.err("Failed to allocate memory for GOAWAY frame payload: {s}\n", .{@errorName(err)});
                return err;
            };
            defer self.allocator.free(payload);

            std.mem.writeInt(u32, payload[0..4], last_stream_id & 0x7FFFFFFF, .big);
            std.mem.writeInt(u32, payload[4..8], error_code, .big);

            if (debug_data.len > 0) {
                std.mem.copyForwards(u8, payload[8..], debug_data);
            }

            var goaway_frame = Frame{
                .header = FrameHeader{
                    .length = @intCast(payload_size),
                    .frame_type = FrameTypes.FRAME_TYPE_GOAWAY,
                    .flags = FrameFlags.init(0),
                    .reserved = false,
                    .stream_id = 0,
                },
                .payload = payload,
            };

            log.debug("Sending GOAWAY frame with error code {d} and last_stream_id {d}\n", .{ error_code, last_stream_id });

            log.debug("GOAWAY frame payload: {x}\n", .{payload});

            try goaway_frame.write(self.writer);

            log.debug("GOAWAY frame sent successfully\n", .{});
            self.goaway_sent = true;
        }

        pub fn close(self: *@This()) !void {
            // Determine the highest stream ID that was processed
            var stream_id: u32 = 0;

            var it = self.streams.iterator();
            while (it.next()) |entry| {
                if (entry.key_ptr.* > stream_id) {
                    stream_id = entry.key_ptr.*;
                }
            }

            // Error code 0 indicates graceful shutdown; adjust this if specific errors need to be reported.
            const error_code: u32 = 0; // 0: NO_ERROR, indicating graceful shutdown

            // Optional debug data for GOAWAY frame, informing the client about the reason
            const debug_data = "Connection closing: graceful shutdown";

            // Send the GOAWAY frame with the highest stream ID and debug information
            try self.send_goaway(stream_id, error_code, debug_data);

            // Ensure the GOAWAY frame is fully sent before closing the connection.

            // Close the underlying writer and terminate the connection gracefully
            // try self.writer.close();

            // Optionally, free up resources associated with streams
            @constCast(&self.streams).deinit();

            log.debug("Connection closed gracefully with GOAWAY frame\n", .{});
        }

        pub fn get_stream(self: *@This(), stream_id: u32) !*Stream {
            // Ensure the stream ID is valid (odd numbers for client-initiated streams)
            if (stream_id % 2 == 0) {
                log.err("Received invalid stream ID {d} from client: PROTOCOL_ERROR\n", .{stream_id});
                try self.send_goaway(0, 0x1, "Invalid stream ID: PROTOCOL_ERROR");
                return error.ProtocolError;
            }

            // Check if the stream already exists
            if (self.streams.get(stream_id)) |stream| {
                return stream;
            } else {
                // Enforce the max concurrent streams limit
                if (self.streams.count() >= self.settings.max_concurrent_streams) {
                    log.err("Exceeded max concurrent streams limit: {d}\n", .{self.settings.max_concurrent_streams});
                    return error.MaxConcurrentStreamsExceeded;
                }

                // Ensure the new stream ID is greater than the last processed stream ID
                if (stream_id <= self.last_stream_id) {
                    log.err("Received new stream ID {d} <= last_stream_id {d}: PROTOCOL_ERROR\n", .{ stream_id, self.last_stream_id });
                    try self.send_goaway(0, 0x1, "Stream ID decreased: PROTOCOL_ERROR");
                    return error.ProtocolError;
                }

                // Update the last processed stream ID
                self.last_stream_id = stream_id;

                // Initialize a new stream in-place
                const new_stream = Stream.init(self.allocator, self, stream_id) catch |err| {
                    log.err("Failed to initialize stream {d}: {s}\n", .{ stream_id, @errorName(err) });
                    return err;
                };
                try self.streams.put(stream_id, new_stream);
                return new_stream;
            }
        }

        fn update_send_window(self: *@This(), increment: i32) !void {
            self.send_window_size += increment;
            if (self.send_window_size > 2147483647) { // Max value for a signed 31-bit integer
                return error.FlowControlError;
            }
        }

        fn update_recv_window(self: *@This(), delta: i32) void {
            self.recv_window_size += delta;
        }

        fn send_window_update(self: *@This(), stream_id: u32, increment: i32) !void {
            var frame_header = FrameHeader{
                .length = 4,
                .frame_type = FrameTypes.FRAME_TYPE_WINDOW_UPDATE,
                .flags = FrameFlags.init(0),
                .reserved = false,
                .stream_id = stream_id,
            };

            var buffer: [4]u8 = undefined;
            std.mem.writeInt(u32, &buffer, @intCast(increment), .big);

            try frame_header.write(self.writer);
            try self.writer.writeAll(&buffer);
        }

        pub fn handle_window_update(self: *@This(), frame: Frame) !void {
            if (frame.payload.len != 4) {
                return error.InvalidFrameSize;
            }

            const pay: *const [4]u8 = @ptrCast(frame.payload[0..4]);
            const increment = std.mem.readInt(u32, pay, .big);

            if (increment > 0x7FFFFFFF) { // u32 max value
                return error.FlowControlError;
            }

            if (frame.header.stream_id == 0) {
                try self.update_send_window(@intCast(increment));
            } else {
                // Forward to the appropriate stream for handling
                var stream = try self.get_stream(frame.header.stream_id);
                try stream.updateSendWindow(@intCast(increment));
            }
        }

        pub fn send_data(self: *@This(), stream: *Stream, data: []const u8, end_stream: bool) !void {
            const max_frame_size = self.settings.max_frame_size;

            var remaining_data = data;
            while (remaining_data.len > 0) {
                const chunk_size = if (remaining_data.len > max_frame_size) max_frame_size else remaining_data.len;

                const data_chunk = remaining_data[0..chunk_size];
                remaining_data = remaining_data[chunk_size..];

                var data_frame = Frame{
                    .header = FrameHeader{
                        .length = @intCast(chunk_size),
                        .frame_type = FrameTypes.FRAME_TYPE_DATA,
                        .flags = FrameFlags{
                            .value = if (remaining_data.len == 0 and end_stream) FrameFlags.END_STREAM else 0,
                        },
                        .reserved = false,
                        .stream_id = stream.id,
                    },
                    .payload = data_chunk,
                };

                try data_frame.write(self.writer);
            }
        }
    };
}

const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: u32 = 100,
    initial_window_size: u32 = 65535,
    max_frame_size: u32 = 16384,
    max_header_list_size: u32 = 8192,

    pub fn default() Settings {
        return Settings{};
    }
};

/// Determines if a frame type is connection-level.
fn is_connection_level_frame(frame_type: u8) bool {
    return switch (frame_type) {
        FrameTypes.FRAME_TYPE_SETTINGS, FrameTypes.FRAME_TYPE_PING, FrameTypes.FRAME_TYPE_GOAWAY, FrameTypes.FRAME_TYPE_WINDOW_UPDATE => true,
        else => false,
    };
}

/// Determines if a frame type is valid according to HTTP/2 specification.
fn is_valid_frame_type(frame_type: u8) bool {
    // Return true only for recognized HTTP/2 frame types as per RFC 7540, Section 6.
    return switch (frame_type) {
        FrameTypes.FRAME_TYPE_DATA, FrameTypes.FRAME_TYPE_HEADERS, FrameTypes.FRAME_TYPE_PRIORITY, FrameTypes.FRAME_TYPE_RST_STREAM, FrameTypes.FRAME_TYPE_SETTINGS, FrameTypes.FRAME_TYPE_PUSH_PROMISE, FrameTypes.FRAME_TYPE_PING, FrameTypes.FRAME_TYPE_GOAWAY, FrameTypes.FRAME_TYPE_WINDOW_UPDATE, FrameTypes.FRAME_TYPE_CONTINUATION => true,
        else => false,
    };
}

/// Ensure valid flags for frame types.
fn is_valid_flags(header: FrameHeader) bool {
    const flags = header.flags.value;

    // Get the allowed flags for the frame type
    const allowed_flags = switch (header.frame_type) {
        FrameTypes.FRAME_TYPE_DATA => FrameFlags.END_STREAM | FrameFlags.PADDED,
        FrameTypes.FRAME_TYPE_HEADERS => FrameFlags.END_STREAM | FrameFlags.END_HEADERS | FrameFlags.PADDED | FrameFlags.PRIORITY,
        FrameTypes.FRAME_TYPE_PRIORITY => 0,
        FrameTypes.FRAME_TYPE_RST_STREAM => 0,
        FrameTypes.FRAME_TYPE_SETTINGS => FrameFlags.ACK,
        FrameTypes.FRAME_TYPE_PUSH_PROMISE => FrameFlags.END_HEADERS | FrameFlags.PADDED,
        FrameTypes.FRAME_TYPE_PING => FrameFlags.ACK,
        FrameTypes.FRAME_TYPE_GOAWAY => 0,
        FrameTypes.FRAME_TYPE_WINDOW_UPDATE => 0,
        FrameTypes.FRAME_TYPE_CONTINUATION => FrameFlags.END_HEADERS,
        else => 0, // Unknown frame types have no allowed flags
    };

    // Return true if no invalid flags are set
    return (flags & ~allowed_flags) == 0;
}

test "HTTP/2 connection initialization and flow control" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [8192]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);

    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var connection = try ConnectionType.init(&allocator, reader, writer, false);

    // Initialize stream
    var stream = try Stream.init(&allocator, &connection, 1);

    const preface_written_data = buffer_stream.getWritten();
    std.debug.print("Preface written data length: {d}\n", .{preface_written_data.len});

    // Encode headers using Hpack.encodeHeaderField
    const response_headers = [_]Hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "13" },
    };

    var encoded_headers = std.ArrayList(u8).init(allocator);
    defer encoded_headers.deinit();

    for (response_headers) |header| {
        try Hpack.encodeHeaderField(header, &connection.hpack_dynamic_table, &encoded_headers);
    }

    const headers_payload = try encoded_headers.toOwnedSlice();
    const headers_payload_len: u32 = @intCast(headers_payload.len);

    const headers_frame = Frame{
        .header = FrameHeader{
            .length = headers_payload_len,
            .frame_type = FrameTypes.FRAME_TYPE_HEADERS,
            .flags = FrameFlags.init(FrameFlags.END_HEADERS),
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = headers_payload,
    };
    std.debug.print("About to handle headers frame\n", .{});
    try stream.handleFrame(headers_frame);
    std.debug.print("Headers frame handled\n", .{});

    // Check if headers were written
    const headers_written_data = buffer_stream.getWritten();
    std.debug.print("Headers frame written data length: {d}\n", .{headers_written_data.len - preface_written_data.len});

    // Ensure headers frame was actually written
    assert(headers_written_data.len > preface_written_data.len);

    // Send data
    const data = "Hello, world!";
    try connection.send_data(stream, data, false);

    const written_data = buffer_stream.getWritten();

    // Debug each section length
    std.debug.print("Written data preface length: {d}\n", .{http2_preface.len});
    std.debug.print("Written data settings frame length: {d}\n", .{39});
    std.debug.print("Written data headers frame length: {d}\n", .{headers_written_data.len - preface_written_data.len});
    std.debug.print("Written data payload length: {d}\n", .{data.len});
    std.debug.print("Total written data length: {d}\n", .{written_data.len});

    // Verify the expected length
    const preface_length = 24; // 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' is 24 bytes
    const settings_frame_length = 39; // As per your logs
    const headers_frame_length = headers_payload_len + 9; // headers_payload + frame header
    const data_frame_payload_length = data.len; // 13 bytes for "Hello, world!"
    const data_frame_header_length = 9; // Standard HTTP/2 frame header size

    const data_frame_total_length = data_frame_payload_length + data_frame_header_length; // 22 bytes

    const expected_length = preface_length + settings_frame_length + headers_frame_length + data_frame_total_length; // 24 + 39 + len(headers) + 22

    std.debug.print("written_data.len = {d}, expected_length = {d}\n", .{ written_data.len, expected_length });
    assert(written_data.len == expected_length);

    // Clear buffer for next operations
    std.debug.print("Buffer before reset: {x}\n", .{buffer_stream.getWritten()});
    buffer_stream.reset();

    // Check that data was sent after reset
    const data_after_reset = "Hello again!";
    try connection.send_data(stream, data_after_reset, false);

    const sent_data = buffer_stream.getWritten();
    std.debug.print("Buffer after sending data: {x}\n", .{sent_data});
    assert(sent_data.len > 0);

    // Simulate receiving a WINDOW_UPDATE frame to increase send window size
    const window_update_frame = Frame{
        .header = FrameHeader{
            .length = 4,
            .frame_type = FrameTypes.FRAME_TYPE_WINDOW_UPDATE,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0, // Connection-level window update
        },
        .payload = &[_]u8{ 0x00, 0x00, 0x01, 0x00 },
    };

    try connection.handle_window_update(window_update_frame);

    // After handling WINDOW_UPDATE, we should be able to send more data
    try connection.send_data(stream, data_after_reset, false);
    const sent_data_after_window_update = buffer_stream.getWritten();
    assert(sent_data_after_window_update.len > sent_data.len);

    // Clean up
    try connection.close();
}

test "apply_frame_settings test" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);

    const reader = stream.reader().any();
    const writer = stream.writer().any();

    var alloc = arena.allocator();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var connection = try ConnectionType.init(&alloc, reader, writer, false);

    // Frame with the SETTINGS type and 18 bytes of payload
    const frame = Frame{
        .header = FrameHeader{
            .length = 18, // 3 settings of 6 bytes each
            .frame_type = FrameTypes.FRAME_TYPE_SETTINGS,
            .flags = FrameFlags.init(0),
            .reserved = false,
            .stream_id = 0,
        },
        .payload = &[_]u8{
            // Example settings: ID 1, value 4096; ID 3, value 100; ID 4, value 65535
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // header_table_size: 4096
            0x00, 0x03, 0x00, 0x00, 0x00, 0x64, // max_concurrent_streams: 100
            0x00, 0x04, 0x00, 0x00, 0xFF, 0xFF, // initial_window_size: 65535
        },
    };

    // Call the function to apply the frame settings via connection
    try connection.apply_frame_settings(frame);

    // Assert that the settings were applied correctly in the connection
    try std.testing.expect(connection.settings.header_table_size == 4096);
    try std.testing.expect(connection.settings.max_concurrent_streams == 100);
    try std.testing.expect(connection.settings.initial_window_size == 65535);
    std.debug.print("Settings applied successfully in test\n", .{});
}

test "send HEADERS and DATA frames with proper flow" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [8192]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);

    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var connection = try ConnectionType.init(&allocator, reader, writer, false);

    var stream = try Stream.init(&allocator, &connection, 1);

    // Send a HEADERS frame
    const headers_payload: [16]u8 = undefined;
    const headers_frame = Frame{
        .header = FrameHeader{
            .length = headers_payload.len,
            .frame_type = FrameTypes.FRAME_TYPE_HEADERS,
            .flags = FrameFlags{
                .value = FrameFlags.END_HEADERS, // Mark end of headers
            },
            .reserved = false,
            .stream_id = stream.id,
        },
        .payload = &headers_payload,
    };

    // Handle HEADERS frame
    try stream.handleFrame(headers_frame);

    // Check that the HEADERS frame was processed before continuing
    const headers_written_data = buffer_stream.getWritten();
    assert(headers_written_data.len > 0);
    std.debug.print("HEADERS frame written data length: {d}\n", .{headers_written_data.len});

    // Now send the DATA frame only after ensuring the HEADERS frame was handled
    const data = "Hello, world!";
    try connection.send_data(stream, data, false);

    const written_data = buffer_stream.getWritten();
    std.debug.print("Total written data length after DATA frame: {d}\n", .{written_data.len});
}

test "send RST_STREAM frame with correct frame_type" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var buffer: [1024]u8 = undefined;
    var buffer_stream = std.io.fixedBufferStream(&buffer);
    const reader = buffer_stream.reader().any();
    const writer = buffer_stream.writer().any();

    const ConnectionType = Connection(@TypeOf(reader), @TypeOf(writer));
    var allocator = arena.allocator();
    var connection = try ConnectionType.init(&allocator, reader, writer, false);

    var stream = try Stream.init(&allocator, &connection, 1);

    // Send RST_STREAM
    try stream.sendRstStream(0x1); // PROTOCOL_ERROR

    // Check the buffer to ensure frame_type is 3
    const written_data = buffer_stream.getWritten();
    // Frame header is 9 bytes: length (3), type (1), flags (1), stream_id (4)
    try std.testing.expectEqual(written_data[3], 3); // frame_type = 3 for RST_STREAM
}
