//! HTTP request-target normalization as defined by RFC 9113 § 8.1.2.3.
//!
//! The module normalises percent-encoded bytes, resolves `.` and `..` path
//! segments, separates the query string, and rejects targets containing
//! embedded NUL bytes — all without touching the heap.
//!
//! A fast-path check (`normalizedRequestTarget`) avoids the slow normalisation
//! loop for the common case where the target is already canonical. On the
//! benchmark hot path (>99th-percentile requests) this skips the per-character
//! decode loop entirely.

const std = @import("std");

/// A decomposed request target whose path has been normalised.
pub const RequestTarget = struct {
    normalized_path: []const u8,
    query: []const u8,
};

/// Return the target unchanged when the raw form is already canonical.
/// Returns null when the slow normalisation path is required.
pub fn normalizedRequestTarget(raw_target: []const u8) ?RequestTarget {
    const query_index = std.mem.indexOfScalar(u8, raw_target, '?') orelse raw_target.len;
    const raw_path = raw_target[0..query_index];
    if (!requestPathIsNormalized(raw_path)) {
        return null;
    }

    const query = if (query_index < raw_target.len)
        raw_target[query_index + 1 ..]
    else
        "";

    return .{
        .normalized_path = raw_path,
        .query = query,
    };
}

/// Fully normalise `raw_target` into caller-owned `storage`.
/// Returns the normalised path slice and the query slice.
/// `storage` must be large enough to hold the result; callers should size it
/// to at least `raw_target.len`.
pub fn normalizeRequestTarget(
    raw_target: []const u8,
    storage: []u8,
) !RequestTarget {
    if (storage.len == 0) {
        return error.RequestTargetTooLarge;
    }

    const query_index = std.mem.indexOfScalar(u8, raw_target, '?') orelse raw_target.len;
    const raw_path = raw_target[0..query_index];
    const query = if (query_index < raw_target.len)
        raw_target[query_index + 1 ..]
    else
        "";

    var source_index: usize = 0;
    var target_index: usize = 0;
    var last_slash: usize = 0;

    storage[target_index] = '/';
    target_index += 1;
    if (raw_path.len > 0 and raw_path[0] == '/') {
        source_index = 1;
    }

    while (source_index < raw_path.len) {
        const decoded = try decodePathByte(raw_path, &source_index);
        if (decoded == 0) {
            return error.InvalidRequestTarget;
        }

        if (decoded == '/') {
            const rewind = rewindSpecialPath(
                storage[0..target_index],
                last_slash,
            );
            target_index -= rewind;
            if (rewind > 0) {
                last_slash = if (target_index > 0) target_index - 1 else 0;
                continue;
            }
            last_slash = target_index;
        }

        if (target_index >= storage.len) {
            return error.RequestTargetTooLarge;
        }
        storage[target_index] = decoded;
        target_index += 1;
    }

    const rewind = rewindSpecialPath(
        storage[0..target_index],
        last_slash,
    );
    target_index -= rewind;
    if (target_index == 0) {
        storage[0] = '/';
        target_index = 1;
    }

    return .{
        .normalized_path = storage[0..target_index],
        .query = query,
    };
}

/// Fast check: returns true when `raw_path` is already canonical and the
/// slow normalisation loop can be skipped.
fn requestPathIsNormalized(raw_path: []const u8) bool {
    if (raw_path.len == 0) {
        return false;
    }
    if (raw_path[0] != '/') {
        return false;
    }

    var segment_start: usize = 1;
    var index: usize = 1;
    while (index <= raw_path.len) : (index += 1) {
        if (index < raw_path.len) {
            const byte = raw_path[index];
            if (byte == 0) {
                return false;
            }
            if (byte == '%') {
                return false;
            }
            if (byte != '/') {
                continue;
            }
        }

        if (requestPathSegmentIsSpecial(raw_path[segment_start..index])) {
            return false;
        }
        segment_start = index + 1;
    }

    return true;
}

/// Returns true when `segment` is `.` or `..` — the two tokens that
/// require rewind behaviour during normalisation.
fn requestPathSegmentIsSpecial(segment: []const u8) bool {
    if (segment.len == 1) {
        return segment[0] == '.';
    }
    if (segment.len == 2) {
        if (segment[0] == '.') {
            return segment[1] == '.';
        }
    }
    return false;
}

/// Decode one byte from `raw_path` starting at `source_index`.
/// Handles percent-encoding and advances `source_index` past the consumed
/// input.  Returns the decoded byte or an error for embedded NUL bytes.
fn decodePathByte(raw_path: []const u8, source_index: *usize) !u8 {
    std.debug.assert(source_index.* < raw_path.len);

    const current = raw_path[source_index.*];
    if (current != '%') {
        source_index.* += 1;
        return current;
    }

    // Incomplete percent-encoding; return the literal '%' and advance.
    if (source_index.* + 2 >= raw_path.len) {
        source_index.* += 1;
        return current;
    }

    const hi = decodeHexDigit(raw_path[source_index.* + 1]) orelse {
        source_index.* += 1;
        return current;
    };
    const lo = decodeHexDigit(raw_path[source_index.* + 2]) orelse {
        source_index.* += 1;
        return current;
    };

    source_index.* += 3;
    return (hi << 4) | lo;
}

/// Decode a single hex digit. Returns null when the byte is outside 0-9, A-F, a-f.
fn decodeHexDigit(byte: u8) ?u8 {
    if (byte >= '0' and byte <= '9') return byte - '0';
    if (byte >= 'A' and byte <= 'F') return byte - 'A' + 10;
    if (byte >= 'a' and byte <= 'f') return byte - 'a' + 10;
    return null;
}

/// Compute how many bytes to "rewind" after encountering a `.` or `..` segment
/// at the end of a path.  `last_slash` is the byte index of the most recent `/`.
fn rewindSpecialPath(path: []const u8, last_slash: usize) usize {
    std.debug.assert(path.len > 0);
    std.debug.assert(last_slash < path.len);

    const original_len = path.len;
    var new_len = original_len;
    const part_len = original_len - last_slash;

    if (part_len == 2 and path[original_len - 1] == '.') {
        new_len -= 1;
    } else if (part_len == 3 and path[original_len - 2] == '.' and path[original_len - 1] == '.') {
        new_len -= 2;
        if (new_len > 1) {
            while (new_len > 0 and path[new_len - 1] != '/') {
                new_len -= 1;
            }
        }
    }

    return original_len - new_len;
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test "normalized request target fast path accepts canonical target" {
    const target = normalizedRequestTarget("/baseline2?a=1&b=2").?;

    try std.testing.expectEqualStrings("/baseline2", target.normalized_path);
    try std.testing.expectEqualStrings("a=1&b=2", target.query);
}

test "normalized request target fast path rejects slow-path targets" {
    try std.testing.expect(normalizedRequestTarget("") == null);
    try std.testing.expect(normalizedRequestTarget("baseline2?a=1") == null);
    try std.testing.expect(normalizedRequestTarget("/a/../b") == null);
    try std.testing.expect(normalizedRequestTarget("/a/%62") == null);
    try std.testing.expect(normalizedRequestTarget("/a/./b") == null);
}

test "normalize path decodes percent encoding" {
    var storage: [128]u8 = undefined;
    const target = try normalizeRequestTarget("/%48%65%6c%6c%6f", &storage);
    try std.testing.expectEqualStrings("/Hello", target.normalized_path);
}

test "normalize path rejects embedded NUL" {
    var storage: [128]u8 = undefined;
    try std.testing.expectError(
        error.InvalidRequestTarget,
        normalizeRequestTarget("/%00", &storage),
    );
}

test "normalize path rejects storage too small" {
    var storage: [1]u8 = undefined;
    try std.testing.expectError(
        error.RequestTargetTooLarge,
        normalizeRequestTarget("/abcdefgh", &storage),
    );
}
