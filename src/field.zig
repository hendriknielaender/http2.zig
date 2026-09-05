//! HTTP field validation required by RFC 9113 § 8.2.1 and § 8.3.1, using the
//! stricter RFC 9110 § 5.1 and § 5.5 grammars it advises. Allocates nothing.

const std = @import("std");
const assert = std.debug.assert;

/// A u64 has at most 20 decimal digits. The parser additionally checks the
/// accumulator before every multiply/add, so the bound is explicit.
const content_length_digits_max: usize = 20;

/// RFC 9110 § 5.1 `tchar`, minus the uppercase letters RFC 9113 § 8.2.1
/// forbids in HTTP/2.
const name_byte_allowed: [256]bool = buildByteTable(nameByteIsAllowed);

/// RFC 9110 § 5.5 `field-vchar`, plus SP and HTAB. The grammar admits those
/// two only between visible characters; surrounding whitespace is rejected.
const value_byte_allowed: [256]bool = buildByteTable(valueByteIsAllowed);

/// Validation runs per field on the request hot path, so the per-byte test is
/// a load rather than a chain of comparisons.
fn buildByteTable(comptime predicate: fn (u8) bool) [256]bool {
    var table = [_]bool{false} ** 256;
    var byte: usize = 0;
    while (byte < table.len) : (byte += 1) {
        table[byte] = predicate(@intCast(byte));
    }
    return table;
}

fn nameByteIsAllowed(byte: u8) bool {
    if (byte >= 'a' and byte <= 'z') {
        return true;
    }
    if (byte >= '0' and byte <= '9') {
        return true;
    }
    return switch (byte) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

fn valueByteIsAllowed(byte: u8) bool {
    if (byte == ' ') {
        return true;
    }
    if (byte == '\t') {
        return true;
    }
    // VCHAR, then obs-text. DEL (0x7f) falls between the two and stays out.
    if (byte >= 0x21 and byte <= 0x7e) {
        return true;
    }
    return byte >= 0x80;
}

comptime {
    assert(content_length_digits_max == 20);

    // Positive space: representatives of every class the grammars admit.
    assert(name_byte_allowed['a']);
    assert(name_byte_allowed['z']);
    assert(name_byte_allowed['0']);
    assert(name_byte_allowed['9']);
    assert(name_byte_allowed['-']);
    assert(name_byte_allowed['~']);

    // Negative space: every byte RFC 9113 § 8.2.1 names explicitly.
    assert(!name_byte_allowed[0x00]);
    assert(!name_byte_allowed[0x20]);
    assert(!name_byte_allowed['A']);
    assert(!name_byte_allowed['Z']);
    assert(!name_byte_allowed[':']);
    assert(!name_byte_allowed[0x7f]);
    assert(!name_byte_allowed[0xff]);

    assert(value_byte_allowed[' ']);
    assert(value_byte_allowed['\t']);
    assert(value_byte_allowed[0x21]);
    assert(value_byte_allowed[0x7e]);
    assert(value_byte_allowed[0x80]);
    assert(value_byte_allowed[0xff]);

    assert(!value_byte_allowed[0x00]);
    assert(!value_byte_allowed['\r']);
    assert(!value_byte_allowed['\n']);
    assert(!value_byte_allowed[0x7f]);
}

/// Rejects the empty name, uppercase, SP, COLON, and every non-visible byte:
/// RFC 9113 § 8.2.1's mandatory checks plus the `token` rule it advises.
pub fn nameIsValid(name: []const u8) bool {
    if (name.len == 0) {
        return false;
    }

    for (name) |byte| {
        if (!name_byte_allowed[byte]) {
            return false;
        }
    }
    return true;
}

/// One leading colon, then a non-empty token. Delegating the remainder to
/// `nameIsValid` is what rejects a second colon (RFC 9113 § 8.2.1).
pub fn pseudoNameIsValid(name: []const u8) bool {
    if (name.len < 2) {
        return false;
    }
    if (name[0] != ':') {
        return false;
    }
    return nameIsValid(name[1..]);
}

/// An empty value is legal; NUL, CR, LF, other control bytes, and surrounding
/// whitespace are not (RFC 9113 § 8.2.1, RFC 9110 § 5.5).
pub fn valueIsValid(value: []const u8) bool {
    if (value.len == 0) {
        return true;
    }
    if (byteIsWhitespace(value[0])) {
        return false;
    }
    if (byteIsWhitespace(value[value.len - 1])) {
        return false;
    }

    for (value) |byte| {
        if (!value_byte_allowed[byte]) {
            return false;
        }
    }
    return true;
}

/// Control-data grammars (RFC 9113 § 8.3.1) admit no whitespace, so an interior
/// space that the generic field-value rule allows is rejected here.
pub fn pseudoValueIsValid(value: []const u8) bool {
    if (!valueIsValid(value)) {
        return false;
    }

    for (value) |byte| {
        if (byteIsWhitespace(byte)) {
            return false;
        }
    }
    return true;
}

fn byteIsWhitespace(byte: u8) bool {
    if (byte == ' ') {
        return true;
    }
    return byte == '\t';
}

/// RFC 9110 § 8.6 defines the value as `1*DIGIT`. `std.fmt.parseInt` would also
/// take "+5" and "1_0", lengths a peer spells differently — § 8.1.1 malformed.
pub fn parseContentLength(value: []const u8) ?u64 {
    if (value.len == 0) {
        return null;
    }
    if (value.len > content_length_digits_max) {
        return null;
    }

    var total: u64 = 0;
    for (value) |byte| {
        if (byte < '0') {
            return null;
        }
        if (byte > '9') {
            return null;
        }
        const digit: u64 = byte - '0';
        if (total > (std.math.maxInt(u64) - digit) / 10) {
            return null;
        }
        total = total * 10 + digit;
    }

    return total;
}

/// The two schemes whose extra ":authority" and ":path" restrictions
/// RFC 9113 § 8.3.1 spells out.
pub fn schemeIsHttp(scheme: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(scheme, "http")) {
        return true;
    }
    return std.ascii.eqlIgnoreCase(scheme, "https");
}

/// RFC 9113 § 8.3.1: for http and https, non-empty and '/'-rooted, or '*' for
/// asterisk-form OPTIONS. Other schemes arrive via a gateway and are left be.
pub fn pathIsValid(scheme: []const u8, method: []const u8, path_value: []const u8) bool {
    if (path_value.len == 0) {
        return false;
    }
    if (!schemeIsHttp(scheme)) {
        return true;
    }
    if (path_value[0] == '/') {
        return true;
    }
    if (!std.mem.eql(u8, method, "OPTIONS")) {
        return false;
    }
    return std.mem.eql(u8, path_value, "*");
}

/// RFC 3986 § 3.2 subcomponents. No colon yields an empty port, keeping
/// "absent" distinguishable from "explicitly zero".
const Authority = struct {
    host: []const u8,
    port: []const u8,
};

/// The delimiter is searched for after any IPv6 literal, so the colons inside
/// `[::1]:8443` are not mistaken for it.
fn splitAuthority(authority: []const u8) Authority {
    const search_start = if (std.mem.lastIndexOfScalar(u8, authority, ']')) |bracket|
        bracket + 1
    else
        0;
    assert(search_start <= authority.len);

    const colon = std.mem.indexOfScalarPos(u8, authority, search_start, ':') orelse {
        return .{ .host = authority, .port = "" };
    };
    assert(colon < authority.len);
    return .{ .host = authority[0..colon], .port = authority[colon + 1 ..] };
}

/// The port RFC 3986 § 6.2.3 implies when one is omitted. Empty means the
/// scheme has no default, so explicit and absent ports never match.
fn defaultPort(scheme: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(scheme, "https")) {
        return "443";
    }
    if (std.ascii.eqlIgnoreCase(scheme, "http")) {
        return "80";
    }
    return "";
}

/// RFC 9113 § 8.3.1 compares the two after RFC 3986 § 6.2.3 normalization: host
/// case folded, a port equal to the scheme default treated as absent.
pub fn authorityMatchesHost(
    scheme: []const u8,
    authority: []const u8,
    host: []const u8,
) bool {
    if (!authorityIsValid(authority, false)) return false;
    if (!authorityIsValid(host, false)) return false;
    const from_pseudo = splitAuthority(authority);
    const from_header = splitAuthority(host);
    assert(from_pseudo.host.len <= authority.len);
    assert(from_header.host.len <= host.len);
    if (!std.ascii.eqlIgnoreCase(from_pseudo.host, from_header.host)) {
        return false;
    }

    const implied_port = defaultPort(scheme);
    const pseudo_port = if (from_pseudo.port.len == 0) implied_port else from_pseudo.port;
    const header_port = if (from_header.port.len == 0) implied_port else from_header.port;
    return std.mem.eql(u8, pseudo_port, header_port);
}

/// RFC 9113 § 8.3.1 forbids userinfo in ":authority" for http and https:
/// `example.com@evil.test` reads as two origins to a router and to a parser.
pub fn authorityHasUserinfo(authority: []const u8) bool {
    return std.mem.indexOfScalar(u8, authority, '@') != null;
}

fn regNameIsValid(host: []const u8) bool {
    if (host.len == 0) return false;
    var index: usize = 0;
    while (index < host.len) : (index += 1) {
        const byte = host[index];
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => continue,
            '%' => {
                if (index + 2 >= host.len) return false;
                if (!std.ascii.isHex(host[index + 1])) return false;
                if (!std.ascii.isHex(host[index + 2])) return false;
                index += 2;
            },
            else => return false,
        }
    }
    return true;
}

fn ipLiteralIsValid(host: []const u8) bool {
    if (host.len == 0) return false;
    if (host[0] != 'v' and host[0] != 'V') {
        _ = std.Io.net.IpAddress.parseIp6(host, 0) catch return false;
        return true;
    }

    var index: usize = 1;
    const version_start = index;
    while (index < host.len and std.ascii.isHex(host[index])) : (index += 1) {}
    if (index == version_start or index >= host.len or host[index] != '.') return false;
    index += 1;
    if (index >= host.len) return false;
    while (index < host.len) : (index += 1) {
        const byte = host[index];
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=', ':' => {},
            else => return false,
        }
    }
    return true;
}

fn portIsValid(port: []const u8) bool {
    if (port.len == 0) return false;
    for (port) |byte| {
        if (byte < '0' or byte > '9') return false;
    }
    return true;
}

/// RFC 3986 authority syntax used by RFC 9113 control data. Userinfo is
/// deliberately excluded from HTTP/HTTPS authority values.
pub fn authorityIsValid(authority: []const u8, port_required: bool) bool {
    if (authority.len == 0 or authorityHasUserinfo(authority)) return false;

    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return false;
        if (!ipLiteralIsValid(authority[1..close])) return false;
        if (close + 1 == authority.len) return !port_required;
        if (authority[close + 1] != ':') return false;
        return portIsValid(authority[close + 2 ..]);
    }

    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host = if (colon) |position| authority[0..position] else authority;
    if (!regNameIsValid(host)) return false;
    if (colon) |position| {
        if (std.mem.indexOfScalar(u8, host, ':') != null) return false;
        return portIsValid(authority[position + 1 ..]);
    }
    return !port_required;
}

/// RFC 9113 § 8.5 uses the authority-form request target for CONNECT. That
/// form carries a non-empty URI host and an explicit decimal port.
pub fn connectAuthorityIsValid(authority: []const u8) bool {
    return authorityIsValid(authority, true);
}

test "field names follow RFC 9110 token minus uppercase" {
    try std.testing.expect(nameIsValid("content-length"));
    try std.testing.expect(nameIsValid("x-custom_header.1"));
    try std.testing.expect(nameIsValid("a"));

    try std.testing.expect(!nameIsValid(""));
    try std.testing.expect(!nameIsValid("Content-Length"));
    try std.testing.expect(!nameIsValid("content length"));
    try std.testing.expect(!nameIsValid("content:length"));
    try std.testing.expect(!nameIsValid("content\x00length"));
    try std.testing.expect(!nameIsValid("content\rlength"));
    try std.testing.expect(!nameIsValid("content\x7flength"));
    try std.testing.expect(!nameIsValid("content\xfflength"));
    try std.testing.expect(!nameIsValid("(comment)"));
}

test "pseudo-header names carry exactly one leading colon" {
    try std.testing.expect(pseudoNameIsValid(":method"));
    try std.testing.expect(pseudoNameIsValid(":authority"));

    try std.testing.expect(!pseudoNameIsValid(":"));
    try std.testing.expect(!pseudoNameIsValid("::method"));
    try std.testing.expect(!pseudoNameIsValid(":met:hod"));
    try std.testing.expect(!pseudoNameIsValid(":Method"));
    try std.testing.expect(!pseudoNameIsValid("method"));
}

test "field values reject control bytes and surrounding whitespace" {
    try std.testing.expect(valueIsValid(""));
    try std.testing.expect(valueIsValid("text/html; charset=utf-8"));
    try std.testing.expect(valueIsValid("a b"));
    try std.testing.expect(valueIsValid("\xc3\xa9"));

    try std.testing.expect(!valueIsValid(" leading"));
    try std.testing.expect(!valueIsValid("trailing "));
    try std.testing.expect(!valueIsValid("\ttab"));
    try std.testing.expect(!valueIsValid("tab\t"));
    try std.testing.expect(!valueIsValid("has\x00nul"));
    try std.testing.expect(!valueIsValid("has\rcr"));
    try std.testing.expect(!valueIsValid("has\nlf"));
    try std.testing.expect(!valueIsValid("has\x7fdel"));
}

test "pseudo-header values reject interior whitespace" {
    try std.testing.expect(pseudoValueIsValid("/index.html"));
    try std.testing.expect(pseudoValueIsValid("GET"));

    try std.testing.expect(!pseudoValueIsValid("/a b"));
    try std.testing.expect(!pseudoValueIsValid("/a\tb"));
    try std.testing.expect(!pseudoValueIsValid("/a\rb"));
}

test "content-length accepts only 1*DIGIT" {
    try std.testing.expectEqual(@as(?u64, 0), parseContentLength("0"));
    try std.testing.expectEqual(@as(?u64, 42), parseContentLength("42"));
    try std.testing.expectEqual(@as(?u64, 10), parseContentLength("0010"));
    try std.testing.expectEqual(
        @as(?u64, std.math.maxInt(u64)),
        parseContentLength("18446744073709551615"),
    );

    try std.testing.expectEqual(@as(?u64, null), parseContentLength(""));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("+5"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("-5"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("1_0"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength(" 5"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("5 "));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("0x10"));
    try std.testing.expectEqual(@as(?u64, null), parseContentLength("18446744073709551616"));
}

test "path form is enforced for http and https only" {
    try std.testing.expect(pathIsValid("https", "GET", "/"));
    try std.testing.expect(pathIsValid("https", "GET", "/a?b=c"));
    try std.testing.expect(pathIsValid("https", "OPTIONS", "*"));
    try std.testing.expect(pathIsValid("ftp", "GET", "anything"));

    try std.testing.expect(!pathIsValid("https", "GET", ""));
    try std.testing.expect(!pathIsValid("https", "GET", "*"));
    try std.testing.expect(!pathIsValid("http", "GET", "index.html"));
    try std.testing.expect(!pathIsValid("http", "OPTIONS", "*x"));
}

test "host and authority compare after scheme-based normalization" {
    try std.testing.expect(authorityMatchesHost("https", "example.com", "example.com"));
    try std.testing.expect(authorityMatchesHost("https", "Example.COM", "example.com"));
    try std.testing.expect(authorityMatchesHost("https", "example.com:443", "example.com"));
    try std.testing.expect(authorityMatchesHost("http", "example.com", "example.com:80"));
    try std.testing.expect(authorityMatchesHost("https", "[::1]:8443", "[::1]:8443"));
    try std.testing.expect(authorityMatchesHost("https", "[::1]", "[::1]"));

    try std.testing.expect(!authorityMatchesHost("https", "example.com", "evil.test"));
    try std.testing.expect(!authorityMatchesHost("https", "example.com:8443", "example.com"));
    try std.testing.expect(!authorityMatchesHost("http", "example.com:443", "example.com"));
    try std.testing.expect(!authorityMatchesHost("https", "[::1]:8443", "[::1]:9443"));
}

test "userinfo is detected in an authority" {
    try std.testing.expect(authorityHasUserinfo("user@example.com"));
    try std.testing.expect(authorityHasUserinfo("example.com@evil.test"));

    try std.testing.expect(!authorityHasUserinfo("example.com"));
    try std.testing.expect(!authorityHasUserinfo("example.com:8443"));
}

test "CONNECT authority requires host and explicit decimal port" {
    try std.testing.expect(connectAuthorityIsValid("example.com:443"));
    try std.testing.expect(connectAuthorityIsValid("[::1]:8443"));
    try std.testing.expect(connectAuthorityIsValid("example.com:0"));

    try std.testing.expect(!connectAuthorityIsValid(""));
    try std.testing.expect(!connectAuthorityIsValid("example.com"));
    try std.testing.expect(!connectAuthorityIsValid("example.com:"));
    try std.testing.expect(!connectAuthorityIsValid(":443"));
    try std.testing.expect(!connectAuthorityIsValid("example.com:https"));
    try std.testing.expect(!connectAuthorityIsValid("::1:8443"));
    try std.testing.expect(!connectAuthorityIsValid("[]:8443"));
    try std.testing.expect(!connectAuthorityIsValid("[not-ip]:8443"));
    try std.testing.expect(!connectAuthorityIsValid("example.com/path:443"));
    try std.testing.expect(!connectAuthorityIsValid("example.com?x:443"));
    try std.testing.expect(!connectAuthorityIsValid("user@example.com:443"));
}

test "schemes outside http and https are recognized as such" {
    try std.testing.expect(schemeIsHttp("http"));
    try std.testing.expect(schemeIsHttp("HTTPS"));

    try std.testing.expect(!schemeIsHttp("ftp"));
    try std.testing.expect(!schemeIsHttp(""));
}
