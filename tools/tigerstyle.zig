//! Enforce the small, mechanical subset of TigerStyle used by this project.

const std = @import("std");

const max_columns: usize = 100;
const max_function_lines: usize = 70;
const max_source_bytes: usize = 2 * 1024 * 1024;

const SourceRange = struct {
    start: usize,
    end: usize,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        usage();
    }

    var violations: usize = 0;
    var argument_index: usize = 1;
    while (argument_index < args.len) {
        if (std.mem.eql(u8, args[argument_index], "--region")) {
            if (argument_index + 3 >= args.len) usage();
            violations += try checkSourceRegion(
                init.io,
                init.gpa,
                args[argument_index + 1],
                args[argument_index + 2],
                args[argument_index + 3],
            );
            argument_index += 4;
        } else {
            violations += try checkSource(init.io, init.gpa, args[argument_index]);
            argument_index += 1;
        }
    }

    if (violations != 0) {
        std.debug.print("tigerstyle: {d} violation(s)\n", .{violations});
        std.process.exit(1);
    }
}

fn usage() noreturn {
    std.debug.print(
        "usage: tigerstyle <zig-source>... " ++
            "[--region <zig-source> <start-marker> <end-marker>]...\n",
        .{},
    );
    std.process.exit(2);
}

fn checkSource(io: std.Io, gpa: std.mem.Allocator, path: []const u8) !usize {
    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_source_bytes),
        .of(u8),
        0,
    );
    defer gpa.free(source);

    var tree = try std.zig.Ast.parse(gpa, source, .zig);
    defer tree.deinit(gpa);

    var violations = checkColumns(path, source, .{ .start = 0, .end = source.len });
    violations += checkParseErrors(path, &tree);
    if (tree.errors.len == 0) {
        violations += checkFunctionLengths(path, &tree, .{ .start = 0, .end = source.len });
    }
    return violations;
}

fn checkSourceRegion(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    start_marker: []const u8,
    end_marker: []const u8,
) !usize {
    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_source_bytes),
        .of(u8),
        0,
    );
    defer gpa.free(source);

    const range = findSourceRange(path, source, start_marker, end_marker) orelse return 1;

    var tree = try std.zig.Ast.parse(gpa, source, .zig);
    defer tree.deinit(gpa);

    var violations = checkColumns(path, source, range);
    violations += checkParseErrors(path, &tree);
    if (tree.errors.len == 0) {
        violations += checkFunctionLengths(path, &tree, range);
    }
    return violations;
}

fn findSourceRange(
    path: []const u8,
    source: []const u8,
    start_marker: []const u8,
    end_marker: []const u8,
) ?SourceRange {
    const start = std.mem.indexOf(u8, source, start_marker) orelse {
        std.debug.print("{s}: TigerStyle region start marker not found: {s}\n", .{
            path,
            start_marker,
        });
        return null;
    };
    const after_start = start + start_marker.len;
    if (std.mem.indexOf(u8, source[after_start..], start_marker) != null) {
        std.debug.print("{s}: TigerStyle region start marker is not unique: {s}\n", .{
            path,
            start_marker,
        });
        return null;
    }

    const end_relative = std.mem.indexOf(u8, source[after_start..], end_marker) orelse {
        std.debug.print("{s}: TigerStyle region end marker not found: {s}\n", .{
            path,
            end_marker,
        });
        return null;
    };
    const end = after_start + end_relative;
    const after_end = end + end_marker.len;
    if (std.mem.indexOf(u8, source[after_end..], end_marker) != null) {
        std.debug.print("{s}: TigerStyle region end marker is not unique: {s}\n", .{
            path,
            end_marker,
        });
        return null;
    }

    return .{ .start = start, .end = end };
}

fn checkColumns(path: []const u8, source: []const u8, range: SourceRange) usize {
    var violations: usize = 0;
    var lines = std.mem.splitScalar(u8, source, '\n');
    var line_number: usize = 1;
    var line_start: usize = 0;
    while (lines.next()) |line| : (line_number += 1) {
        const line_end = line_start + line.len;
        defer line_start = line_end + 1;
        if (line_end < range.start or line_start >= range.end) continue;

        const columns = if (std.mem.endsWith(u8, line, "\r")) line.len - 1 else line.len;
        if (columns <= max_columns) continue;
        std.debug.print("{s}:{d}: line is {d} columns (max {d})\n", .{
            path,
            line_number,
            columns,
            max_columns,
        });
        violations += 1;
    }
    return violations;
}

fn checkParseErrors(path: []const u8, tree: *const std.zig.Ast) usize {
    if (tree.errors.len == 0) return 0;
    for (tree.errors) |parse_error| {
        const location = tree.tokenLocation(0, parse_error.token);
        std.debug.print("{s}:{d}: source does not parse\n", .{ path, location.line + 1 });
    }
    return tree.errors.len;
}

fn checkFunctionLengths(
    path: []const u8,
    tree: *const std.zig.Ast,
    range: SourceRange,
) usize {
    var violations: usize = 0;
    var node_index: usize = 1;
    while (node_index < tree.nodes.len) : (node_index += 1) {
        const node: std.zig.Ast.Node.Index = @enumFromInt(node_index);
        if (tree.nodeTag(node) != .fn_decl) continue;

        const function_lines = functionLineCount(tree, node);
        const first_token = tree.firstToken(node);
        const function_start = tree.tokenStart(first_token);
        if (function_start < range.start or function_start >= range.end) continue;
        if (function_lines <= max_function_lines) continue;

        const location = tree.tokenLocation(0, first_token);
        std.debug.print("{s}:{d}: function is {d} lines (max {d})\n", .{
            path,
            location.line + 1,
            function_lines,
            max_function_lines,
        });
        violations += 1;
    }
    return violations;
}

fn functionLineCount(tree: *const std.zig.Ast, node: std.zig.Ast.Node.Index) usize {
    const first_token = tree.firstToken(node);
    const body_node = tree.nodeData(node).node_and_node[1];
    const last_token = tree.lastToken(body_node);
    const first = tree.tokenLocation(0, first_token);
    const last = tree.tokenLocation(0, last_token);
    return last.line - first.line + 1;
}
