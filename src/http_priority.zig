const std = @import("std");
const assert = std.debug.assert;

pub const urgency_default: u8 = 3;
pub const urgency_highest: u8 = 0;
pub const urgency_lowest: u8 = 7;

pub const Priority = struct {
    urgency: u8 = urgency_default,
    incremental: bool = false,

    pub fn parse(field_value: []const u8) !Priority {
        const trimmed = trim_ascii_whitespace(field_value);
        if (trimmed.len == 0) {
            return error.InvalidPriorityFieldValue;
        }

        var priority = Priority{};
        var saw_incremental = false;
        var saw_urgency = false;
        var member_iter = std.mem.splitScalar(u8, trimmed, ',');

        while (member_iter.next()) |member_raw| {
            const member = trim_ascii_whitespace(member_raw);
            if (member.len == 0) {
                return error.InvalidPriorityFieldValue;
            }

            try parse_member(
                member,
                &priority,
                &saw_incremental,
                &saw_urgency,
            );
        }

        return priority;
    }

    pub fn write(self: Priority, buffer: []u8) ![]const u8 {
        assert(self.urgency >= urgency_highest);
        assert(self.urgency <= urgency_lowest);

        if (self.incremental) {
            return std.fmt.bufPrint(buffer, "u={d}, i", .{self.urgency});
        }

        return std.fmt.bufPrint(buffer, "u={d}", .{self.urgency});
    }

    fn parse_member(
        member: []const u8,
        priority: *Priority,
        saw_incremental: *bool,
        saw_urgency: *bool,
    ) !void {
        const equal_index = std.mem.indexOfScalar(u8, member, '=') orelse {
            return parse_boolean_member(
                member,
                priority,
                saw_incremental,
                saw_urgency,
            );
        };

        const key = trim_ascii_whitespace(member[0..equal_index]);
        const value = trim_ascii_whitespace(member[equal_index + 1 ..]);
        if (key.len == 0) {
            return error.InvalidPriorityFieldValue;
        }
        if (value.len == 0) {
            return error.InvalidPriorityFieldValue;
        }

        if (std.mem.eql(u8, key, "u")) {
            if (saw_urgency.*) {
                return error.InvalidPriorityFieldValue;
            }
            saw_urgency.* = true;

            const urgency = parse_urgency(value) orelse return;
            priority.urgency = urgency;
            return;
        }

        if (std.mem.eql(u8, key, "i")) {
            if (saw_incremental.*) {
                return error.InvalidPriorityFieldValue;
            }
            saw_incremental.* = true;

            const incremental = parse_incremental(value) orelse return;
            priority.incremental = incremental;
            return;
        }
    }

    fn parse_boolean_member(
        member: []const u8,
        priority: *Priority,
        saw_incremental: *bool,
        saw_urgency: *bool,
    ) !void {
        const key = trim_ascii_whitespace(member);
        if (key.len == 0) {
            return error.InvalidPriorityFieldValue;
        }

        if (std.mem.eql(u8, key, "i")) {
            if (saw_incremental.*) {
                return error.InvalidPriorityFieldValue;
            }
            saw_incremental.* = true;
            priority.incremental = true;
            return;
        }

        if (std.mem.eql(u8, key, "u")) {
            if (saw_urgency.*) {
                return error.InvalidPriorityFieldValue;
            }
            saw_urgency.* = true;
            return;
        }
    }

    fn parse_urgency(value: []const u8) ?u8 {
        const parsed = std.fmt.parseInt(i32, value, 10) catch return null;
        if (parsed < urgency_highest) {
            return null;
        }
        if (parsed > urgency_lowest) {
            return null;
        }

        return @intCast(parsed);
    }

    fn parse_incremental(value: []const u8) ?bool {
        if (std.mem.eql(u8, value, "?0")) {
            return false;
        }
        if (std.mem.eql(u8, value, "?1")) {
            return true;
        }

        return null;
    }
};

fn trim_ascii_whitespace(input: []const u8) []const u8 {
    return std.mem.trim(u8, input, " \t");
}

test "Priority parser handles urgency and incremental values" {
    const priority = try Priority.parse("u=5, i");

    try std.testing.expectEqual(@as(u8, 5), priority.urgency);
    try std.testing.expect(priority.incremental);
}

test "Priority parser ignores unknown and out-of-range members" {
    const priority = try Priority.parse("vendor=3, u=9, i=?0");

    try std.testing.expectEqual(@as(u8, urgency_default), priority.urgency);
    try std.testing.expect(!priority.incremental);
}

test "Priority parser rejects duplicate known members" {
    try std.testing.expectError(
        error.InvalidPriorityFieldValue,
        Priority.parse("u=1, u=2"),
    );
}

test "Priority formatter emits structured field values" {
    var buffer: [16]u8 = undefined;
    const priority = Priority{
        .urgency = 1,
        .incremental = true,
    };
    const field_value = try priority.write(&buffer);

    try std.testing.expectEqualStrings("u=1, i", field_value);
}
