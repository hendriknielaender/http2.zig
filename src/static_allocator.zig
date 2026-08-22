//! Allocator phase guard for startup-only allocation.
//!
//! The backing allocator is available while the process builds its fixed
//! resource pools. The guard is then sealed before runtime work begins. A
//! separate teardown phase permits frees, but never permits allocation again.
//!
//! Retained from the project's TigerBeetle-derived allocator and adapted with
//! release-safe phase checks and exact live/reserved-byte accounting.

const std = @import("std");
const mem = std.mem;
const Alignment = mem.Alignment;

const StaticAllocator = @This();

parent_allocator: mem.Allocator,
state: State,
allocations_live: usize,
bytes_live: usize,
bytes_reserved: usize,

pub const State = enum {
    init,
    static,
    deinit,
};

pub fn init(parent_allocator: mem.Allocator) StaticAllocator {
    return .{
        .parent_allocator = parent_allocator,
        .state = .init,
        .allocations_live = 0,
        .bytes_live = 0,
        .bytes_reserved = 0,
    };
}

pub fn deinit(self: *StaticAllocator) void {
    requireState(self, .deinit, "deinit before teardown phase");
    if (self.allocations_live != 0) @panic("static allocator leaked allocations");
    if (self.bytes_live != 0) @panic("static allocator leaked bytes");
    self.* = undefined;
}

pub fn transition_from_init_to_static(self: *StaticAllocator) void {
    requireState(self, .init, "static allocator sealed outside init phase");
    self.bytes_reserved = self.bytes_live;
    self.state = .static;
}

pub fn transition_from_init_to_deinit(self: *StaticAllocator) void {
    requireState(self, .init, "static allocator teardown outside init phase");
    self.state = .deinit;
}

pub fn transition_from_static_to_deinit(self: *StaticAllocator) void {
    requireState(self, .static, "static allocator teardown outside runtime phase");
    self.state = .deinit;
}

pub fn allocator(self: *StaticAllocator) mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        },
    };
}

fn alloc(ctx: *anyopaque, len: usize, ptr_align: Alignment, ret_addr: usize) ?[*]u8 {
    const self: *StaticAllocator = @ptrCast(@alignCast(ctx));
    requireState(self, .init, "allocation attempted after startup");

    const result = self.parent_allocator.rawAlloc(len, ptr_align, ret_addr);
    if (result != null) allocationAdded(self, len);
    return result;
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    const self: *StaticAllocator = @ptrCast(@alignCast(ctx));
    requireState(self, .init, "resize attempted after startup");

    const resized = self.parent_allocator.rawResize(buf, buf_align, new_len, ret_addr);
    if (resized) {
        if (new_len == 0) {
            self.state = .deinit;
            allocationRemoved(self, buf.len);
        } else {
            allocationResized(self, buf.len, new_len);
        }
    }
    return resized;
}

fn remap(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: Alignment,
    new_len: usize,
    ret_addr: usize,
) ?[*]u8 {
    const self: *StaticAllocator = @ptrCast(@alignCast(ctx));
    requireState(self, .init, "remap attempted after startup");

    const result = self.parent_allocator.rawRemap(buf, buf_align, new_len, ret_addr);
    if (result != null) {
        if (new_len == 0) {
            self.state = .deinit;
            allocationRemoved(self, buf.len);
        } else {
            allocationResized(self, buf.len, new_len);
        }
    }
    return result;
}

fn free(ctx: *anyopaque, buf: []u8, buf_align: Alignment, ret_addr: usize) void {
    const self: *StaticAllocator = @ptrCast(@alignCast(ctx));
    if (self.state == .static) @panic("free attempted before teardown");
    if (self.state == .init) self.state = .deinit;
    requireState(self, .deinit, "free attempted outside teardown phase");

    allocationRemoved(self, buf.len);
    self.parent_allocator.rawFree(buf, buf_align, ret_addr);
}

fn allocationAdded(self: *StaticAllocator, len: usize) void {
    requireState(self, .init, "allocation accounting outside startup");
    if (self.allocations_live == std.math.maxInt(usize)) {
        @panic("static allocator allocation count overflow");
    }
    self.allocations_live += 1;
    self.bytes_live = std.math.add(usize, self.bytes_live, len) catch {
        @panic("static allocator byte count overflow");
    };
}

fn allocationResized(self: *StaticAllocator, old_len: usize, new_len: usize) void {
    requireState(self, .init, "resize accounting outside startup");
    if (self.bytes_live < old_len) @panic("static allocator byte count underflow");
    self.bytes_live -= old_len;
    self.bytes_live = std.math.add(usize, self.bytes_live, new_len) catch {
        @panic("static allocator byte count overflow");
    };
}

fn allocationRemoved(self: *StaticAllocator, len: usize) void {
    requireState(self, .deinit, "free accounting outside teardown");
    if (self.allocations_live == 0) @panic("static allocator allocation count underflow");
    if (self.bytes_live < len) @panic("static allocator byte count underflow");
    self.allocations_live -= 1;
    self.bytes_live -= len;
}

fn requireState(self: *const StaticAllocator, expected: State, message: []const u8) void {
    if (self.state != expected) @panic(message);
}

test "allocator records a fixed startup reservation" {
    var static_allocator = StaticAllocator.init(std.testing.allocator);
    const allocator_instance = static_allocator.allocator();
    const allocation = try allocator_instance.alloc(u8, 64);

    try std.testing.expectEqual(@as(usize, 1), static_allocator.allocations_live);
    try std.testing.expectEqual(@as(usize, 64), static_allocator.bytes_live);

    static_allocator.transition_from_init_to_static();
    try std.testing.expectEqual(@as(usize, 64), static_allocator.bytes_reserved);

    static_allocator.transition_from_static_to_deinit();
    allocator_instance.free(allocation);
    static_allocator.deinit();
}
