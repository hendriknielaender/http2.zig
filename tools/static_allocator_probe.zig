const std = @import("std");
const StaticAllocator = @import("static-allocator");

const Operation = enum {
    alloc,
    free,
    resize,
    remap,
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) {
        std.debug.print("usage: static-allocator-release-probe <operation>\n", .{});
        std.process.exit(2);
    }
    const operation = std.meta.stringToEnum(Operation, args[1]) orelse {
        std.debug.print("unknown static allocator operation: {s}\n", .{args[1]});
        std.process.exit(2);
    };

    var static_allocator = StaticAllocator.init(std.heap.page_allocator);
    const allocator = static_allocator.allocator();
    const startup_memory = try allocator.alloc(u8, 64);
    std.mem.doNotOptimizeAway(startup_memory);

    static_allocator.transition_from_init_to_static();

    // Every operation must abort even in ReleaseFast. The build checks SIGABRT
    // and the operation-specific phase-guard message for each invocation.
    switch (operation) {
        .alloc => _ = try allocator.alloc(u8, 1),
        .free => allocator.free(startup_memory),
        .resize => _ = allocator.resize(startup_memory, 32),
        .remap => _ = allocator.remap(startup_memory, 32),
    }
}
