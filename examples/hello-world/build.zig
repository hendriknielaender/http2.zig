const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const http2_module = b.addModule("http2", .{
        .root_source_file = b.path("../../src/http2.zig"),
    });

    const exe = b.addExecutable(.{
        .name = "hello_world_server",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();

    exe.root_module.addImport("http2", http2_module);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the example HTTP/2 server");
    run_step.dependOn(&run_cmd.step);
}
