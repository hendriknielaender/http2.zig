const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const http2 = b.dependency("http2", .{
        .target = target,
        .optimize = optimize,
    });

    const http2_module = http2.module("http2");

    const exe = b.addExecutable(.{
        .name = "hello_world_server",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    exe.addIncludePath(b.path("../../boringssl/include/openssl"));
    exe.addLibraryPath(b.path("../../boringssl/build"));

    exe.root_module.addImport("http2", http2_module);
    exe.linkLibrary(http2.artifact("http2"));

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the example HTTP/2 server");
    run_step.dependOn(&run_cmd.step);
}
