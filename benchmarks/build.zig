const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Add dependencies
    const http2 = b.dependency("http2", .{
        .target = target,
        .optimize = optimize,
    });

    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    // benchmark server using library
    const server_exe = b.addExecutable(.{
        .name = "benchmark-server",
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Basic server executable (fallback)
    const basic_server_exe = b.addExecutable(.{
        .name = "basic-server",
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize,
    });

    basic_server_exe.root_module.addImport("http2", http2.module("http2"));
    basic_server_exe.root_module.addImport("xev", libxev.module("xev"));
    b.installArtifact(basic_server_exe);

    server_exe.root_module.addImport("http2", http2.module("http2"));
    server_exe.root_module.addImport("xev", libxev.module("xev"));
    b.installArtifact(server_exe);

    // Run step
    const run_server = b.addRunArtifact(server_exe);
    run_server.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the benchmark server");
    run_step.dependOn(&run_server.step);
}

