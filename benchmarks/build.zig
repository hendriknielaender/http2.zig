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

    // Async benchmark server
    const async_server_exe = b.addExecutable(.{
        .name = "async-server",
        .root_source_file = b.path("async_server.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Original benchmark server using library
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

    async_server_exe.root_module.addImport("http2", http2.module("http2"));
    async_server_exe.root_module.addImport("xev", libxev.module("xev"));
    b.installArtifact(async_server_exe);

    basic_server_exe.root_module.addImport("http2", http2.module("http2"));
    basic_server_exe.root_module.addImport("xev", libxev.module("xev"));
    b.installArtifact(basic_server_exe);

    server_exe.root_module.addImport("http2", http2.module("http2"));
    server_exe.root_module.addImport("xev", libxev.module("xev"));
    b.installArtifact(server_exe);

    // Run step for async server
    const run_async_server = b.addRunArtifact(async_server_exe);
    run_async_server.step.dependOn(b.getInstallStep());

    const run_async_step = b.step("run", "Run the async benchmark server");
    run_async_step.dependOn(&run_async_server.step);
    
    // Alternative run step for original server
    const run_server = b.addRunArtifact(server_exe);
    run_server.step.dependOn(b.getInstallStep());

    const run_orig_step = b.step("run-orig", "Run the original benchmark server");
    run_orig_step.dependOn(&run_server.step);
}

