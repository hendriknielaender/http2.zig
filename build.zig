const std = @import("std");

const Build = std.Build;

const version = std.SemanticVersion{ .major = 0, .minor = 0, .patch = 1 };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Setup library
    _ = setupLibrary(b, target, optimize);

    // Setup exe
    setupExe(b, target, optimize);

    // Setup testing
    setupTesting(b, target, optimize);
}

fn setupLibrary(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const boringssl_include_path = b.path("boringssl/include/openssl");
    const boringssl_lib_path = b.path("boringssl/build");

    const lib = b.addStaticLibrary(.{
        .name = "http2",
        .root_source_file = b.path("http2/connection.zig"),
        .target = target,
        .optimize = optimize,
        .version = version,
    });

    lib.linkLibC();

    // Link OpenSSL libraries
    lib.linkSystemLibrary("ssl");
    lib.linkSystemLibrary("crypto");

    lib.addIncludePath(boringssl_include_path);
    lib.addLibraryPath(boringssl_lib_path);

    lib.addIncludePath(b.path("boringssl/include/openssl"));

    b.installArtifact(lib);

    return lib;
}

fn setupExe(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const exe_step = b.step("http2", "Build exe for http2 lib");

    const exe = b.addExecutable(.{
        .name = "http2",
        .root_source_file = b.path("http2.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();

    // Link OpenSSL libraries
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");

    const boringssl_include_path = b.path("boringssl/include/openssl");
    const boringssl_lib_path = b.path("boringssl/build");

    exe.addIncludePath(boringssl_include_path);
    exe.addLibraryPath(boringssl_lib_path);

    exe.addIncludePath(b.path("boringssl/include/openssl"));

    b.installArtifact(exe);
    exe_step.dependOn(&exe.step);
}

fn setupTesting(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const test_files = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "hpack", .path = "http2/hpack.zig" },
        .{ .name = "huffman", .path = "http2/huffman.zig" },
        .{ .name = "frame", .path = "http2/frame.zig" },
        .{ .name = "stream", .path = "http2/stream.zig" },
        .{ .name = "connection", .path = "http2/connection.zig" },
    };

    const test_step = b.step("test", "Run library tests");
    for (test_files) |test_file| {
        const _test = b.addTest(.{
            .name = test_file.name,
            .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = test_file.path } },
            .target = target,
            .optimize = optimize,
        });
        const run_test = b.addRunArtifact(_test);
        test_step.dependOn(&run_test.step);
    }
}
