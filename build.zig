const std = @import("std");

const Build = std.Build;

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_include_path = b.path("boringssl/include/openssl");
    const boringssl_lib_path = b.path("boringssl/build");

    const lib = b.addStaticLibrary(.{
        .name = "http2.zig",
        .root_source_file = b.path("http2.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();

    // Link OpenSSL libraries
    lib.linkSystemLibrary("ssl");
    lib.linkSystemLibrary("crypto");

    lib.addIncludePath(boringssl_include_path);
    lib.addLibraryPath(boringssl_lib_path);

    lib.addIncludePath(b.path("boringssl/include/openssl"));

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("http2.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    lib_unit_tests.linkLibC();

    // Link OpenSSL libraries
    lib_unit_tests.linkSystemLibrary("ssl");
    lib_unit_tests.linkSystemLibrary("crypto");

    lib_unit_tests.addIncludePath(boringssl_include_path);
    lib_unit_tests.addLibraryPath(boringssl_lib_path);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
