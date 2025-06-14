//! HTTP/2 Protocol Implementation Build Configuration
//!
//! - Library build for embedding in other projects
//! - Example server and client applications
//! - Comprehensive test suite
//! - Documentation generation
//! - Benchmarking tools

const std = @import("std");

// Project metadata
const project_name = "http2";
const project_version = "0.1.0";
const minimum_zig_version = "0.14.0";

pub fn build(b: *std.Build) void {
    // Standard target and optimization options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_include_path = b.path("boringssl/include");
    const boringssl_lib_path = b.path("boringssl/build");

    // Add libxev dependency
    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    // Core HTTP/2 library
    const http2_lib = b.addStaticLibrary(.{
        .name = project_name,
        .root_source_file = b.path("src/http2.zig"),
        .target = target,
        .optimize = optimize,
        .version = std.SemanticVersion.parse(project_version) catch unreachable,
    });
    http2_lib.linkLibC();
    http2_lib.linkLibCpp();
    http2_lib.addIncludePath(boringssl_include_path);
    http2_lib.addLibraryPath(boringssl_lib_path);
    http2_lib.addObjectFile(b.path("boringssl/build/ssl/libssl.a"));
    http2_lib.addObjectFile(b.path("boringssl/build/crypto/libcrypto.a"));

    // Configure library
    b.installArtifact(http2_lib);

    // Create module for use in other projects
    const http2_module = b.addModule("http2", .{
        .root_source_file = b.path("src/http2.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Add libxev to the http2 module
    http2_module.addImport("xev", libxev.module("xev"));

    // Example applications
    add_example_applications(b, target, optimize, http2_module);

    // Test suite
    add_test_suite(b, target, optimize);

    // Documentation
    add_documentation(b, http2_lib);

    // Benchmarks
    add_benchmarks(b, target, optimize, http2_module);

    // Linting and formatting
    add_code_quality_checks(b);
}

/// Add example applications demonstrating HTTP/2 usage
fn add_example_applications(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
) void {
    // Hello World Example (main example)
    const hello_world_example = b.addExecutable(.{
        .name = "hello_world_server",
        .root_source_file = b.path("examples/hello-world/src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    hello_world_example.root_module.addImport("http2", http2_module);
    hello_world_example.linkLibC();
    hello_world_example.linkLibCpp();
    hello_world_example.addIncludePath(b.path("boringssl/include"));
    hello_world_example.addLibraryPath(b.path("boringssl/build"));
    hello_world_example.addObjectFile(b.path("boringssl/build/ssl/libssl.a"));
    hello_world_example.addObjectFile(b.path("boringssl/build/crypto/libcrypto.a"));
    b.installArtifact(hello_world_example);

    // Run step for hello world example
    const run_hello_world = b.addRunArtifact(hello_world_example);
    run_hello_world.step.dependOn(b.getInstallStep());
    const run_hello_world_step = b.step("run", "Run hello world server (default)");
    run_hello_world_step.dependOn(&run_hello_world.step);
}

/// Add comprehensive test suite
fn add_test_suite(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    // Add libxev dependency for tests
    const libxev = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });

    // Unit tests for all modules
    const test_modules = [_][]const u8{
        "src/frame.zig",
        "src/stream.zig", 
        "src/budget_assertions.zig",
        "src/connection.zig",
        "src/hpack.zig",
        "src/huffman.zig",
        "src/worker_pool.zig",
        "src/http2.zig",
        "src/memory_budget.zig",
    };

    var all_tests_step = b.step("test", "Run all unit tests");

    for (test_modules) |module_path| {
        const module_test = b.addTest(.{
            .root_source_file = b.path(module_path),
            .target = target,
            .optimize = optimize,
        });
        
        // Add libxev dependency to tests that need it
        module_test.root_module.addImport("xev", libxev.module("xev"));

        const run_test = b.addRunArtifact(module_test);
        all_tests_step.dependOn(&run_test.step);
    }

    // H2spec conformance tests (external tool)
    const h2spec_test_step = b.step("test-h2spec", "Run h2spec conformance tests");
    const h2spec_cmd = b.addSystemCommand(&[_][]const u8{ "h2spec", "http2", "-h", "127.0.0.1", "-p", "9001", "-S" });
    h2spec_test_step.dependOn(&h2spec_cmd.step);
}

/// Add documentation generation
fn add_documentation(b: *std.Build, http2_lib: *std.Build.Step.Compile) void {
    const docs = b.addInstallDirectory(.{
        .source_dir = http2_lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });

    const docs_step = b.step("docs", "Generate documentation");
    docs_step.dependOn(&docs.step);
}

/// Add benchmark suite
fn add_benchmarks(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
) void {
    // Skip benchmarks if files don't exist yet
    _ = b;
    _ = target;
    _ = optimize;
    _ = http2_module;

    // TODO: Implement when benchmark structure is ready
    // const benchmark_exe = b.addExecutable(.{
    //     .name = "http2_benchmark",
    //     .root_source_file = b.path("benchmarks/benchmark.zig"),
    //     .target = target,
    //     .optimize = .ReleaseFast,
    // });
    // benchmark_exe.root_module.addImport("http2", http2_module);

    // const run_benchmark = b.addRunArtifact(benchmark_exe);
    // const benchmark_step = b.step("benchmark", "Run performance benchmarks");
    // benchmark_step.dependOn(&run_benchmark.step);
}

/// Add code quality and formatting checks
fn add_code_quality_checks(b: *std.Build) void {
    // Format check
    const fmt_check = b.addFmt(.{
        .paths = &[_][]const u8{ "src/", "examples/", "scripts/" },
        .check = true,
    });
    const fmt_check_step = b.step("fmt-check", "Check code formatting");
    fmt_check_step.dependOn(&fmt_check.step);

    // Format fix
    const fmt_fix = b.addFmt(.{
        .paths = &[_][]const u8{ "src/", "examples/", "scripts/" },
        .check = false,
    });
    const fmt_fix_step = b.step("fmt", "Fix code formatting");
    fmt_fix_step.dependOn(&fmt_fix.step);
}
