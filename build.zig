//! HTTP/2 Protocol Implementation Build Configuration
//!
//! - High-performance HTTP/2 library with libxev
//! - Example server applications  
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
    add_examples(b, target, optimize, http2_module);

    // Benchmark application
    add_benchmark(b, target, optimize, http2_module);

    // Test suite
    add_tests(b, target, optimize, libxev);

    // Documentation
    add_documentation(b, http2_lib);

    // Code quality checks
    add_code_quality_checks(b);
}

/// Add example applications
fn add_examples(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
) void {
    // Basic TLS Example
    const basic_tls = b.addExecutable(.{
        .name = "basic_tls_server",
        .root_source_file = b.path("examples/basic_tls.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic_tls.root_module.addImport("http2", http2_module);
    basic_tls.linkLibC();
    basic_tls.linkLibCpp();
    basic_tls.addIncludePath(b.path("boringssl/include"));
    basic_tls.addLibraryPath(b.path("boringssl/build"));
    basic_tls.addObjectFile(b.path("boringssl/build/ssl/libssl.a"));
    basic_tls.addObjectFile(b.path("boringssl/build/crypto/libcrypto.a"));
    b.installArtifact(basic_tls);

    // Run step for basic TLS example
    const run_basic = b.addRunArtifact(basic_tls);
    run_basic.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run basic TLS server example");
    run_step.dependOn(&run_basic.step);
}

/// Add benchmark application
fn add_benchmark(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
) void {
    // Benchmark server
    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_source_file = b.path("benchmarks/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark.root_module.addImport("http2", http2_module);
    benchmark.linkLibC();
    benchmark.linkLibCpp();
    benchmark.addIncludePath(b.path("boringssl/include"));
    benchmark.addLibraryPath(b.path("boringssl/build"));
    benchmark.addObjectFile(b.path("boringssl/build/ssl/libssl.a"));
    benchmark.addObjectFile(b.path("boringssl/build/crypto/libcrypto.a"));
    b.installArtifact(benchmark);

    // Run step for benchmark
    const run_benchmark = b.addRunArtifact(benchmark);
    run_benchmark.step.dependOn(b.getInstallStep());
    const benchmark_step = b.step("benchmark", "Run HTTP/2 benchmark server");
    benchmark_step.dependOn(&run_benchmark.step);
}

/// Add comprehensive test suite
fn add_tests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    libxev: *std.Build.Dependency,
) void {
    // Unit tests for core modules
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
        "src/server.zig",
    };

    var all_tests_step = b.step("test", "Run all unit tests");

    for (test_modules) |module_path| {
        const module_test = b.addTest(.{
            .root_source_file = b.path(module_path),
            .target = target,
            .optimize = optimize,
        });
        
        // Add libxev dependency to tests
        module_test.root_module.addImport("xev", libxev.module("xev"));

        const run_test = b.addRunArtifact(module_test);
        all_tests_step.dependOn(&run_test.step);
    }
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

/// Add code quality and formatting checks
fn add_code_quality_checks(b: *std.Build) void {
    // Format check
    const fmt_check = b.addFmt(.{
        .paths = &[_][]const u8{ "src/", "examples/", "benchmarks/" },
        .check = true,
    });
    const fmt_check_step = b.step("fmt-check", "Check code formatting");
    fmt_check_step.dependOn(&fmt_check.step);

    // Format fix
    const fmt_fix = b.addFmt(.{
        .paths = &[_][]const u8{ "src/", "examples/", "benchmarks/" },
        .check = false,
    });
    const fmt_fix_step = b.step("fmt", "Fix code formatting");
    fmt_fix_step.dependOn(&fmt_fix.step);
}