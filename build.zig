//! HTTP/2 protocol implementation build configuration.
//!
//! - High-performance HTTP/2 library
//! - Example server applications
//! - Comprehensive test suite
//! - Documentation generation
//! - Benchmarking tools

const std = @import("std");

// Project metadata
const project_name = "http2";
const project_version = "0.0.3";

pub fn build(b: *std.Build) void {
    // Standard target and optimization options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const evented = b.option(
        bool,
        "evented",
        "Enable the experimental std.Io.Evented backend.",
    ) orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "use_evented_backend", evented);

    // Create module for use in other projects
    const http2_module = b.addModule("http2", .{
        .root_source_file = b.path("src/http2.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    http2_module.addOptions("build_options", build_options);

    // Core HTTP/2 library
    const http2_lib = b.addLibrary(.{
        .name = project_name,
        .root_module = http2_module,
        .linkage = .static,
        .version = std.SemanticVersion.parse(project_version) catch unreachable,
    });
    linkBoringSsl(b, http2_lib);
    b.installArtifact(http2_lib);

    // Example applications
    add_examples(b, target, optimize, http2_module, build_options);

    // Benchmark application
    add_benchmark(b, target, optimize, http2_module, build_options);

    // Test suite
    add_tests(b, target, optimize, build_options);

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
    build_options: *std.Build.Step.Options,
) void {
    // Basic TLS Example
    const basic_tls_module = b.createModule(.{
        .root_source_file = b.path("examples/basic_tls.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic_tls_module.addImport("http2", http2_module);
    basic_tls_module.addOptions("build_options", build_options);

    const basic_tls = b.addExecutable(.{
        .name = "basic_tls_server",
        .root_module = basic_tls_module,
    });
    linkBoringSsl(b, basic_tls);
    b.installArtifact(basic_tls);

    // Run step for basic TLS example
    const run_basic = b.addRunArtifact(basic_tls);
    run_basic.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run basic TLS server example");
    run_step.dependOn(&run_basic.step);

    const turboapi_core_dep = b.dependency("turboapi_core", .{
        .target = target,
        .optimize = optimize,
    });
    const turboapi_core_module = turboapi_core_dep.module("turboapi-core");

    // turboapi-core Example
    const turboapi_module = b.createModule(.{
        .root_source_file = b.path("examples/turboapi.zig"),
        .target = target,
        .optimize = optimize,
    });
    turboapi_module.addImport("http2", http2_module);
    turboapi_module.addImport("turboapi-core", turboapi_core_module);
    turboapi_module.addOptions("build_options", build_options);

    const turboapi = b.addExecutable(.{
        .name = "turboapi_server",
        .root_module = turboapi_module,
    });
    linkBoringSsl(b, turboapi);
    b.installArtifact(turboapi);

    const run_turboapi = b.addRunArtifact(turboapi);
    run_turboapi.step.dependOn(b.getInstallStep());
    const run_turboapi_step = b.step("run-turboapi", "Run turboapi-core example");
    run_turboapi_step.dependOn(&run_turboapi.step);
}

/// Add benchmark application
fn add_benchmark(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
    build_options: *std.Build.Step.Options,
) void {
    // Benchmark server
    const benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark_module.addImport("http2", http2_module);
    benchmark_module.addOptions("build_options", build_options);

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = benchmark_module,
    });
    linkBoringSsl(b, benchmark);
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
    build_options: *std.Build.Step.Options,
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
        const test_module = b.createModule(.{
            .root_source_file = b.path(module_path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
        });
        test_module.addOptions("build_options", build_options);

        const module_test = b.addTest(.{
            .root_module = test_module,
        });
        linkBoringSsl(b, module_test);

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
        .paths = &[_][]const u8{
            "build.zig",
            "src/",
            "examples/",
            "benchmarks/",
        },
        .check = true,
    });
    const fmt_check_step = b.step("fmt-check", "Check code formatting");
    fmt_check_step.dependOn(&fmt_check.step);

    // Format fix
    const fmt_fix = b.addFmt(.{
        .paths = &[_][]const u8{
            "build.zig",
            "src/",
            "examples/",
            "benchmarks/",
        },
        .check = false,
    });
    const fmt_fix_step = b.step("fmt", "Fix code formatting");
    fmt_fix_step.dependOn(&fmt_fix.step);
}

fn linkBoringSsl(b: *std.Build, artifact: *std.Build.Step.Compile) void {
    artifact.root_module.link_libc = true;
    artifact.root_module.link_libcpp = true;
    artifact.root_module.addIncludePath(b.path("boringssl/include"));
    artifact.root_module.addLibraryPath(b.path("boringssl/build"));
    artifact.root_module.addObjectFile(b.path("boringssl/build/ssl/libssl.a"));
    artifact.root_module.addObjectFile(b.path("boringssl/build/crypto/libcrypto.a"));
}
