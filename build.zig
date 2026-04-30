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
const project_version = "0.0.6";

pub fn build(b: *std.Build) void {
    // Standard target and optimization options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const http2_boring_root = b.option(
        []const u8,
        "http2-boring-root",
        "Optional path to a local http2-boring adapter checkout.",
    );
    const boringssl_source_path = b.option(
        []const u8,
        "boringssl-source-path",
        "Path to a BoringSSL source checkout for the boring package.",
    ) orelse "boringssl";
    const boringssl_lib_path = b.option(
        []const u8,
        "boringssl-lib-path",
        "Path to a BoringSSL CMake build root for the boring package.",
    );

    const boring_dependency = if (boringssl_lib_path) |lib_path|
        b.dependency("boring", .{
            .target = target,
            .optimize = optimize,
            .@"boringssl-source-path" = boringssl_source_path,
            .@"boringssl-lib-path" = lib_path,
        })
    else
        b.dependency("boring", .{
            .target = target,
            .optimize = optimize,
            .@"boringssl-source-path" = boringssl_source_path,
        });
    const boring_module = boring_dependency.module("boring");
    const http2_boring_source: std.Build.LazyPath = if (http2_boring_root) |root|
        .{ .cwd_relative = b.pathJoin(&.{ root, "src/http2_boring.zig" }) }
    else
        boring_dependency.path("http2-boring/src/http2_boring.zig");

    // Create module for use in other projects
    const http2_module = b.addModule("http2", .{
        .root_source_file = b.path("src/http2.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const http2_boring_module = add_http2_boring_module(
        b,
        target,
        optimize,
        http2_module,
        boring_module,
        http2_boring_source,
    );
    const tls_server_module = add_tls_server_module(
        b,
        target,
        optimize,
        http2_module,
        http2_boring_module,
        boring_module,
    );

    // Core HTTP/2 library
    const http2_lib = b.addLibrary(.{
        .name = project_name,
        .root_module = http2_module,
        .linkage = .static,
        .version = std.SemanticVersion.parse(project_version) catch unreachable,
    });
    b.installArtifact(http2_lib);

    // Example applications
    add_examples(
        b,
        target,
        optimize,
        http2_module,
        http2_boring_module,
        boring_module,
        tls_server_module,
    );

    // Benchmark application
    add_benchmark(
        b,
        target,
        optimize,
        http2_boring_root,
        boringssl_source_path,
        boringssl_lib_path,
    );

    // Test suite
    add_tests(b, target, optimize);

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
    http2_boring_module: *std.Build.Module,
    boring_module: *std.Build.Module,
    tls_server_module: *std.Build.Module,
) void {
    // Basic TLS Example
    const basic_tls_module = b.createModule(.{
        .root_source_file = b.path("examples/basic_tls.zig"),
        .target = target,
        .optimize = optimize,
    });
    basic_tls_module.addImport("http2", http2_module);
    basic_tls_module.addImport("http2-boring", http2_boring_module);
    basic_tls_module.addImport("boring", boring_module);
    basic_tls_module.addImport("tls-server", tls_server_module);

    const basic_tls = b.addExecutable(.{
        .name = "basic_tls_server",
        .root_module = basic_tls_module,
    });
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
    turboapi_module.addImport("http2-boring", http2_boring_module);
    turboapi_module.addImport("boring", boring_module);
    turboapi_module.addImport("tls-server", tls_server_module);
    turboapi_module.addImport("turboapi-core", turboapi_core_module);

    const turboapi = b.addExecutable(.{
        .name = "turboapi_server",
        .root_module = turboapi_module,
    });
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
    http2_boring_root: ?[]const u8,
    boringssl_source_path: []const u8,
    boringssl_lib_path: ?[]const u8,
) void {
    // Benchmarks must be optimized by default. Actix is always built with
    // `cargo build --release`, so a default `zig build httparena-vs-actix`
    // must not silently compare Debug Zig against Release Rust.
    const benchmark_optimize: std.builtin.OptimizeMode = switch (optimize) {
        .Debug => .ReleaseFast,
        else => optimize,
    };

    const benchmark_boring_dependency = if (boringssl_lib_path) |lib_path|
        b.dependency("boring", .{
            .target = target,
            .optimize = benchmark_optimize,
            .@"boringssl-source-path" = boringssl_source_path,
            .@"boringssl-lib-path" = lib_path,
        })
    else
        b.dependency("boring", .{
            .target = target,
            .optimize = benchmark_optimize,
            .@"boringssl-source-path" = boringssl_source_path,
        });
    const benchmark_boring_module = benchmark_boring_dependency.module("boring");
    const benchmark_http2_module = b.createModule(.{
        .root_source_file = b.path("src/http2.zig"),
        .target = target,
        .optimize = benchmark_optimize,
        .link_libc = true,
    });
    const benchmark_http2_boring_source: std.Build.LazyPath = if (http2_boring_root) |root|
        .{ .cwd_relative = b.pathJoin(&.{ root, "src/http2_boring.zig" }) }
    else
        benchmark_boring_dependency.path("http2-boring/src/http2_boring.zig");
    const benchmark_http2_boring_module = add_http2_boring_module(
        b,
        target,
        benchmark_optimize,
        benchmark_http2_module,
        benchmark_boring_module,
        benchmark_http2_boring_source,
    );
    const benchmark_tls_server_module = add_tls_server_module(
        b,
        target,
        benchmark_optimize,
        benchmark_http2_module,
        benchmark_http2_boring_module,
        benchmark_boring_module,
    );

    // Benchmark server
    const benchmark_module = b.createModule(.{
        .root_source_file = b.path("benchmarks/benchmark.zig"),
        .target = target,
        .optimize = benchmark_optimize,
    });
    benchmark_module.addImport("http2", benchmark_http2_module);
    benchmark_module.addImport("http2-boring", benchmark_http2_boring_module);
    benchmark_module.addImport("boring", benchmark_boring_module);
    benchmark_module.addImport("tls-server", benchmark_tls_server_module);

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = benchmark_module,
    });
    b.installArtifact(benchmark);

    // Run step for benchmark
    const run_benchmark = b.addRunArtifact(benchmark);
    run_benchmark.step.dependOn(b.getInstallStep());
    const benchmark_step = b.step("benchmark", "Run HTTP/2 TLS benchmark server");
    benchmark_step.dependOn(&run_benchmark.step);

    // HttpArena baseline-h2 profile: starts the server, runs h2load with the
    // upstream profile knobs, writes results JSON in HttpArena's schema.
    const httparena_run = b.addSystemCommand(&.{ "bash", "benchmarks/httparena/run.sh" });
    httparena_run.step.dependOn(b.getInstallStep());
    const httparena_step = b.step(
        "httparena",
        "Run the HttpArena baseline-h2 profile against our server",
    );
    httparena_step.dependOn(&httparena_run.step);

    // Comparison: read the local results and rank against the upstream
    // leaderboard JSON pulled from github.com/MDA2AV/HttpArena.
    const httparena_compare = b.addSystemCommand(&.{ "bash", "benchmarks/httparena/compare.sh" });
    const compare_step = b.step(
        "httparena-compare",
        "Compare local HttpArena results against the upstream leaderboard",
    );
    compare_step.dependOn(&httparena_compare.step);

    // Same-host comparison against the upstream Rust reference (actix-h2c).
    // The reference source lives at benchmarks/httparena/actix-h2c/ as a
    // verbatim copy. The runner cargo-builds it on first use.
    const httparena_actix = b.addSystemCommand(&.{ "bash", "benchmarks/httparena/run-actix.sh" });
    const actix_step = b.step(
        "httparena-actix",
        "Build & benchmark the upstream actix-h2c reference implementation",
    );
    actix_step.dependOn(&httparena_actix.step);

    // Same-host comparison against the upstream actix TLS variant (h2 + rustls).
    // This is the apples-to-apples reference for our zig server, since both
    // negotiate h2 over TLS on :8443. Source at benchmarks/httparena/actix/.
    const httparena_actix_tls = b.addSystemCommand(&.{
        "bash",
        "benchmarks/httparena/run-actix-tls.sh",
    });
    const actix_tls_step = b.step(
        "httparena-actix-tls",
        "Build & benchmark the upstream actix h2-over-TLS reference implementation",
    );
    actix_tls_step.dependOn(&httparena_actix_tls.step);

    // End-to-end: run our zig profile, run both actix references, print a
    // side-by-side table on identical hardware. The runners use the same
    // port (8443) for the TLS variants, so they must run sequentially.
    // build.zig serializes the steps via dependsOn rather than running them
    // in parallel.
    const httparena_compare_local = b.addSystemCommand(&.{
        "bash",
        "benchmarks/httparena/compare-local.sh",
    });
    httparena_compare_local.step.dependOn(&httparena_run.step);
    httparena_compare_local.step.dependOn(&httparena_actix.step);
    httparena_actix_tls.step.dependOn(&httparena_run.step);
    httparena_compare_local.step.dependOn(&httparena_actix_tls.step);
    const vs_actix_step = b.step(
        "httparena-vs-actix",
        "Run zig + actix-h2c + actix-tls benchmarks and print side-by-side results",
    );
    vs_actix_step.dependOn(&httparena_compare_local.step);
}

fn add_http2_boring_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
    boring_module: *std.Build.Module,
    root_source_file: std.Build.LazyPath,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
    });
    module.addImport("boring", boring_module);
    module.addImport("http2", http2_module);

    return module;
}

fn add_tls_server_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
    http2_boring_module: *std.Build.Module,
    boring_module: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("examples/tls_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("http2", http2_module);
    module.addImport("http2-boring", http2_boring_module);
    module.addImport("boring", boring_module);

    return module;
}

fn add_http2_boring_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
    boring_module: *std.Build.Module,
    root_source_file: std.Build.LazyPath,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
    });
    module.addImport("boring", boring_module);
    module.addImport("http2", http2_module);

    return module;
}

fn add_tls_server_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
    http2_boring_module: *std.Build.Module,
    boring_module: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("examples/tls_server.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("http2", http2_module);
    module.addImport("http2-boring", http2_boring_module);
    module.addImport("boring", boring_module);

    return module;
}

/// Add comprehensive test suite
fn add_tests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
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
        "src/transport.zig",
    };

    var all_tests_step = b.step("test", "Run all unit tests");

    for (test_modules) |module_path| {
        const test_module = b.createModule(.{
            .root_source_file = b.path(module_path),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        const module_test = b.addTest(.{
            .root_module = test_module,
        });
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
