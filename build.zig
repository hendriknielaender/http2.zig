//! HTTP/2 protocol implementation build configuration.
//!
//! - High-performance HTTP/2 library
//! - Example server applications
//! - Comprehensive test suite
//! - Documentation generation
//! - Benchmarking tools

const std = @import("std");

const CiDeps = struct {
    fmt_check: ?*std.Build.Step = null,
    tigerstyle: ?*std.Build.Step = null,
    @"test": ?*std.Build.Step = null,
    dst: ?*std.Build.Step = null,
    dpt_compare: ?*std.Build.Step = null,
};

const ExampleArtifacts = struct {
    streaming: *std.Build.Step.Compile,
};

// Project metadata
const project_name = "http2";
const project_version = "0.1.0";

const tigerstyle_checked_paths = [_][]const u8{
    "src/static_allocator.zig",
    "src/memory_budget.zig",
    "src/budget_assertions.zig",
    "src/server.zig",
    "src/io/EventLoop.zig",
    "src/io/poll/kqueue.zig",
    "src/io/poll/epoll.zig",
    "src/http2.zig",
    "src/transport.zig",
    "src/frame.zig",
    "src/hpack.zig",
    "src/huffman.zig",
    "src/stream_storage.zig",
    "src/response.zig",
    "src/handler.zig",
    "examples/tls_server.zig",
    "examples/streaming.zig",
    "benchmarks/benchmark.zig",
    "tools/static_allocator_probe.zig",
    "tools/tigerstyle.zig",
};

const TigerStyleRegion = struct {
    path: []const u8,
    start_marker: []const u8,
    end_marker: []const u8,
};

// These legacy files predate project-wide TigerStyle. Keep the allocator-facing
// startup surface gated without making validation depend on the working-tree diff.
const tigerstyle_checked_regions = [_]TigerStyleRegion{
    .{
        .path = "src/connection.zig",
        .start_marker = "pub const Connection = struct {",
        .end_marker = "    pub fn bindRequestDispatcher(",
    },
    .{
        .path = "src/frame_handler.zig",
        .start_marker = "pub const DispatchContext = struct {",
        .end_marker = "pub fn dispatchFrameOptimized(",
    },
    .{
        .path = "src/connection.zig",
        .start_marker = "    fn continue_ready_streams_before_read(",
        .end_marker = "    const FlushReadyResult = struct {",
    },
    .{
        .path = "src/connection.zig",
        .start_marker = "test \"streaming scheduler bounds fair rounds and continues without input\" {",
        .end_marker = "test \"event-driven PRIORITY frame rejects payload lengths other than five octets\" {",
    },
    .{
        .path = "src/frame_handler.zig",
        .start_marker = "fn handleStreamLevelFrameProcess(",
        .end_marker = "fn handleStreamLevelFrameUpdateContinuationState(",
    },
    .{
        .path = "src/frame_handler.zig",
        .start_marker = "fn handleWindowUpdate(",
        .end_marker = "pub fn handlePriorityUpdateFrame(",
    },
    .{
        .path = "src/stream.zig",
        .start_marker = "            pub fn updateSendWindow(",
        .end_marker = "            pub fn sendRstStream(",
    },
};

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

    var ci = CiDeps{};

    // Example applications
    const examples = add_examples(
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
    add_simulators(b, target, optimize, &ci);

    // Test suite
    add_tests(b, target, optimize, examples, &ci);

    // Documentation
    add_documentation(b, http2_lib);

    // Code quality checks
    add_code_quality_checks(b, &ci);

    // CI orchestration
    add_ci(b, ci);
}

/// Add deterministic simulation and deterministic performance test runners.
fn add_simulators(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    ci: *CiDeps,
) void {
    const sim_module = b.createModule(.{
        .root_source_file = b.path("src/http2_sim.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const sim_exe = b.addExecutable(.{
        .name = "http2_sim",
        .root_module = sim_module,
    });
    b.installArtifact(sim_exe);

    const run_dst = b.addRunArtifact(sim_exe);
    run_dst.addArg("--dst");
    if (b.args) |args| run_dst.addArgs(args);
    hide_stderr(run_dst);
    const dst_step = b.step("dst", "Run deterministic HTTP/2 simulation testing");
    dst_step.dependOn(&run_dst.step);
    ci.dst = dst_step;

    const run_dst_swarm = b.addRunArtifact(sim_exe);
    run_dst_swarm.addArg("--dst");
    run_dst_swarm.addArg("--swarm");
    if (b.args) |args| run_dst_swarm.addArgs(args);
    hide_stderr(run_dst_swarm);
    const dst_swarm_step = b.step("dst-swarm", "Run deterministic HTTP/2 swarm simulation testing");
    dst_swarm_step.dependOn(&run_dst_swarm.step);

    const run_dpt = b.addRunArtifact(sim_exe);
    run_dpt.addArg("--dpt");
    run_dpt.addArg("--profile=hpack_pressure");
    if (b.args) |args| run_dpt.addArgs(args);
    hide_stderr(run_dpt);
    const dpt_step = b.step("dpt", "Run deterministic HTTP/2 performance testing");
    dpt_step.dependOn(&run_dpt.step);

    const run_dpt_baseline = b.addRunArtifact(sim_exe);
    run_dpt_baseline.addArg("--dpt");
    run_dpt_baseline.addArg("--dpt-baseline");
    run_dpt_baseline.addArg("--profile=hpack_pressure");
    if (b.args) |args| run_dpt_baseline.addArgs(args);
    hide_stderr(run_dpt_baseline);
    const dpt_baseline_step = b.step("dpt-baseline", "Print deterministic HTTP/2 performance baseline");
    dpt_baseline_step.dependOn(&run_dpt_baseline.step);

    const run_dpt_compare = b.addRunArtifact(sim_exe);
    run_dpt_compare.addArg("--dpt");
    run_dpt_compare.addArg("--dpt-compare");
    run_dpt_compare.addArg("--profile=hpack_pressure");
    if (b.args) |args| run_dpt_compare.addArgs(args);
    hide_stderr(run_dpt_compare);
    const dpt_compare_step = b.step("dpt-compare", "Compare deterministic HTTP/2 performance against thresholds");
    dpt_compare_step.dependOn(&run_dpt_compare.step);
    ci.dpt_compare = dpt_compare_step;
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
) ExampleArtifacts {
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

    const streaming = add_streaming_example(b, target, optimize, http2_module);

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

    return .{ .streaming = streaming };
}

fn add_streaming_example(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    http2_module: *std.Build.Module,
) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .root_source_file = b.path("examples/streaming.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("http2", http2_module);

    const executable = b.addExecutable(.{
        .name = "streaming_server",
        .root_module = module,
    });
    b.installArtifact(executable);

    const build_streaming = b.step(
        "example-streaming",
        "Build the static HTTP/2 streaming example",
    );
    build_streaming.dependOn(&executable.step);

    const run_streaming = b.addRunArtifact(executable);
    if (b.args) |args| run_streaming.addArgs(args);
    const run_step = b.step(
        "run-streaming",
        "Run the static HTTP/2 streaming example",
    );
    run_step.dependOn(&run_streaming.step);
    return executable;
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

/// Add comprehensive test suite
fn add_tests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    examples: ExampleArtifacts,
    ci: *CiDeps,
) void {
    // Unit tests for core modules
    const test_modules = [_][]const u8{
        "src/frame.zig",
        "src/stream.zig",
        "src/budget_assertions.zig",
        "src/connection.zig",
        "src/hpack.zig",
        "src/huffman.zig",
        "src/http2.zig",
        "src/memory_budget.zig",
        "src/server.zig",
        "src/transport.zig",
        "src/testing/prng.zig",
        "src/testing/time_sim.zig",
        "src/testing/packet_simulator.zig",
        "src/testing/network_sim.zig",
        "src/testing/cluster_sim.zig",
        "src/http2_sim.zig",
        "src/http2_cluster_sim.zig",
    };

    var all_tests_step = b.step("test", "Run all unit tests");
    ci.@"test" = all_tests_step;
    all_tests_step.dependOn(&examples.streaming.step);

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

    const allocator_probe_module = b.createModule(.{
        .root_source_file = b.path("tools/static_allocator_probe.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    });
    allocator_probe_module.addImport("static-allocator", b.createModule(.{
        .root_source_file = b.path("src/static_allocator.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseFast,
    }));
    const allocator_probe = b.addExecutable(.{
        .name = "static-allocator-release-probe",
        .root_module = allocator_probe_module,
    });
    const allocator_probe_step = b.step(
        "static-allocator-probe",
        "Verify ReleaseFast allocator phase guards",
    );
    const allocator_probe_cases = [_]struct {
        operation: []const u8,
        guard_message: []const u8,
    }{
        .{ .operation = "alloc", .guard_message = "allocation attempted after startup" },
        .{ .operation = "free", .guard_message = "free attempted before teardown" },
        .{ .operation = "resize", .guard_message = "resize attempted after startup" },
        .{ .operation = "remap", .guard_message = "remap attempted after startup" },
    };
    for (allocator_probe_cases) |probe_case| {
        const run_allocator_probe = b.addRunArtifact(allocator_probe);
        run_allocator_probe.addArg(probe_case.operation);
        run_allocator_probe.addCheck(.{ .expect_term = .{ .signal = .ABRT } });
        run_allocator_probe.expectStdErrMatch(probe_case.guard_message);
        allocator_probe_step.dependOn(&run_allocator_probe.step);
    }
    all_tests_step.dependOn(allocator_probe_step);
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

fn add_ci(b: *std.Build, ci: CiDeps) void {
    const step_ci = b.step("ci", "Run the full suite of CI checks");

    const CIMode = enum { smoke, @"test", full };

    const mode: CIMode = if (b.args) |args| mode: {
        if (args.len != 1) {
            step_ci.dependOn(&b.addFail("usage: zig build ci -- <smoke|test|full>").step);
            return;
        }
        break :mode std.meta.stringToEnum(CIMode, args[0]) orelse {
            step_ci.dependOn(&b.addFail("usage: zig build ci -- <smoke|test|full>").step);
            return;
        };
    } else .@"test";

    const all = mode == .full;
    const default = all or mode == .@"test";

    if (all or mode == .smoke or default) {
        step_ci.dependOn(ci.tigerstyle.?);
        step_ci.dependOn(ci.dst.?);
    }
    if (default or all) {
        step_ci.dependOn(ci.@"test".?);
        step_ci.dependOn(ci.dpt_compare.?);
    }
}

// Hide a step's stderr unless it fails, keeping CI output clean.
fn hide_stderr(run: *std.Build.Step.Run) void {
    const b = run.step.owner;
    run.addCheck(.{ .expect_term = .{ .exited = 0 } });
    run.has_side_effects = true;

    const Override = struct {
        var global_map: std.AutoHashMapUnmanaged(usize, std.Build.Step.MakeFn) = .{};

        fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
            const original = global_map.get(@intFromPtr(step)).?;
            try original(step, options);
            step.result_stderr = "";
        }
    };

    const original = run.step.makeFn;
    Override.global_map.put(b.allocator, @intFromPtr(&run.step), original) catch @panic("OOM");
    run.step.makeFn = &Override.make;
}

/// Add code quality and formatting checks
fn add_code_quality_checks(b: *std.Build, ci: *CiDeps) void {
    // Format check
    const fmt_check = b.addFmt(.{
        .paths = &[_][]const u8{
            "build.zig",
            "src/",
            "examples/",
            "benchmarks/",
            "tools/",
        },
        .check = true,
    });
    const fmt_check_step = b.step("fmt-check", "Check code formatting");
    fmt_check_step.dependOn(&fmt_check.step);
    ci.fmt_check = fmt_check_step;

    // Format fix
    const fmt_fix = b.addFmt(.{
        .paths = &[_][]const u8{
            "build.zig",
            "src/",
            "examples/",
            "benchmarks/",
            "tools/",
        },
        .check = false,
    });
    const fmt_fix_step = b.step("fmt", "Fix code formatting");
    fmt_fix_step.dependOn(&fmt_fix.step);

    const tigerstyle_checker = b.addExecutable(.{
        .name = "tigerstyle-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/tigerstyle.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const run_tigerstyle = b.addRunArtifact(tigerstyle_checker);
    for (tigerstyle_checked_paths) |path| {
        run_tigerstyle.addFileArg(b.path(path));
    }
    for (tigerstyle_checked_regions) |region| {
        run_tigerstyle.addArg("--region");
        run_tigerstyle.addFileArg(b.path(region.path));
        run_tigerstyle.addArg(region.start_marker);
        run_tigerstyle.addArg(region.end_marker);
    }

    const tigerstyle_step = b.step(
        "tigerstyle",
        "Check formatting, 100-column lines, and 70-line functions",
    );
    tigerstyle_step.dependOn(&fmt_check.step);
    tigerstyle_step.dependOn(&run_tigerstyle.step);
    ci.tigerstyle = tigerstyle_step;
}
