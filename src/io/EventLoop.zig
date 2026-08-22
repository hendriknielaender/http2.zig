const EventLoop = @This();
const builtin = @import("builtin");

const std = @import("std");
const Io = std.Io;
const Dir = std.Io.Dir;
const File = std.Io.File;
const net = std.Io.net;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const IpAddress = std.Io.net.IpAddress;
const errnoBug = std.Io.Threaded.errnoBug;
const closeFd = std.Io.Threaded.closeFd;
const posix = std.posix;
const posixSocketModeProtocol = Io.Threaded.posixSocketModeProtocol;

/// Readiness poller for the host platform. Everything below this line is
/// platform-neutral: the poller owns each thread's kernel descriptor and
/// normalizes its events, so adding a platform means adding a poller rather
/// than forking the scheduler.
pub const Poll = switch (builtin.os.tag) {
    .macos, .freebsd, .netbsd, .openbsd, .dragonfly => @import("poll/kqueue.zig"),
    .linux => @import("poll/epoll.zig"),
    else => @compileError("unimplemented platform: " ++ @tagName(builtin.os.tag)),
};

/// Out-of-band message delivered to a thread's idle loop.
const Signal = Poll.Signal;
/// Backend-reported readiness detail, carried to the woken fiber verbatim.
const Completion = Poll.Completion;

/// Must be a thread-safe allocator.
gpa: Allocator,
main_fiber_buffer: [@sizeOf(Fiber) + Fiber.max_result_size]u8 align(@alignOf(Fiber)),
threads: Thread.List,
fiber_pool: FiberPool,
workers_spawned: u32,
main_owner: std.atomic.Value(std.Thread.Id),

/// Idle-loop stack for each event-loop thread.
///
/// Two floors apply. The self-hosted backend was empirically seen using more
/// than 128 KiB when panicking, and glibc carves a thread's static TLS block
/// out of this same allocation and rejects `pthread_create` with `EINVAL`
/// unless the stack clears `guardsize + static TLS + MINIMAL_REST_STACK`. Zig
/// binaries carry roughly 264 KiB of static TLS, which puts that floor just
/// above 256 KiB, so a stack sized to the first bound alone fails to spawn any
/// worker on glibc. One MiB clears both with room to spare; the pages are
/// reserved lazily, so the unused tail costs address space rather than memory.
const idle_stack_size = 1024 * 1024;

const max_idle_search = 4;
const max_steal_ready_search = 4;
const max_iovecs_len = 8;

const Thread = struct {
    thread: std.Thread,
    idle_context: Io.fiber.Context,
    current_context: *Io.fiber.Context,
    ready_queue: ?*Fiber,
    poll: Poll.Instance,
    mutex: std.atomic.Mutex,
    idle_search_index: u32,
    steal_ready_search_index: u32,
    /// For ensuring multiple fibers waiting on the same file descriptor and
    /// filter share one registration.
    wait_queues: WaitQueues,
    wait_queue_limit: usize,

    const WaitQueueKey = struct {
        ident: usize,
        filter: Poll.Filter,
    };

    /// A wait_queues entry persists for the lifetime of the (fd, filter)
    /// poller registration. Registrations are edge-triggered: we register the
    /// FD once and leave it registered across many events — when no fibers
    /// are waiting, both fields are null but the entry stays in the map as
    /// a marker that "the poller still knows about this FD". The entry is
    /// only removed on `wakeFd` (called from `netClose`).
    const WaitQueue = struct {
        head: ?*Fiber,
        tail: ?*Fiber,
    };

    const WaitQueues = std.AutoArrayHashMapUnmanaged(WaitQueueKey, WaitQueue);

    const canceling: ?*Thread = @ptrFromInt(@alignOf(Thread));

    threadlocal var self: *Thread = undefined;

    fn current() *Thread {
        return self;
    }

    fn currentFiber(thread: *Thread) *Fiber {
        return @fieldParentPtr("context", thread.current_context);
    }

    const List = struct {
        allocated: []Thread,
        active: u32,
    };

    fn init(thread: *Thread, gpa: Allocator, wait_queue_capacity: usize) !void {
        var wait_queues: WaitQueues = .empty;
        errdefer wait_queues.deinit(gpa);
        try wait_queues.ensureTotalCapacity(gpa, wait_queue_capacity);

        var poll: Poll.Instance = undefined;
        try poll.init();
        errdefer poll.deinit();

        thread.* = .{
            .thread = undefined,
            .idle_context = undefined,
            .current_context = &thread.idle_context,
            .ready_queue = null,
            .poll = poll,
            .mutex = .unlocked,
            .idle_search_index = 0,
            .steal_ready_search_index = 0,
            .wait_queues = wait_queues,
            .wait_queue_limit = wait_queue_capacity,
        };
    }

    fn deinit(thread: *Thread, gpa: Allocator) void {
        thread.poll.deinit();
        // With persistent edge-triggered registrations, entries may remain
        // as empty markers after all FDs were closed via `wakeFd`. What we
        // must not see is any *active* waiter still parked on this thread.
        for (thread.wait_queues.values()) |wait_queue| {
            if (wait_queue.head != null) {
                @panic("EventLoop deinitialized with an active wait registration");
            }
        }
        thread.wait_queues.deinit(gpa);
    }
};

const Fiber = struct {
    required_align: void align(4),
    context: Io.fiber.Context,
    awaiter: ?*Fiber,
    queue_next: ?*Fiber,
    group_next: ?*Fiber,
    cancel_thread: ?*Thread,
    awaiting_completions: std.StaticBitSet(3),

    const finished: ?*Fiber = @ptrFromInt(@alignOf(Thread));

    const max_result_align: Alignment = .@"16";
    const max_result_size = max_result_align.forward(64);
    /// This includes any stack realignments that need to happen, and also the
    /// initial frame return address slot and argument frame, depending on target.
    const min_stack_size = 512 * 1024;
    const max_context_align: Alignment = .@"16";
    const max_context_size = max_context_align.forward(1024);
    const max_closure_size: usize = @sizeOf(AsyncClosure);
    const max_closure_align: Alignment = .of(AsyncClosure);
    const allocation_size = std.mem.alignForward(
        usize,
        max_closure_align.max(max_context_align).forward(
            max_result_align.forward(@sizeOf(Fiber)) + max_result_size + min_stack_size,
        ) + max_closure_size + max_context_size,
        std.heap.page_size_max,
    );

    fn allocate(loop: *EventLoop) error{ConcurrencyUnavailable}!*Fiber {
        return loop.fiber_pool.acquire() orelse error.ConcurrencyUnavailable;
    }

    fn allocatedSlice(f: *Fiber) []align(@alignOf(Fiber)) u8 {
        return @as([*]align(@alignOf(Fiber)) u8, @ptrCast(f))[0..allocation_size];
    }

    fn allocatedEnd(f: *Fiber) [*]u8 {
        const allocated_slice = f.allocatedSlice();
        return allocated_slice[allocated_slice.len..].ptr;
    }

    fn resultPointer(f: *Fiber, comptime Result: type) *Result {
        return @ptrCast(@alignCast(f.resultBytes(.of(Result))));
    }

    fn resultBytes(f: *Fiber, alignment: Alignment) [*]u8 {
        return @ptrFromInt(alignment.forward(@intFromPtr(f) + @sizeOf(Fiber)));
    }

    fn enterCancelRegion(fiber: *Fiber, thread: *Thread) error{Canceled}!void {
        if (@cmpxchgStrong(
            ?*Thread,
            &fiber.cancel_thread,
            null,
            thread,
            .acq_rel,
            .acquire,
        )) |cancel_thread| {
            assert(cancel_thread == Thread.canceling);
            return error.Canceled;
        }
    }

    fn exitCancelRegion(fiber: *Fiber, thread: *Thread) void {
        if (@cmpxchgStrong(
            ?*Thread,
            &fiber.cancel_thread,
            thread,
            null,
            .acq_rel,
            .acquire,
        )) |cancel_thread| assert(cancel_thread == Thread.canceling);
    }

    const Queue = struct { head: *Fiber, tail: *Fiber };
};

/// Startup memory reserved for each concurrent EventLoop task.
pub const fiber_allocation_size = Fiber.allocation_size;
/// Conservative per-registration map storage, including index/control bytes.
pub const wait_registration_bytes_max: usize = 128;
/// Conservative fixed allocation and alignment slack for each wait map.
pub const wait_map_fixed_bytes_max: usize = 256;
pub const worker_stack_size = idle_stack_size;
pub const worker_stack_reservation_bytes_max = worker_stack_size + std.heap.page_size_max;
pub const thread_state_size = @sizeOf(Thread);
pub const backend_struct_size = @sizeOf(EventLoop);

const FiberPool = struct {
    storage: []align(@alignOf(Fiber)) u8,
    free_head: ?*Fiber,
    free_count: usize,
    capacity: usize,
    mutex: std.atomic.Mutex,

    fn init(gpa: Allocator, capacity: usize) !FiberPool {
        const storage_size = std.math.mul(
            usize,
            capacity,
            Fiber.allocation_size,
        ) catch return error.OutOfMemory;
        const storage = try gpa.alignedAlloc(u8, .of(Fiber), storage_size);

        var free_head: ?*Fiber = null;
        var index = capacity;
        while (index > 0) {
            index -= 1;
            const offset = index * Fiber.allocation_size;
            const fiber: *Fiber = @ptrCast(@alignCast(storage[offset..].ptr));
            fiber.queue_next = free_head;
            free_head = fiber;
        }

        return .{
            .storage = storage,
            .free_head = free_head,
            .free_count = capacity,
            .capacity = capacity,
            .mutex = .unlocked,
        };
    }

    fn deinit(pool: *FiberPool, gpa: Allocator) void {
        if (pool.free_count != pool.capacity) {
            @panic("EventLoop deinitialized with live fibers");
        }
        gpa.free(pool.storage);
        pool.* = undefined;
    }

    fn acquire(pool: *FiberPool) ?*Fiber {
        lockMutex(&pool.mutex);
        defer pool.mutex.unlock();

        const fiber = pool.free_head orelse return null;
        pool.free_head = fiber.queue_next;
        fiber.queue_next = null;
        assert(pool.free_count > 0);
        pool.free_count -= 1;
        return fiber;
    }

    fn release(pool: *FiberPool, fiber: *Fiber) void {
        lockMutex(&pool.mutex);
        defer pool.mutex.unlock();

        assert(fiber.queue_next == null);
        assert(pool.free_count < pool.capacity);
        fiber.queue_next = pool.free_head;
        pool.free_head = fiber;
        pool.free_count += 1;
    }
};

test "fiber allocation reports saturation and reuses storage" {
    var loop: EventLoop = undefined;
    loop.fiber_pool = try FiberPool.init(std.testing.allocator, 2);
    const first = try Fiber.allocate(&loop);
    const second = try Fiber.allocate(&loop);
    const saturated = blk: {
        _ = Fiber.allocate(&loop) catch |err| {
            break :blk err == error.ConcurrencyUnavailable;
        };
        break :blk false;
    };

    loop.fiber_pool.release(first);
    const recycled = try Fiber.allocate(&loop);
    const reused = recycled == first;
    loop.fiber_pool.release(second);
    loop.fiber_pool.release(recycled);
    const storage_len = loop.fiber_pool.storage.len;
    loop.fiber_pool.deinit(std.testing.allocator);

    try std.testing.expect(saturated);
    try std.testing.expect(reused);
    try std.testing.expectEqual(2 * fiber_allocation_size, storage_len);
}

fn recycle(loop: *EventLoop, fiber: *Fiber) void {
    std.log.debug("recycling {*}", .{fiber});
    assert(fiber.queue_next == null);
    loop.fiber_pool.release(fiber);
}

pub const InitOptions = struct {
    n_threads: ?usize = null,
    max_concurrent_tasks: usize,
    max_wait_registrations_per_thread: usize,
};

pub const InitError = error{InvalidCapacity} ||
    Allocator.Error ||
    Poll.CreateError ||
    std.Thread.SpawnError;

pub const AllocationSizeError = error{ InvalidCapacity, Overflow };

/// Bounds bytes requested from `gpa` by `create(EventLoop)` plus `init`.
/// OS-owned stacks are separate: reserve `worker_stack_reservation_bytes_max` per worker.
pub fn allocatorBytesMax(options: InitOptions) AllocationSizeError!usize {
    const n_threads = try resolveThreadCount(options);
    const thread_bytes = try multiplyBytes(n_threads, thread_state_size);
    const main_storage = try alignBytes(
        try addBytes(thread_bytes, idle_stack_size),
        std.heap.page_size_max,
    );
    const fiber_bytes = try multiplyBytes(
        options.max_concurrent_tasks,
        fiber_allocation_size,
    );
    const registration_bytes = try multiplyBytes(
        options.max_wait_registrations_per_thread,
        wait_registration_bytes_max,
    );
    const map_bytes = try addBytes(wait_map_fixed_bytes_max, registration_bytes);
    const all_map_bytes = try multiplyBytes(n_threads, map_bytes);

    var total = try addBytes(backend_struct_size, main_storage);
    total = try addBytes(total, fiber_bytes);
    return addBytes(total, all_map_bytes);
}

fn addBytes(a: usize, b: usize) error{Overflow}!usize {
    return std.math.add(usize, a, b) catch error.Overflow;
}

fn multiplyBytes(a: usize, b: usize) error{Overflow}!usize {
    return std.math.mul(usize, a, b) catch error.Overflow;
}

fn alignBytes(value: usize, alignment: usize) error{Overflow}!usize {
    const with_padding = try addBytes(value, alignment - 1);
    return with_padding & ~(alignment - 1);
}

pub fn init(loop: *EventLoop, gpa: Allocator, options: InitOptions) !void {
    const n_threads = try resolveThreadCount(options);
    const threads_size = std.math.mul(
        usize,
        n_threads,
        @sizeOf(Thread),
    ) catch return error.OutOfMemory;
    const idle_stack_unaligned = std.math.add(
        usize,
        threads_size,
        idle_stack_size,
    ) catch return error.OutOfMemory;
    const idle_stack_end_offset = std.mem.alignForward(
        usize,
        idle_stack_unaligned,
        std.heap.page_size_max,
    );
    const allocated_slice = try gpa.alignedAlloc(u8, .of(Thread), idle_stack_end_offset);
    errdefer gpa.free(allocated_slice);

    var fiber_pool = try FiberPool.init(gpa, options.max_concurrent_tasks);
    errdefer fiber_pool.deinit(gpa);

    loop.* = .{
        .gpa = gpa,
        .main_fiber_buffer = undefined,
        .threads = .{
            .allocated = @ptrCast(allocated_slice[0..threads_size]),
            .active = 0,
        },
        .fiber_pool = fiber_pool,
        .workers_spawned = 0,
        .main_owner = .init(0),
    };

    initializeThreads(loop, options.max_wait_registrations_per_thread) catch |err| {
        cleanupInitializedThreads(loop);
        loop.* = undefined;
        return err;
    };
    initializeMainFiber(loop, allocated_slice, idle_stack_end_offset);
    spawnWorkerThreads(loop) catch |err| {
        cleanupInitializedThreads(loop);
        loop.* = undefined;
        return err;
    };
}

fn resolveThreadCount(options: InitOptions) error{InvalidCapacity}!usize {
    if (options.max_concurrent_tasks == 0 or
        options.max_wait_registrations_per_thread == 0)
    {
        return error.InvalidCapacity;
    }
    if (options.n_threads) |n_threads| {
        if (n_threads == 0 or n_threads > std.math.maxInt(u32)) {
            return error.InvalidCapacity;
        }
        return n_threads;
    }

    const detected = std.Thread.getCpuCount() catch 1;
    if (detected > std.math.maxInt(u32)) return error.InvalidCapacity;
    return @max(1, detected);
}

test "init options require explicit nonzero capacities" {
    try std.testing.expectError(error.InvalidCapacity, resolveThreadCount(.{
        .n_threads = 1,
        .max_concurrent_tasks = 0,
        .max_wait_registrations_per_thread = 1,
    }));
    try std.testing.expectError(error.InvalidCapacity, resolveThreadCount(.{
        .n_threads = 1,
        .max_concurrent_tasks = 1,
        .max_wait_registrations_per_thread = 0,
    }));
    try std.testing.expectError(error.InvalidCapacity, resolveThreadCount(.{
        .n_threads = 0,
        .max_concurrent_tasks = 1,
        .max_wait_registrations_per_thread = 1,
    }));
}

test "init preallocates the single-thread backend" {
    var loop: EventLoop = undefined;
    try loop.init(std.testing.allocator, .{
        .n_threads = 1,
        .max_concurrent_tasks = 2,
        .max_wait_registrations_per_thread = 3,
    });

    const active_threads = loop.threads.active;
    const available_tasks = loop.fiber_pool.free_count;
    const wait_capacity = loop.threads.allocated[0].wait_queues.capacity();
    loop.deinit();

    try std.testing.expectEqual(1, active_threads);
    try std.testing.expectEqual(2, available_tasks);
    try std.testing.expect(wait_capacity >= 3);
}

test "init eagerly starts configured workers" {
    var loop: EventLoop = undefined;
    try loop.init(std.heap.c_allocator, .{
        .n_threads = 2,
        .max_concurrent_tasks = 2,
        .max_wait_registrations_per_thread = 3,
    });

    const active_threads = loop.threads.active;
    const workers_spawned = loop.workers_spawned;
    loop.deinit();

    try std.testing.expectEqual(2, active_threads);
    try std.testing.expectEqual(1, workers_spawned);
}

test "exit notification cannot be replaced by an ordinary wake" {
    var thread: Thread = undefined;
    try thread.init(std.testing.allocator, 1);
    defer thread.deinit(std.testing.allocator);

    signalThreadExit(&thread);
    wakeThread(&thread);
    var events: [Poll.wait_buffer_len]Poll.Event = undefined;
    const event_count = try thread.poll.wait(&events, 0);

    var saw_exit = false;
    var saw_wakeup = false;
    for (events[0..event_count]) |event| {
        const message = switch (event) {
            .signal => |signal| signal,
            .ready => continue,
        };
        saw_exit = saw_exit or message == .exit;
        saw_wakeup = saw_wakeup or message == .wakeup;
    }
    try std.testing.expectEqual(2, event_count);
    try std.testing.expect(saw_exit);
    try std.testing.expect(saw_wakeup);
}

test "allocator byte bound covers eager backend storage" {
    var gpa: std.heap.DebugAllocator(.{
        .enable_memory_limit = true,
        .thread_safe = true,
    }) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const options: InitOptions = .{
        .n_threads = 2,
        .max_concurrent_tasks = 2,
        .max_wait_registrations_per_thread = 17,
    };

    const loop = try allocator.create(EventLoop);
    try loop.init(allocator, options);
    const actual_bytes = gpa.total_requested_bytes;
    const bounded_bytes = try allocatorBytesMax(options);
    loop.deinit();
    allocator.destroy(loop);

    try std.testing.expect(actual_bytes <= bounded_bytes);
    try std.testing.expectEqual(0, gpa.total_requested_bytes);
}

const AttachTestContext = struct {
    loop: *EventLoop,
    attached: std.atomic.Value(bool) = .init(false),
    finished: std.atomic.Value(bool) = .init(false),
    release: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    fn run(context: *AttachTestContext) void {
        defer context.finished.store(true, .release);
        context.loop.attachCurrentThread() catch |err| {
            context.failure = err;
            return;
        };
        defer context.loop.detachCurrentThread();
        context.loop.checkCancel() catch |err| {
            context.failure = err;
            return;
        };
        context.attached.store(true, .release);
        while (!context.release.load(.acquire)) std.Thread.yield() catch {};
    }
};

test "main fiber ownership transfers without allocation" {
    var loop: EventLoop = undefined;
    try loop.init(std.testing.allocator, .{
        .n_threads = 1,
        .max_concurrent_tasks = 1,
        .max_wait_registrations_per_thread = 1,
    });

    var context = AttachTestContext{ .loop = &loop };
    const thread = try std.Thread.spawn(.{}, AttachTestContext.run, .{&context});
    while (!context.attached.load(.acquire) and
        !context.finished.load(.acquire))
    {
        std.Thread.yield() catch {};
    }
    if (!context.attached.load(.acquire)) {
        thread.join();
        return context.failure orelse error.TestUnexpectedResult;
    }
    try std.testing.expectError(error.ThreadAlreadyAttached, loop.attachCurrentThread());
    context.release.store(true, .release);
    thread.join();

    try std.testing.expectEqual(@as(?anyerror, null), context.failure);
    try loop.attachCurrentThread();
    try std.testing.expectError(error.ThreadAlreadyAttached, loop.attachCurrentThread());
    loop.detachCurrentThread();
    loop.deinit();
}

fn initializeThreads(loop: *EventLoop, wait_queue_capacity: usize) !void {
    for (loop.threads.allocated) |*thread| {
        try thread.init(loop.gpa, wait_queue_capacity);
        loop.threads.active += 1;
    }
}

fn initializeMainFiber(
    loop: *EventLoop,
    allocated_slice: []align(@alignOf(Thread)) u8,
    idle_stack_end_offset: usize,
) void {
    const main_fiber = loop.mainFiber();
    main_fiber.* = .{
        .required_align = {},
        .context = undefined,
        .awaiter = null,
        .queue_next = null,
        .group_next = null,
        .cancel_thread = null,
        .awaiting_completions = .empty,
    };
    const main_thread = &loop.threads.allocated[0];
    const idle_stack_end: [*]align(16) usize = @ptrCast(@alignCast(
        allocated_slice[idle_stack_end_offset..].ptr,
    ));
    (idle_stack_end - 1)[0..1].* = .{@intFromPtr(loop)};
    main_thread.idle_context = switch (builtin.cpu.arch) {
        .aarch64 => .{
            .sp = @intFromPtr(idle_stack_end),
            .fp = 0,
            .pc = @intFromPtr(&mainIdleEntry),
        },
        .x86_64 => .{
            .rsp = @intFromPtr(idle_stack_end - 1),
            .rbp = 0,
            .rip = @intFromPtr(&mainIdleEntry),
        },
        else => @compileError("unimplemented architecture"),
    };
    main_thread.current_context = &main_fiber.context;
    main_thread.idle_search_index = 1;
    main_thread.steal_ready_search_index = 1;
    std.log.debug("created main idle {*}", .{&main_thread.idle_context});
    std.log.debug("created main {*}", .{main_fiber});
}

fn spawnWorkerThreads(loop: *EventLoop) std.Thread.SpawnError!void {
    for (loop.threads.allocated[1..], 1..) |*thread, index| {
        thread.thread = try std.Thread.spawn(.{
            .stack_size = idle_stack_size,
            .allocator = loop.gpa,
        }, threadEntry, .{ loop, @as(u32, @intCast(index)) });
        loop.workers_spawned += 1;
    }
}

fn cleanupInitializedThreads(loop: *EventLoop) void {
    const initialized = loop.threads.active;
    if (initialized == 0) return;

    const spawned_end = loop.workers_spawned + 1;
    for (loop.threads.allocated[1..spawned_end]) |*thread| signalThreadExit(thread);
    for (loop.threads.allocated[1..spawned_end]) |*thread| thread.thread.join();

    for (loop.threads.allocated[0..initialized]) |*thread| thread.deinit(loop.gpa);
    loop.threads.active = 0;
    loop.workers_spawned = 0;
}

pub const AttachError = error{ThreadAlreadyAttached};

/// Acquires exclusive ownership of the main fiber for the calling thread.
/// Attachment is not reentrant; detach before any later attachment.
pub fn attachCurrentThread(loop: *EventLoop) AttachError!void {
    const current_id = std.Thread.getCurrentId();
    assert(current_id != 0);
    if (loop.main_owner.cmpxchgStrong(0, current_id, .acq_rel, .acquire) != null)
        return error.ThreadAlreadyAttached;

    const main_thread = &loop.threads.allocated[0];
    const main_fiber = loop.mainFiber();
    assert(main_thread.current_context == &main_fiber.context);
    main_thread.current_context = &main_fiber.context;
    Thread.self = main_thread;
}

/// Releases main-fiber ownership after synchronous I/O has returned.
pub fn detachCurrentThread(loop: *EventLoop) void {
    const current_id = std.Thread.getCurrentId();
    const main_thread = &loop.threads.allocated[0];
    const main_fiber = loop.mainFiber();
    assert(loop.main_owner.load(.acquire) == current_id);
    assert(Thread.self == main_thread);
    assert(main_thread.current_context == &main_fiber.context);

    Thread.self = undefined;
    const owner = loop.main_owner.cmpxchgStrong(current_id, 0, .release, .acquire);
    assert(owner == null);
}

/// Cancels and wakes the main fiber if it is parked on `fd`.
/// Cancellation is published first so a concurrent wait publication cannot
/// miss the interrupt.
pub fn interruptMainWait(loop: *EventLoop, fd: posix.fd_t) void {
    assert(fd >= 0);
    const previous = @atomicRmw(
        ?*Thread,
        &loop.mainFiber().cancel_thread,
        .Xchg,
        Thread.canceling,
        .acq_rel,
    );
    if (previous != null and previous != Thread.canceling) {
        @panic("EventLoop main fiber interrupted inside a cancel region");
    }
    loop.wakeFd(fd);
}

/// Clears the stop-time cancellation after the main wait has returned.
pub fn clearMainCancellation(loop: *EventLoop) void {
    const previous = @atomicRmw(
        ?*Thread,
        &loop.mainFiber().cancel_thread,
        .Xchg,
        null,
        .acq_rel,
    );
    if (previous != null and previous != Thread.canceling) {
        @panic("EventLoop main fiber left a cancel region active");
    }
}

pub fn deinit(loop: *EventLoop) void {
    loop.attachCurrentThread() catch @panic("EventLoop main fiber is already attached");
    const active_threads = @atomicLoad(u32, &loop.threads.active, .acquire);
    for (loop.threads.allocated[0..active_threads]) |*thread| {
        const ready_fiber = @atomicLoad(?*Fiber, &thread.ready_queue, .monotonic);
        if (ready_fiber != null and ready_fiber != Fiber.finished) {
            @panic("EventLoop deinitialized with ready fibers");
        }
    }
    loop.yield(null, .exit);
    const gpa = loop.gpa;
    const allocated_ptr: [*]align(@alignOf(Thread)) u8 = @ptrCast(@alignCast(
        loop.threads.allocated.ptr,
    ));
    const idle_stack_end_offset = std.mem.alignForward(
        usize,
        loop.threads.allocated.len * @sizeOf(Thread) + idle_stack_size,
        std.heap.page_size_max,
    );
    for (loop.threads.allocated[1..active_threads]) |*thread| thread.thread.join();
    for (loop.threads.allocated[0..active_threads]) |*thread| thread.deinit(gpa);
    loop.fiber_pool.deinit(gpa);
    loop.detachCurrentThread();
    gpa.free(allocated_ptr[0..idle_stack_end_offset]);
    loop.* = undefined;
}

fn lockThread(thread: *Thread) void {
    lockMutex(&thread.mutex);
}

fn lockMutex(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) {
        std.Thread.yield() catch {};
    }
}

fn mainFiber(loop: *EventLoop) *Fiber {
    return @ptrCast(&loop.main_fiber_buffer);
}

fn queueContainsFiber(head: *Fiber, target: *Fiber) bool {
    var fiber = head;
    while (true) {
        if (fiber == target) return true;
        fiber = fiber.queue_next orelse return false;
    }
}

fn findReadyFiber(loop: *EventLoop, thread: *Thread) ?*Fiber {
    if (@atomicRmw(?*Fiber, &thread.ready_queue, .Xchg, Fiber.finished, .acquire)) |ready_fiber| {
        // The sentinel locks the list against pushers until the remainder is
        // published; see `waitForReadyQueue`.
        const remainder = ready_fiber.queue_next;
        ready_fiber.queue_next = null;
        if (@cmpxchgStrong(
            ?*Fiber,
            &thread.ready_queue,
            Fiber.finished,
            remainder,
            .release,
            .monotonic,
        ) != null) @panic("ready queue pushed across an active pop");
        return ready_fiber;
    }
    const active_threads = @atomicLoad(u32, &loop.threads.active, .acquire);
    for (0..@min(max_steal_ready_search, active_threads)) |_| {
        defer thread.steal_ready_search_index += 1;
        if (thread.steal_ready_search_index == active_threads) thread.steal_ready_search_index = 0;
        const steal_ready_search_thread =
            &loop.threads.allocated[0..active_threads][thread.steal_ready_search_index];
        if (steal_ready_search_thread == thread) continue;
        const ready_fiber = @atomicLoad(
            ?*Fiber,
            &steal_ready_search_thread.ready_queue,
            .acquire,
        ) orelse continue;
        if (ready_fiber == Fiber.finished) continue;
        if (queueContainsFiber(ready_fiber, loop.mainFiber())) continue;
        if (@cmpxchgWeak(
            ?*Fiber,
            &steal_ready_search_thread.ready_queue,
            ready_fiber,
            null,
            .acquire,
            .monotonic,
        )) |_| continue;
        const remainder = ready_fiber.queue_next;
        ready_fiber.queue_next = null;
        // Our own slot still holds this pop's sentinel; publish the stolen
        // remainder through it, exactly like the local-pop path above.
        if (@cmpxchgStrong(
            ?*Fiber,
            &thread.ready_queue,
            Fiber.finished,
            remainder,
            .release,
            .monotonic,
        ) != null) @panic("ready queue pushed across an active steal");
        return ready_fiber;
    }
    // couldn't find anything to do, so we are now open for business
    @atomicStore(?*Fiber, &thread.ready_queue, null, .monotonic);
    return null;
}

fn yield(
    loop: *EventLoop,
    maybe_ready_fiber: ?*Fiber,
    pending_task: SwitchMessage.PendingTask,
) void {
    const thread: *Thread = .current();
    const local_ready = loop.readyFiberForThread(thread, maybe_ready_fiber);
    const ready_context = if (local_ready orelse loop.findReadyFiber(thread)) |ready_fiber|
        &ready_fiber.context
    else
        &thread.idle_context;
    const message: SwitchMessage = .{
        .contexts = .{
            .old = thread.current_context,
            .new = ready_context,
        },
        .pending_task = pending_task,
    };
    std.log.debug("switching from {*} to {*}", .{
        message.contexts.old,
        message.contexts.new,
    });
    contextSwitch(&message).handle(loop);
}

fn readyFiberForThread(loop: *EventLoop, thread: *Thread, maybe_fiber: ?*Fiber) ?*Fiber {
    const fiber = maybe_fiber orelse return null;
    if (fiber != loop.mainFiber() or thread == &loop.threads.allocated[0]) return fiber;

    assert(fiber.queue_next == null);
    scheduleReadyQueueOnThread(&loop.threads.allocated[0], .{
        .head = fiber,
        .tail = fiber,
    });
    return null;
}

fn schedule(loop: *EventLoop, thread: *Thread, unpinned_queue: Fiber.Queue) void {
    var ready_queue = unpinned_queue;
    if (!loop.pinMainFiber(&ready_queue)) return;
    {
        var fiber = ready_queue.head;
        while (true) {
            std.log.debug("scheduling {*}", .{fiber});
            fiber = fiber.queue_next orelse break;
        }
        assert(fiber == ready_queue.tail);
    }
    const active_threads = @atomicLoad(u32, &loop.threads.active, .acquire);
    for (0..@min(max_idle_search, active_threads)) |_| {
        defer thread.idle_search_index += 1;
        if (thread.idle_search_index == active_threads) thread.idle_search_index = 0;
        const idle_search_thread =
            &loop.threads.allocated[0..active_threads][thread.idle_search_index];
        if (idle_search_thread == thread) continue;
        if (@cmpxchgWeak(
            ?*Fiber,
            &idle_search_thread.ready_queue,
            null,
            ready_queue.head,
            .release,
            .monotonic,
        )) |_| continue;
        wakeThread(idle_search_thread);
        return;
    }
    // nobody wanted it, so just queue it on ourselves
    var expected: ?*Fiber = null;
    while (true) {
        waitForReadyQueue(thread);
        if (@cmpxchgWeak(
            ?*Fiber,
            &thread.ready_queue,
            expected,
            ready_queue.head,
            .acq_rel,
            .acquire,
        )) |old_head| {
            if (old_head != Fiber.finished) {
                ready_queue.tail.queue_next = old_head;
                expected = old_head;
            }
            continue;
        }
        break;
    }
}

/// Blocks pushers while a pop holds the `finished` sentinel in the slot, so a
/// push can never interleave between the pop's list detach and its remainder
/// publication.
fn waitForReadyQueue(thread: *Thread) void {
    while (@atomicLoad(?*Fiber, &thread.ready_queue, .acquire) == Fiber.finished) {
        std.atomic.spinLoopHint();
    }
}

fn pinMainFiber(loop: *EventLoop, ready_queue: *Fiber.Queue) bool {
    const main_fiber = loop.mainFiber();
    var previous: ?*Fiber = null;
    var fiber = ready_queue.head;
    while (true) {
        if (fiber == main_fiber) {
            const next = fiber.queue_next;
            if (previous) |previous_fiber| {
                previous_fiber.queue_next = next;
                if (ready_queue.tail == fiber) ready_queue.tail = previous_fiber;
            } else if (next) |next_fiber| {
                ready_queue.head = next_fiber;
            }
            fiber.queue_next = null;
            scheduleReadyQueueOnThread(&loop.threads.allocated[0], .{
                .head = fiber,
                .tail = fiber,
            });
            return previous != null or next != null;
        }
        previous = fiber;
        fiber = fiber.queue_next orelse return true;
    }
}

fn mainIdle(
    loop: *EventLoop,
    message: *const SwitchMessage,
) callconv(.withStackAlign(.c, @max(
    @alignOf(Thread),
    @alignOf(Io.fiber.Context),
))) noreturn {
    message.handle(loop);
    loop.idle(&loop.threads.allocated[0]);
    loop.yield(@ptrCast(&loop.main_fiber_buffer), .nothing);
    unreachable; // switched to dead fiber
}

fn threadEntry(loop: *EventLoop, index: u32) void {
    const thread: *Thread = &loop.threads.allocated[index];
    Thread.self = thread;
    std.log.debug("created thread idle {*}", .{&thread.idle_context});
    loop.idle(thread);
}

fn idle(loop: *EventLoop, thread: *Thread) void {
    var events_buffer: [Poll.wait_buffer_len]Poll.Event = undefined;
    var maybe_ready_fiber: ?*Fiber = null;
    while (true) {
        while (maybe_ready_fiber orelse loop.findReadyFiber(thread)) |ready_fiber| {
            loop.yield(ready_fiber, .nothing);
            maybe_ready_fiber = null;
        }
        const n = thread.poll.wait(&events_buffer, null) catch |err| {
            // TODO handle EINTR for cancellation purposes
            @panic(@errorName(err)); // TODO
        };
        var maybe_ready_queue: ?Fiber.Queue = null;
        for (events_buffer[0..n]) |event| switch (event) {
            .signal => |message| switch (message) {
                .wakeup => {},
                .cleanup => @panic("failed to notify other threads that we are exiting"),
                .exit => {
                    // Pending async work must have drained before exit.
                    assert(maybe_ready_fiber == null and maybe_ready_queue == null);
                    return;
                },
            },
            .ready => |ready| processFdEvent(
                thread,
                ready,
                &maybe_ready_fiber,
                &maybe_ready_queue,
            ),
        };
        if (maybe_ready_queue) |ready_queue| loop.schedule(thread, ready_queue);
    }
}

fn processFdEvent(
    thread: *Thread,
    event: Poll.Event.Ready,
    maybe_ready_fiber: *?*Fiber,
    maybe_ready_queue: *?Fiber.Queue,
) void {
    const wait_queue = drainWaitQueue(thread, event) orelse return;
    const event_head = wait_queue.head;
    const event_tail = wait_queue.tail;
    assert(event_tail.queue_next == null);

    event_head.resultPointer(Completion).* = event.completion;
    queueReadyEvent(maybe_ready_fiber, maybe_ready_queue, event_head, event_tail);
}

fn drainWaitQueue(thread: *Thread, event: Poll.Event.Ready) ?Fiber.Queue {
    lockThread(thread);
    defer thread.mutex.unlock();

    const entry = thread.wait_queues.getPtr(.{
        .ident = event.ident,
        .filter = event.filter,
    }) orelse return null;
    const head = entry.head orelse return null;
    const tail = entry.tail.?;
    entry.* = .{ .head = null, .tail = null };
    return .{ .head = head, .tail = tail };
}

fn queueReadyEvent(
    maybe_fiber: *?*Fiber,
    maybe_queue: *?Fiber.Queue,
    event_head: *Fiber,
    event_tail: *Fiber,
) void {
    const head = if (maybe_fiber.* == null) blk: {
        maybe_fiber.* = event_head;
        const next = event_head.queue_next orelse return;
        event_head.queue_next = null;
        break :blk next;
    } else event_head;

    if (maybe_queue.*) |*ready_queue| {
        ready_queue.tail.queue_next = head;
        ready_queue.tail = event_tail;
    } else {
        maybe_queue.* = .{ .head = head, .tail = event_tail };
    }
}

const WaitPublicationResult = enum {
    pending,
    waiting,
    canceled,
    system_resources,
};

const WaitPublication = struct {
    fd: posix.fd_t,
    filter: Poll.Filter,
    result: *WaitPublicationResult,
};

const GroupCompletion = struct {
    fiber: *Fiber,
    group: *Io.Group,
};

fn waitForFd(
    loop: *EventLoop,
    fd: posix.fd_t,
    filter: Poll.Filter,
) error{ Canceled, SystemResources }!void {
    try loop.checkCancel();

    assert(fd >= 0);
    var result: WaitPublicationResult = .pending;
    loop.yield(null, .{ .publish_wait = .{
        .fd = fd,
        .filter = filter,
        .result = &result,
    } });

    switch (result) {
        .pending => unreachable,
        .waiting => try loop.checkCancel(),
        .canceled => return error.Canceled,
        .system_resources => return error.SystemResources,
    }
}

fn publishWait(
    loop: *EventLoop,
    thread: *Thread,
    fiber: *Fiber,
    publication: WaitPublication,
) void {
    assert(publication.result.* == .pending);
    assert(fiber.queue_next == null);

    lockThread(thread);
    const key: Thread.WaitQueueKey = .{
        .ident = @intCast(publication.fd),
        .filter = publication.filter,
    };
    const canceled = @atomicLoad(
        ?*Thread,
        &fiber.cancel_thread,
        .acquire,
    ) == Thread.canceling;
    if (canceled) {
        publication.result.* = .canceled;
    } else if (thread.wait_queues.getPtr(key)) |wait_queue| {
        const was_empty = wait_queue.head == null;
        appendWaiter(wait_queue, fiber);
        if (was_empty) registerFd(thread, key.ident, key.filter, fiber);
        publication.result.* = .waiting;
    } else if (thread.wait_queues.count() >= thread.wait_queue_limit) {
        publication.result.* = .system_resources;
    } else {
        const gop = thread.wait_queues.getOrPutAssumeCapacity(key);
        assert(!gop.found_existing);
        gop.value_ptr.* = .{ .head = fiber, .tail = fiber };
        registerFd(thread, key.ident, key.filter, fiber);
        publication.result.* = .waiting;
    }
    const schedule_immediately = publication.result.* != .waiting;
    thread.mutex.unlock();

    if (schedule_immediately) {
        loop.schedule(thread, .{ .head = fiber, .tail = fiber });
    }
}

fn appendWaiter(wait_queue: *Thread.WaitQueue, fiber: *Fiber) void {
    // An empty entry marks an existing persistent poller registration.
    if (wait_queue.tail) |tail| {
        tail.queue_next = fiber;
        wait_queue.tail = fiber;
    } else {
        assert(wait_queue.head == null);
        wait_queue.* = .{ .head = fiber, .tail = fiber };
    }
}

fn registerFd(thread: *Thread, ident: usize, filter: Poll.Filter, fiber: *Fiber) void {
    thread.poll.register(ident, filter, @intFromPtr(fiber));
}

fn removeWaitingFiber(loop: *EventLoop, fiber: *Fiber) bool {
    const active_threads = @atomicLoad(u32, &loop.threads.active, .acquire);
    for (loop.threads.allocated[0..active_threads]) |*thread| {
        lockThread(thread);

        var index: usize = 0;
        while (index < thread.wait_queues.count()) {
            switch (waitQueueRemoveFiber(&thread.wait_queues.values()[index], fiber)) {
                .not_found => {},
                // Persistent edge-triggered registration: leave the entry
                // in place even if its queue is now empty. The poller
                // registration outlives any individual waiter; we only
                // tear it down on FD close (see `wakeFd`).
                .removed, .emptied => {
                    thread.mutex.unlock();
                    return true;
                },
            }
            index += 1;
        }

        thread.mutex.unlock();
    }

    return false;
}

fn wakeFd(loop: *EventLoop, fd: posix.fd_t) void {
    assert(fd >= 0);

    const ident: usize = @intCast(fd);
    const active_threads = @atomicLoad(u32, &loop.threads.active, .acquire);
    for (loop.threads.allocated[0..active_threads]) |*thread| {
        lockThread(thread);

        var index: usize = 0;
        while (index < thread.wait_queues.count()) {
            if (thread.wait_queues.keys()[index].ident == ident) {
                const wait_queue = thread.wait_queues.values()[index];
                thread.wait_queues.swapRemoveAt(index);
                if (wait_queue.head) |head| {
                    scheduleReadyQueueOnThread(thread, .{
                        .head = head,
                        .tail = wait_queue.tail.?,
                    });
                }
                continue;
            }
            index += 1;
        }

        thread.mutex.unlock();
    }
}

fn scheduleReadyQueueOnThread(thread: *Thread, ready_queue: Fiber.Queue) void {
    assert(ready_queue.tail.queue_next == null);

    waitForReadyQueue(thread);
    var expected: ?*Fiber = null;
    while (true) {
        if (@cmpxchgWeak(
            ?*Fiber,
            &thread.ready_queue,
            expected,
            ready_queue.head,
            .release,
            .monotonic,
        )) |old_head| {
            if (old_head == Fiber.finished) {
                waitForReadyQueue(thread);
                expected = null;
            } else {
                ready_queue.tail.queue_next = old_head;
                expected = old_head;
            }
            continue;
        }
        break;
    }

    wakeThread(thread);
}

fn wakeThread(thread: *Thread) void {
    signalThread(thread, .wakeup);
}

fn signalThreadExit(thread: *Thread) void {
    signalThread(thread, .exit);
}

fn signalThread(thread: *Thread, message: Signal) void {
    thread.poll.signal(message);
}

const WaitQueueRemove = enum {
    not_found,
    removed,
    emptied,
};

fn waitQueueRemoveFiber(wait_queue: *Thread.WaitQueue, fiber: *Fiber) WaitQueueRemove {
    const head = wait_queue.head orelse return .not_found;
    if (head == fiber) {
        wait_queue.head = fiber.queue_next;
        if (fiber.queue_next == null) wait_queue.tail = null;
        fiber.queue_next = null;
        return if (wait_queue.head == null) .emptied else .removed;
    }

    var previous = head;
    while (previous.queue_next) |next| {
        if (next == fiber) {
            previous.queue_next = fiber.queue_next;
            if (wait_queue.tail == fiber) {
                wait_queue.tail = previous;
            }
            fiber.queue_next = null;
            return .removed;
        }
        previous = next;
    }

    return .not_found;
}

const SwitchMessage = struct {
    contexts: Io.fiber.Switch,
    pending_task: PendingTask,

    const PendingTask = union(enum) {
        nothing,
        reschedule,
        complete_group: GroupCompletion,
        register_awaiter: *?*Fiber,
        publish_wait: WaitPublication,
        exit,
    };

    fn handle(message: *const SwitchMessage, loop: *EventLoop) void {
        const thread: *Thread = .current();
        thread.current_context = message.contexts.new;
        switch (message.pending_task) {
            .nothing => {},
            .reschedule => if (message.contexts.old != &thread.idle_context) {
                const prev_fiber: *Fiber = @alignCast(@fieldParentPtr(
                    "context",
                    message.contexts.old,
                ));
                assert(prev_fiber.queue_next == null);
                loop.schedule(thread, .{ .head = prev_fiber, .tail = prev_fiber });
            },
            .complete_group => |completion| {
                completeGroupFiber(loop, completion);
            },
            .register_awaiter => |awaiter| {
                const prev_fiber: *Fiber = @alignCast(@fieldParentPtr(
                    "context",
                    message.contexts.old,
                ));
                assert(prev_fiber.queue_next == null);
                if (@atomicRmw(?*Fiber, awaiter, .Xchg, prev_fiber, .acq_rel) == Fiber.finished)
                    loop.schedule(thread, .{ .head = prev_fiber, .tail = prev_fiber });
            },
            .publish_wait => |publication| {
                const prev_fiber: *Fiber = @alignCast(@fieldParentPtr(
                    "context",
                    message.contexts.old,
                ));
                publishWait(loop, thread, prev_fiber, publication);
            },
            .exit => {
                const active_threads = @atomicLoad(u32, &loop.threads.active, .acquire);
                for (loop.threads.allocated[0..active_threads]) |*each_thread| {
                    signalThreadExit(each_thread);
                }
            },
        }
    }
};

inline fn contextSwitch(message: *const SwitchMessage) *const SwitchMessage {
    return @fieldParentPtr("contexts", Io.fiber.contextSwitch(&message.contexts));
}

fn mainIdleEntry() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ movq (%%rsp), %%rdi
            \\ jmp %[mainIdle:P]
            :
            : [mainIdle] "X" (&mainIdle),
        ),
        .aarch64 => asm volatile (
            \\ ldr x0, [sp, #-8]
            \\ b %[mainIdle]
            :
            : [mainIdle] "X" (&mainIdle),
        ),
        else => |arch| @compileError("unimplemented architecture: " ++ @tagName(arch)),
    }
}

fn fiberEntry() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ leaq 8(%%rsp), %%rdi
            \\ jmp %[AsyncClosure_call:P]
            :
            : [AsyncClosure_call] "X" (&AsyncClosure.call),
        ),
        .aarch64 => asm volatile (
            \\ mov x0, sp
            \\ b %[AsyncClosure_call]
            :
            : [AsyncClosure_call] "X" (&AsyncClosure.call),
        ),
        else => |arch| @compileError("unimplemented architecture: " ++ @tagName(arch)),
    }
}

const AsyncClosure = struct {
    kqueue: *EventLoop,
    fiber: *Fiber,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
    result_align: Alignment,
    already_awaited: bool,

    fn contextPointer(
        closure: *AsyncClosure,
    ) [*]align(Fiber.max_context_align.toByteUnits()) u8 {
        return @alignCast(@as([*]u8, @ptrCast(closure)) + @sizeOf(AsyncClosure));
    }

    fn call(
        closure: *AsyncClosure,
        message: *const SwitchMessage,
    ) callconv(.withStackAlign(.c, @alignOf(AsyncClosure))) noreturn {
        message.handle(closure.kqueue);
        const fiber = closure.fiber;
        std.log.debug("{*} performing async", .{fiber});
        closure.start(closure.contextPointer(), fiber.resultBytes(closure.result_align));
        const awaiter = @atomicRmw(?*Fiber, &fiber.awaiter, .Xchg, Fiber.finished, .acq_rel);
        const ready_awaiter = r: {
            const a = awaiter orelse break :r null;
            if (@atomicRmw(bool, &closure.already_awaited, .Xchg, true, .acq_rel)) break :r null;
            break :r a;
        };
        closure.kqueue.yield(ready_awaiter, .nothing);
        unreachable; // switched to dead fiber
    }

    fn fromFiber(fiber: *Fiber) *AsyncClosure {
        return @ptrFromInt(Fiber.max_context_align.max(.of(AsyncClosure)).backward(
            @intFromPtr(fiber.allocatedEnd()) - Fiber.max_context_size,
        ) - @sizeOf(AsyncClosure));
    }
};

const GroupAsyncClosure = struct {
    kqueue: *EventLoop,
    fiber: *Fiber,
    group: *Io.Group,
    start: *const fn (context: *const anyopaque) void,

    fn contextPointer(
        closure: *GroupAsyncClosure,
    ) [*]align(Fiber.max_context_align.toByteUnits()) u8 {
        return @alignCast(@as([*]u8, @ptrCast(closure)) + @sizeOf(GroupAsyncClosure));
    }

    fn call(
        closure: *GroupAsyncClosure,
        message: *const SwitchMessage,
    ) callconv(.withStackAlign(.c, @alignOf(GroupAsyncClosure))) noreturn {
        message.handle(closure.kqueue);
        const fiber = closure.fiber;
        closure.start(closure.contextPointer());
        closure.kqueue.yield(null, .{ .complete_group = .{
            .fiber = fiber,
            .group = closure.group,
        } });
        unreachable;
    }

    fn fromFiber(fiber: *Fiber) *GroupAsyncClosure {
        return @ptrFromInt(Fiber.max_context_align.max(.of(GroupAsyncClosure)).backward(
            @intFromPtr(fiber.allocatedEnd()) - Fiber.max_context_size,
        ) - @sizeOf(GroupAsyncClosure));
    }
};

fn groupFiberEntry() callconv(.naked) void {
    switch (builtin.cpu.arch) {
        .x86_64 => asm volatile (
            \\ leaq 8(%%rsp), %%rdi
            \\ jmp %[GroupAsyncClosure_call:P]
            :
            : [GroupAsyncClosure_call] "X" (&GroupAsyncClosure.call),
        ),
        .aarch64 => asm volatile (
            \\ mov x0, sp
            \\ b %[GroupAsyncClosure_call]
            :
            : [GroupAsyncClosure_call] "X" (&GroupAsyncClosure.call),
        ),
        else => |arch| @compileError("unimplemented architecture: " ++ @tagName(arch)),
    }
}

fn completeGroupFiber(loop: *EventLoop, completion: GroupCompletion) void {
    const fiber = completion.fiber;
    const group = completion.group;
    lockGroup(group);
    defer unlockGroup(group);

    var previous: ?*Fiber = @ptrCast(@alignCast(@atomicLoad(
        ?*anyopaque,
        &group.token.raw,
        .acquire,
    )));
    if (previous == fiber) {
        const next = fiber.group_next;
        if (next != null) {
            @atomicStore(?*anyopaque, &group.token.raw, next, .release);
        }
        fiber.group_next = null;
        loop.recycle(fiber);
        if (next == null) {
            @atomicStore(?*anyopaque, &group.token.raw, null, .release);
        }
        return;
    }
    while (previous) |candidate| {
        if (candidate.group_next == fiber) {
            candidate.group_next = fiber.group_next;
            fiber.group_next = null;
            loop.recycle(fiber);
            return;
        }
        previous = candidate.group_next;
    }

    @panic("EventLoop group lost a live fiber");
}

const GroupState = extern struct {
    mutex: std.atomic.Mutex,
    cancel_requested: bool,
};

comptime {
    assert(@sizeOf(GroupState) <= @sizeOf(usize));
    assert(@alignOf(GroupState) <= @alignOf(usize));
    assert(@intFromEnum(std.atomic.Mutex.unlocked) == 0);
}

fn groupState(group: *Io.Group) *GroupState {
    return @ptrCast(&group.state);
}

fn lockGroup(group: *Io.Group) void {
    lockMutex(&groupState(group).mutex);
}

fn unlockGroup(group: *Io.Group) void {
    groupState(group).mutex.unlock();
}

// This EventLoop backend is a local fork of `std.Io.EventLoop` from zig 0.16.0,
// patched so the HTTP/2 server can run on an evented (kqueue) reactor
// instead of one OS thread per accepted connection.
//
// Why fork: the upstream backend is incomplete on 0.16.0. It is missing
// many `std.Io.VTable` slots and still names a few legacy slots
// (`fileWriteStreaming`, `fileReadStreaming`, `netReceive`) that no longer
// exist on `std.Io.VTable`, so the upstream file fails to compile against
// the current vtable shape.
//
// Strategy: derive the vtable from `std.Io.failing` so every slot has a
// defined value (returning errors or panicking when invoked), then override
// only the slots this backend implements natively. Any code path that
// lands on a non-overridden slot will surface the upstream `failing`
// behavior at runtime rather than miscompile at build time. Hot paths used
// by the HTTP/2 server (accept / read / write / shutdown / close) must be
// among the overridden slots — see the assertions further below.
//
// TODO replace this fork once upstream lands a complete kqueue backend.
// Until then, port missing primitives from
// https://github.com/mitchellh/libxev/blob/main/src/backend/kqueue.zig
// while preserving the `std.Io.VTable` interface.
pub fn io(loop: *EventLoop) Io {
    return .{
        .userdata = loop,
        .vtable = &vtable,
    };
}

const vtable: Io.VTable = blk: {
    var vt = Io.failing.vtable.*;

    vt.async = async;
    vt.concurrent = concurrent;
    vt.await = await;
    vt.cancel = cancel;
    vt.checkCancel = ioCheckCancel;

    vt.groupAsync = groupAsync;
    vt.groupConcurrent = groupConcurrent;
    vt.groupAwait = groupAwait;
    vt.groupCancel = groupCancel;

    // Slots backed by real kqueue / posix code in this file. Anything not
    // listed here intentionally falls back to `std.Io.failing` until the
    // upstream backend is completed.
    vt.netListenIp = netListenIp;
    vt.netAccept = netAccept;
    vt.netBindIp = netBindIp;
    vt.netConnectIp = netConnectIp;
    vt.netRead = netRead;
    vt.netWrite = netWrite;
    vt.netSend = netSend;
    vt.netClose = netClose;
    vt.netShutdown = netShutdown;

    break :blk vt;
};

fn async(
    userdata: ?*anyopaque,
    result: []u8,
    result_alignment: std.mem.Alignment,
    context: []const u8,
    context_alignment: std.mem.Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) ?*Io.AnyFuture {
    return concurrent(
        userdata,
        result.len,
        result_alignment,
        context,
        context_alignment,
        start,
    ) catch {
        start(context.ptr, result.ptr);
        return null;
    };
}

fn concurrent(
    userdata: ?*anyopaque,
    result_len: usize,
    result_alignment: Alignment,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque, result: *anyopaque) void,
) Io.ConcurrentError!*Io.AnyFuture {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    assert(result_alignment.compare(.lte, Fiber.max_result_align)); // TODO
    assert(context_alignment.compare(.lte, Fiber.max_context_align)); // TODO
    assert(result_len <= Fiber.max_result_size); // TODO
    assert(context.len <= Fiber.max_context_size); // TODO

    const fiber = try Fiber.allocate(loop);
    std.log.debug("allocated {*}", .{fiber});

    const closure: *AsyncClosure = .fromFiber(fiber);
    fiber.* = .{
        .required_align = {},
        .context = switch (builtin.cpu.arch) {
            .x86_64 => .{
                .rsp = @intFromPtr(closure) - @sizeOf(usize),
                .rbp = 0,
                .rip = @intFromPtr(&fiberEntry),
            },
            .aarch64 => .{
                .sp = @intFromPtr(closure),
                .fp = 0,
                .pc = @intFromPtr(&fiberEntry),
            },
            else => |arch| @compileError("unimplemented architecture: " ++ @tagName(arch)),
        },
        .awaiter = null,
        .queue_next = null,
        .group_next = null,
        .cancel_thread = null,
        .awaiting_completions = .empty,
    };
    closure.* = .{
        .kqueue = loop,
        .fiber = fiber,
        .start = start,
        .result_align = result_alignment,
        .already_awaited = false,
    };
    @memcpy(closure.contextPointer(), context);

    loop.schedule(.current(), .{ .head = fiber, .tail = fiber });
    return @ptrCast(fiber);
}

fn await(
    userdata: ?*anyopaque,
    any_future: *Io.AnyFuture,
    result: []u8,
    result_alignment: std.mem.Alignment,
) void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    const future_fiber: *Fiber = @ptrCast(@alignCast(any_future));
    if (@atomicLoad(?*Fiber, &future_fiber.awaiter, .acquire) != Fiber.finished)
        loop.yield(null, .{ .register_awaiter = &future_fiber.awaiter });
    @memcpy(result, future_fiber.resultBytes(result_alignment));
    loop.recycle(future_fiber);
}

fn cancel(
    userdata: ?*anyopaque,
    any_future: *Io.AnyFuture,
    result: []u8,
    result_alignment: std.mem.Alignment,
) void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    const future_fiber: *Fiber = @ptrCast(@alignCast(any_future));
    _ = @cmpxchgStrong(
        ?*Thread,
        &future_fiber.cancel_thread,
        null,
        Thread.canceling,
        .acq_rel,
        .acquire,
    );
    if (@atomicLoad(?*Fiber, &future_fiber.awaiter, .acquire) != Fiber.finished)
        loop.yield(null, .{ .register_awaiter = &future_fiber.awaiter });
    @memcpy(result, future_fiber.resultBytes(result_alignment));
    loop.recycle(future_fiber);
}

fn cancelRequested(userdata: ?*anyopaque) bool {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    const thread: *Thread = .current();
    if (thread.current_context == &thread.idle_context) return false;
    const fiber = thread.currentFiber();
    return @atomicLoad(?*Thread, &fiber.cancel_thread, .acquire) == Thread.canceling;
}

fn groupAsync(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) void {
    groupConcurrent(userdata, type_erased, context, context_alignment, start) catch {
        start(context.ptr);
    };
}

fn groupConcurrent(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    context: []const u8,
    context_alignment: Alignment,
    start: *const fn (context: *const anyopaque) void,
) Io.ConcurrentError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    assert(context_alignment.compare(.lte, Fiber.max_context_align));
    assert(context.len <= Fiber.max_context_size);

    const fiber = try Fiber.allocate(loop);

    const closure: *GroupAsyncClosure = .fromFiber(fiber);
    fiber.* = .{
        .required_align = {},
        .context = switch (builtin.cpu.arch) {
            .x86_64 => .{
                .rsp = @intFromPtr(closure) - @sizeOf(usize),
                .rbp = 0,
                .rip = @intFromPtr(&groupFiberEntry),
            },
            .aarch64 => .{
                .sp = @intFromPtr(closure),
                .fp = 0,
                .pc = @intFromPtr(&groupFiberEntry),
            },
            else => |arch| @compileError("unimplemented architecture: " ++ @tagName(arch)),
        },
        .awaiter = null,
        .queue_next = null,
        .group_next = null,
        .cancel_thread = null,
        .awaiting_completions = .empty,
    };
    closure.* = .{
        .kqueue = loop,
        .fiber = fiber,
        .group = type_erased,
        .start = start,
    };
    @memcpy(closure.contextPointer(), context);

    lockGroup(type_erased);
    if (groupState(type_erased).cancel_requested) {
        fiber.cancel_thread = Thread.canceling;
    }
    const old = @atomicLoad(?*anyopaque, &type_erased.token.raw, .acquire);
    fiber.group_next = @ptrCast(@alignCast(old));
    @atomicStore(?*anyopaque, &type_erased.token.raw, fiber, .release);
    unlockGroup(type_erased);

    loop.schedule(.current(), .{ .head = fiber, .tail = fiber });
}

fn groupAwait(
    userdata: ?*anyopaque,
    type_erased: *Io.Group,
    initial_token: *anyopaque,
) Io.Cancelable!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    while (true) {
        while (@atomicLoad(?*anyopaque, &type_erased.token.raw, .acquire) != null) {
            loop.checkCancel() catch {
                groupCancel(userdata, type_erased, initial_token);
                return error.Canceled;
            };
            yield(loop, null, .reschedule);
        }

        lockGroup(type_erased);
        const complete = @atomicLoad(
            ?*anyopaque,
            &type_erased.token.raw,
            .acquire,
        ) == null;
        unlockGroup(type_erased);
        if (complete) return;
    }
}

fn groupCancel(userdata: ?*anyopaque, group: *Io.Group, token: *anyopaque) void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = token;

    var ready_queue: ?Fiber.Queue = null;
    lockGroup(group);
    groupState(group).cancel_requested = true;
    var fiber: ?*Fiber = @ptrCast(@alignCast(@atomicLoad(
        ?*anyopaque,
        &group.token.raw,
        .acquire,
    )));
    while (fiber) |f| {
        const next = f.group_next;
        _ = @cmpxchgStrong(
            ?*Thread,
            &f.cancel_thread,
            null,
            Thread.canceling,
            .acq_rel,
            .acquire,
        );
        if (loop.removeWaitingFiber(f)) {
            if (ready_queue) |*queue| {
                queue.tail.queue_next = f;
                queue.tail = f;
            } else {
                ready_queue = .{ .head = f, .tail = f };
            }
        }
        fiber = next;
    }
    unlockGroup(group);

    const thread: *Thread = .current();
    if (ready_queue) |queue| {
        const ready_fiber = queue.head;
        if (ready_fiber.queue_next) |next_ready_fiber| {
            ready_fiber.queue_next = null;
            loop.schedule(thread, .{
                .head = next_ready_fiber,
                .tail = queue.tail,
            });
        }
        loop.yield(ready_fiber, .reschedule);
    }
    finishGroupCancellation(loop, group);
}

fn finishGroupCancellation(loop: *EventLoop, group: *Io.Group) void {
    while (true) {
        while (@atomicLoad(?*anyopaque, &group.token.raw, .acquire) != null) {
            loop.yield(null, .reschedule);
        }

        lockGroup(group);
        if (@atomicLoad(?*anyopaque, &group.token.raw, .acquire) == null) {
            groupState(group).cancel_requested = false;
            unlockGroup(group);
            return;
        }
        unlockGroup(group);
    }
}

fn groupCompletionTask(completed: *std.atomic.Value(usize)) Io.Cancelable!void {
    _ = completed.fetchAdd(1, .seq_cst);
}

test "group list remains consistent during concurrent completion" {
    const tasks_per_round = 64;
    const rounds = 32;

    var loop: EventLoop = undefined;
    try loop.init(std.heap.c_allocator, .{
        .n_threads = 4,
        .max_concurrent_tasks = tasks_per_round,
        .max_wait_registrations_per_thread = 1,
    });
    defer loop.deinit();
    try loop.attachCurrentThread();
    defer loop.detachCurrentThread();

    const evented_io = loop.io();
    var completed: std.atomic.Value(usize) = .init(0);
    for (0..rounds) |round| {
        var group: Io.Group = .init;
        errdefer group.cancel(evented_io);
        for (0..tasks_per_round) |_| {
            try group.concurrent(evented_io, groupCompletionTask, .{&completed});
        }
        try group.await(evented_io);
        try std.testing.expectEqual(
            (round + 1) * tasks_per_round,
            completed.load(.seq_cst),
        );
    }
}

fn groupCancellationTask(
    loop: *EventLoop,
    canceled: *std.atomic.Value(usize),
) Io.Cancelable!void {
    while (true) {
        loop.checkCancel() catch {
            _ = canceled.fetchAdd(1, .seq_cst);
            return error.Canceled;
        };
        std.Thread.yield() catch {};
    }
}

test "group cancellation remains consistent with concurrent completion" {
    const task_count = 32;

    var loop: EventLoop = undefined;
    try loop.init(std.heap.c_allocator, .{
        .n_threads = 4,
        .max_concurrent_tasks = task_count,
        .max_wait_registrations_per_thread = 1,
    });
    defer loop.deinit();
    try loop.attachCurrentThread();
    defer loop.detachCurrentThread();

    const evented_io = loop.io();
    var canceled: std.atomic.Value(usize) = .init(0);
    var group: Io.Group = .init;
    for (0..task_count) |_| {
        try group.concurrent(evented_io, groupCancellationTask, .{ &loop, &canceled });
    }
    group.cancel(evented_io);

    try std.testing.expectEqual(task_count, canceled.load(.seq_cst));
    try std.testing.expectEqual(@as(?*anyopaque, null), group.token.load(.acquire));
}

const SpawnDuringCancellationContext = struct {
    loop: *EventLoop,
    io: Io,
    group: *Io.Group,
    started: *std.atomic.Value(bool),
    child_canceled: *std.atomic.Value(bool),
    child_missed_cancel: *std.atomic.Value(bool),
};

fn childAddedDuringCancellation(context: *SpawnDuringCancellationContext) Io.Cancelable!void {
    context.loop.checkCancel() catch {
        context.child_canceled.store(true, .release);
        return error.Canceled;
    };
    context.child_missed_cancel.store(true, .release);
}

fn spawnAfterCancellationRequest(context: *SpawnDuringCancellationContext) Io.Cancelable!void {
    context.started.store(true, .release);
    while (true) {
        context.loop.checkCancel() catch break;
        std.Thread.yield() catch {};
    }
    context.group.concurrent(
        context.io,
        childAddedDuringCancellation,
        .{context},
    ) catch {
        context.child_missed_cancel.store(true, .release);
        return error.Canceled;
    };
    return error.Canceled;
}

test "concurrent group member inherits cancellation" {
    var loop: EventLoop = undefined;
    try loop.init(std.heap.c_allocator, .{
        .n_threads = 2,
        .max_concurrent_tasks = 2,
        .max_wait_registrations_per_thread = 1,
    });
    defer loop.deinit();
    try loop.attachCurrentThread();
    defer loop.detachCurrentThread();

    const evented_io = loop.io();
    var group: Io.Group = .init;
    var started: std.atomic.Value(bool) = .init(false);
    var child_canceled: std.atomic.Value(bool) = .init(false);
    var child_missed_cancel: std.atomic.Value(bool) = .init(false);
    var context: SpawnDuringCancellationContext = .{
        .loop = &loop,
        .io = evented_io,
        .group = &group,
        .started = &started,
        .child_canceled = &child_canceled,
        .child_missed_cancel = &child_missed_cancel,
    };
    try group.concurrent(evented_io, spawnAfterCancellationRequest, .{&context});
    while (!started.load(.acquire)) std.Thread.yield() catch {};
    group.cancel(evented_io);

    try std.testing.expect(child_canceled.load(.acquire));
    try std.testing.expect(!child_missed_cancel.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), group.state);

    var reused_count: std.atomic.Value(usize) = .init(0);
    try group.concurrent(evented_io, groupCompletionTask, .{&reused_count});
    try group.await(evented_io);
    try std.testing.expectEqual(@as(usize, 1), reused_count.load(.seq_cst));
}

fn dirCreateDir(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
) Dir.CreateDirError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = permissions;
    @panic("TODO");
}

fn dirCreateDirPath(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
) Dir.CreateDirPathError!Dir.CreatePathStatus {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = permissions;
    @panic("TODO");
}

fn dirCreateDirPathOpen(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    permissions: Dir.Permissions,
    options: Dir.OpenOptions,
) Dir.CreateDirPathOpenError!Dir {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = permissions;
    _ = options;
    @panic("TODO");
}

fn dirStat(userdata: ?*anyopaque, dir: Dir) Dir.StatError!Dir.Stat {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    @panic("TODO");
}

fn dirStatFile(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.StatFileOptions,
) Dir.StatFileError!File.Stat {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = options;
    @panic("TODO");
}
fn dirAccess(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.AccessOptions,
) Dir.AccessError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = options;
    @panic("TODO");
}
fn dirCreateFile(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.CreateFlags,
) File.OpenError!File {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = flags;
    @panic("TODO");
}
fn dirOpenFile(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    flags: File.OpenFlags,
) File.OpenError!File {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = flags;
    @panic("TODO");
}
fn dirOpenDir(
    userdata: ?*anyopaque,
    dir: Dir,
    sub_path: []const u8,
    options: Dir.OpenOptions,
) Dir.OpenError!Dir {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dir;
    _ = sub_path;
    _ = options;
    @panic("TODO");
}
fn dirClose(userdata: ?*anyopaque, dirs: []const Dir) void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = dirs;
    @panic("TODO");
}
fn fileStat(userdata: ?*anyopaque, file: File) File.StatError!File.Stat {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    @panic("TODO");
}

fn fileClose(userdata: ?*anyopaque, files: []const File) void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = files;
    @panic("TODO");
}

fn fileWriteStreaming(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) File.Writer.Error!usize {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    _ = header;
    _ = data;
    _ = splat;
    @panic("TODO");
}

fn fileWritePositional(
    userdata: ?*anyopaque,
    file: File,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
    offset: u64,
) File.WritePositionalError!usize {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    _ = header;
    _ = data;
    _ = splat;
    _ = offset;
    @panic("TODO");
}

fn fileReadStreaming(
    userdata: ?*anyopaque,
    file: File,
    data: []const []u8,
) File.Reader.Error!usize {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    _ = data;
    @panic("TODO");
}

fn fileReadPositional(
    userdata: ?*anyopaque,
    file: File,
    data: []const []u8,
    offset: u64,
) File.ReadPositionalError!usize {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    _ = data;
    _ = offset;
    @panic("TODO");
}
fn fileSeekBy(userdata: ?*anyopaque, file: File, relative_offset: i64) File.SeekError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    _ = relative_offset;
    @panic("TODO");
}
fn fileSeekTo(userdata: ?*anyopaque, file: File, absolute_offset: u64) File.SeekError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = file;
    _ = absolute_offset;
    @panic("TODO");
}

fn now(userdata: ?*anyopaque, clock: Io.Clock) Io.Clock.Error!Io.Timestamp {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = clock;
    @panic("TODO");
}
fn sleep(userdata: ?*anyopaque, timeout: Io.Timeout) Io.SleepError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = timeout;
    @panic("TODO");
}

fn netListenIp(
    userdata: ?*anyopaque,
    address: *const net.IpAddress,
    options: net.IpAddress.ListenOptions,
) net.IpAddress.ListenError!net.Socket {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    const family = Io.Threaded.posixAddressFamily(address);
    const socket_fd = try openSocketPosix(loop, family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer closeFd(socket_fd);

    if (options.reuse_address) {
        try setSocketOption(loop, socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, 1);
        if (@hasDecl(posix.SO, "REUSEPORT")) {
            setSocketOption(loop, socket_fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, 1) catch {};
        }
    }

    var storage: Io.Threaded.PosixAddress = undefined;
    var addr_len = Io.Threaded.addressToPosix(address, &storage);
    try posixBind(loop, socket_fd, &storage.any, addr_len);

    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.listen(socket_fd, options.kernel_backlog))) {
            .SUCCESS => break,
            .INTR => continue,
            .CANCELED => return error.Canceled,
            .ADDRINUSE => return error.AddressInUse,
            .BADF => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err),
            .NOTSOCK => |err| return errnoBug(err),
            .OPNOTSUPP => return error.SocketModeUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    try posixGetSockName(loop, socket_fd, &storage.any, &addr_len);
    return .{
        .handle = socket_fd,
        .address = Io.Threaded.addressFromPosix(&storage),
    };
}

fn netAccept(
    userdata: ?*anyopaque,
    server: net.Socket.Handle,
    options: net.Server.AcceptOptions,
) net.Server.AcceptError!net.Socket {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = options;

    var storage: Io.Threaded.PosixAddress = undefined;
    var addr_len: posix.socklen_t = @sizeOf(@TypeOf(storage));

    while (true) {
        try loop.checkCancel();
        const rc = posix.system.accept(server, &storage.any, &addr_len);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const new_fd: posix.fd_t = @intCast(rc);
                errdefer closeFd(new_fd);

                if (Io.Threaded.socket_flags_unsupported) {
                    while (true) {
                        try loop.checkCancel();
                        switch (posix.errno(posix.system.fcntl(
                            new_fd,
                            posix.F.SETFD,
                            @as(usize, posix.FD_CLOEXEC),
                        ))) {
                            .SUCCESS => break,
                            .INTR => continue,
                            .CANCELED => return error.Canceled,
                            else => |err| return posix.unexpectedErrno(err),
                        }
                    }
                }
                try setNonBlocking(loop, new_fd);

                return .{
                    .handle = new_fd,
                    .address = Io.Threaded.addressFromPosix(&storage),
                };
            },
            .INTR => continue,
            .CANCELED => return error.Canceled,
            .AGAIN => {
                try loop.waitForFd(server, .read);
                addr_len = @sizeOf(@TypeOf(storage));
                continue;
            },

            .BADF => return error.SocketNotListening,
            .FAULT => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err),
            .NOTSOCK => |err| return errnoBug(err),
            .OPNOTSUPP => return error.ProtocolFailure,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NETDOWN => return error.NetworkDown,
            .CONNABORTED => return error.ConnectionAborted,
            .PERM => return error.BlockedByFirewall,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}
fn netBindIp(
    userdata: ?*anyopaque,
    address: *const net.IpAddress,
    options: net.IpAddress.BindOptions,
) net.IpAddress.BindError!net.Socket {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    const family = Io.Threaded.posixAddressFamily(address);
    const socket_fd = try openSocketPosix(loop, family, options);
    errdefer closeFd(socket_fd);
    var storage: Io.Threaded.PosixAddress = undefined;
    var addr_len = Io.Threaded.addressToPosix(address, &storage);
    try posixBind(loop, socket_fd, &storage.any, addr_len);
    if (options.allow_broadcast) {
        try setSocketOption(loop, socket_fd, posix.SOL.SOCKET, posix.SO.BROADCAST, 1);
    }
    try posixGetSockName(loop, socket_fd, &storage.any, &addr_len);
    return .{ .handle = socket_fd, .address = Io.Threaded.addressFromPosix(&storage) };
}
fn netConnectIp(
    userdata: ?*anyopaque,
    address: *const net.IpAddress,
    options: net.IpAddress.ConnectOptions,
) net.IpAddress.ConnectError!net.Socket {
    if (options.timeout != .none) @panic("TODO");
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    const family = Io.Threaded.posixAddressFamily(address);
    const socket_fd = try openSocketPosix(loop, family, .{
        .mode = options.mode,
        .protocol = options.protocol,
    });
    errdefer closeFd(socket_fd);
    var storage: Io.Threaded.PosixAddress = undefined;
    var addr_len = Io.Threaded.addressToPosix(address, &storage);
    try posixConnect(loop, socket_fd, &storage.any, addr_len);
    try posixGetSockName(loop, socket_fd, &storage.any, &addr_len);
    return .{ .handle = socket_fd, .address = Io.Threaded.addressFromPosix(&storage) };
}

fn posixConnect(
    loop: *EventLoop,
    socket_fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.connect(socket_fd, addr, addr_len))) {
            .SUCCESS => return,
            .INTR => continue,
            .CANCELED => return error.Canceled,
            .AGAIN => @panic("TODO"),
            .INPROGRESS => return, // Due to TCP fast open, we find out possible error later.

            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .ALREADY => return error.ConnectionPending,
            .BADF => |err| return errnoBug(err), // File descriptor used after closed.
            .CONNREFUSED => return error.ConnectionRefused,
            .CONNRESET => return error.ConnectionResetByPeer,
            .FAULT => |err| return errnoBug(err),
            .ISCONN => |err| return errnoBug(err),
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTSOCK => |err| return errnoBug(err),
            .PROTOTYPE => |err| return errnoBug(err),
            .TIMEDOUT => return error.Timeout,
            .CONNABORTED => |err| return errnoBug(err),
            .ACCES => return error.AccessDenied,
            .PERM => |err| return errnoBug(err),
            .NOENT => |err| return errnoBug(err),
            .NETDOWN => return error.NetworkDown,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn netListenUnix(
    userdata: ?*anyopaque,
    unix_address: *const net.UnixAddress,
    options: net.UnixAddress.ListenOptions,
) net.UnixAddress.ListenError!net.Socket.Handle {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = unix_address;
    _ = options;
    @panic("TODO");
}
fn netConnectUnix(
    userdata: ?*anyopaque,
    unix_address: *const net.UnixAddress,
) net.UnixAddress.ConnectError!net.Socket.Handle {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = unix_address;
    @panic("TODO");
}

fn netSend(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    outgoing_messages: []net.OutgoingMessage,
    flags: net.SendFlags,
) struct { ?net.Socket.SendError, usize } {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));

    const posix_flags: u32 =
        @as(u32, if (@hasDecl(posix.MSG, "CONFIRM") and flags.confirm)
            posix.MSG.CONFIRM
        else
            0) |
        @as(u32, if (@hasDecl(posix.MSG, "DONTROUTE") and flags.dont_route)
            posix.MSG.DONTROUTE
        else
            0) |
        @as(u32, if (@hasDecl(posix.MSG, "EOR") and flags.eor) posix.MSG.EOR else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "OOB") and flags.oob) posix.MSG.OOB else 0) |
        @as(u32, if (@hasDecl(posix.MSG, "FASTOPEN") and flags.fastopen)
            posix.MSG.FASTOPEN
        else
            0) |
        posix.MSG.NOSIGNAL;

    for (outgoing_messages, 0..) |*msg, i| {
        netSendOne(loop, handle, msg, posix_flags) catch |err| return .{ err, i };
    }

    return .{ null, outgoing_messages.len };
}

fn netSendOne(
    loop: *EventLoop,
    handle: net.Socket.Handle,
    message: *net.OutgoingMessage,
    flags: u32,
) net.Socket.SendError!void {
    var addr: Io.Threaded.PosixAddress = undefined;
    var iovec: posix.iovec_const = .{
        .base = @constCast(message.data_ptr),
        .len = message.data_len,
    };
    const msg: posix.msghdr_const = .{
        .name = &addr.any,
        .namelen = Io.Threaded.addressToPosix(message.address, &addr),
        .iov = (&iovec)[0..1],
        .iovlen = 1,
        // OS returns EINVAL if this pointer is invalid even if controllen is zero.
        .control = if (message.control.len == 0) null else @constCast(message.control.ptr),
        .controllen = @intCast(message.control.len),
        .flags = 0,
    };
    while (true) {
        try loop.checkCancel();
        const rc = posix.system.sendmsg(handle, &msg, flags);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                message.data_len = @intCast(rc);
                return;
            },
            .INTR => continue,
            .CANCELED => return error.Canceled,
            .AGAIN => @panic("TODO register poller interest"),

            .ACCES => return error.AccessDenied,
            .ALREADY => return error.FastOpenAlreadyInProgress,
            .BADF => |err| return errnoBug(err), // File descriptor used after closed.
            .CONNRESET => return error.ConnectionResetByPeer,
            .DESTADDRREQ => |err| return errnoBug(err),
            .FAULT => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err),
            .ISCONN => |err| return errnoBug(err),
            .MSGSIZE => return error.MessageOversize,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTSOCK => |err| return errnoBug(err),
            .OPNOTSUPP => |err| return errnoBug(err),
            .PIPE => return error.SocketUnconnected,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTCONN => return error.SocketUnconnected,
            .NETDOWN => return error.NetworkDown,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn netReceive(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    message_buffer: []net.IncomingMessage,
    data_buffer: []u8,
    flags: net.ReceiveFlags,
    timeout: Io.Timeout,
) struct { ?net.Socket.ReceiveTimeoutError, usize } {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = handle;
    _ = message_buffer;
    _ = data_buffer;
    _ = flags;
    _ = timeout;
    @panic("TODO");
}

fn netRead(
    userdata: ?*anyopaque,
    fd: net.Socket.Handle,
    data: [][]u8,
) net.Stream.Reader.Error!usize {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));

    var iovecs_buffer: [max_iovecs_len]posix.iovec = undefined;
    var i: usize = 0;
    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    const dest = iovecs_buffer[0..i];
    assert(dest[0].len > 0);

    while (true) {
        try loop.checkCancel();
        const rc = posix.system.readv(fd, dest.ptr, @intCast(dest.len));
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .CANCELED => return error.Canceled,
            .AGAIN => {
                try loop.waitForFd(fd, .read);
                continue;
            },

            .INVAL => |err| return errnoBug(err),
            .FAULT => |err| return errnoBug(err),
            .BADF => |err| return errnoBug(err), // File descriptor used after closed.
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketUnconnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .TIMEDOUT => return error.Timeout,
            .PIPE => return error.SocketUnconnected,
            .NETDOWN => return error.NetworkDown,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn netWrite(
    userdata: ?*anyopaque,
    dest: net.Socket.Handle,
    header: []const u8,
    data: []const []const u8,
    splat: usize,
) net.Stream.Writer.Error!usize {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));

    var iovecs_buffer: [max_iovecs_len + 2]posix.iovec_const = undefined;
    var i: usize = 0;

    if (header.len > 0) {
        iovecs_buffer[i] = .{ .base = header.ptr, .len = header.len };
        i += 1;
    }

    for (data) |buf| {
        if (iovecs_buffer.len - i == 0) break;
        if (buf.len != 0) {
            iovecs_buffer[i] = .{ .base = buf.ptr, .len = buf.len };
            i += 1;
        }
    }
    for (0..@min(iovecs_buffer.len - i, splat)) |_| {
        if (data.len == 0) break;
        const last = data[data.len - 1];
        if (last.len == 0) break;
        iovecs_buffer[i] = .{ .base = last.ptr, .len = last.len };
        i += 1;
    }

    const src = iovecs_buffer[0..i];
    if (src.len == 0) return @as(usize, 0);

    while (true) {
        try loop.checkCancel();
        const rc = posix.system.writev(dest, src.ptr, @intCast(src.len));
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .CANCELED => return error.Canceled,
            .AGAIN => {
                try loop.waitForFd(dest, .write);
                continue;
            },

            .INVAL => |err| return errnoBug(err),
            .FAULT => |err| return errnoBug(err),
            .BADF => |err| return errnoBug(err),
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTCONN => return error.SocketUnconnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .PIPE => return error.SocketNotBound,
            .NETDOWN => return error.NetworkDown,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .CONNREFUSED => return error.ConnectionRefused,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn netClose(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    for (handles) |handle| {
        loop.wakeFd(handle);
        closeFd(handle);
    }
}

fn netShutdown(
    userdata: ?*anyopaque,
    handle: net.Socket.Handle,
    how: net.ShutdownHow,
) net.ShutdownError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;

    const posix_how: i32 = switch (how) {
        .recv => posix.SHUT.RD,
        .send => posix.SHUT.WR,
        .both => posix.SHUT.RDWR,
    };

    while (true) {
        const rc = posix.system.shutdown(handle, posix_how);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            .BADF => |err| return errnoBug(err),
            .NOTSOCK => |err| return errnoBug(err),
            .NOTCONN => return error.SocketUnconnected,
            .CONNRESET => return error.ConnectionResetByPeer,
            .CONNABORTED => return error.ConnectionAborted,
            .NETDOWN => return error.NetworkDown,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn netInterfaceNameResolve(
    userdata: ?*anyopaque,
    name: *const net.Interface.Name,
) net.Interface.Name.ResolveError!net.Interface {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = name;
    @panic("TODO");
}

fn netInterfaceName(
    userdata: ?*anyopaque,
    interface: net.Interface,
) net.Interface.NameError!net.Interface.Name {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = interface;
    @panic("TODO");
}

fn netLookup(
    userdata: ?*anyopaque,
    host_name: net.HostName,
    resolved: *Io.Queue(net.HostName.LookupResult),
    options: net.HostName.LookupOptions,
) net.HostName.LookupError!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    _ = loop;
    _ = host_name;
    _ = resolved;
    _ = options;
    @panic("TODO");
}

fn openSocketPosix(
    loop: *EventLoop,
    family: posix.sa_family_t,
    options: IpAddress.BindOptions,
) error{
    AddressFamilyUnsupported,
    ProtocolUnsupportedBySystem,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolUnsupportedByAddressFamily,
    SocketModeUnsupported,
    OptionUnsupported,
    Unexpected,
    Canceled,
}!posix.socket_t {
    const mode, const protocol = try posixSocketModeProtocol(
        family,
        options.mode,
        options.protocol,
    );
    const socket_fd = while (true) {
        try loop.checkCancel();
        const flags: u32 = mode | if (Io.Threaded.socket_flags_unsupported)
            0
        else
            posix.SOCK.CLOEXEC;
        const socket_rc = posix.system.socket(family, flags, protocol);
        switch (posix.errno(socket_rc)) {
            .SUCCESS => {
                const fd: posix.fd_t = @intCast(socket_rc);
                errdefer closeFd(fd);
                if (Io.Threaded.socket_flags_unsupported) {
                    try setCloseOnExec(loop, fd);
                }
                try setNonBlocking(loop, fd);
                break fd;
            },
            .INTR => continue,
            .CANCELED => return error.Canceled,

            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .INVAL => return error.ProtocolUnsupportedBySystem,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            .PROTOTYPE => return error.SocketModeUnsupported,
            else => |err| return posix.unexpectedErrno(err),
        }
    };
    errdefer closeFd(socket_fd);

    if (options.ip6_only) {
        if (posix.IPV6 == void) return error.OptionUnsupported;
        try setSocketOption(loop, socket_fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, 0);
    }

    return socket_fd;
}

fn setCloseOnExec(loop: *EventLoop, fd: posix.fd_t) !void {
    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.fcntl(
            fd,
            posix.F.SETFD,
            @as(usize, posix.FD_CLOEXEC),
        ))) {
            .SUCCESS => return,
            .INTR => continue,
            .CANCELED => return error.Canceled,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn posixBind(
    loop: *EventLoop,
    socket_fd: posix.socket_t,
    addr: *const posix.sockaddr,
    addr_len: posix.socklen_t,
) !void {
    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.bind(socket_fd, addr, addr_len))) {
            .SUCCESS => break,
            .INTR => continue,
            .CANCELED => return error.Canceled,

            .ADDRINUSE => return error.AddressInUse,
            .BADF => |err| return errnoBug(err), // File descriptor used after closed.
            .INVAL => |err| return errnoBug(err), // invalid parameters
            .NOTSOCK => |err| return errnoBug(err), // invalid `sockfd`
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .ADDRNOTAVAIL => return error.AddressUnavailable,
            .FAULT => |err| return errnoBug(err), // invalid `addr` pointer
            .NOMEM => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn posixGetSockName(
    loop: *EventLoop,
    socket_fd: posix.fd_t,
    addr: *posix.sockaddr,
    addr_len: *posix.socklen_t,
) !void {
    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.getsockname(socket_fd, addr, addr_len))) {
            .SUCCESS => break,
            .INTR => continue,
            .CANCELED => return error.Canceled,

            .BADF => |err| return errnoBug(err), // File descriptor used after closed.
            .FAULT => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err), // invalid parameters
            .NOTSOCK => |err| return errnoBug(err), // always a race condition
            .NOBUFS => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn setSocketOption(loop: *EventLoop, fd: posix.fd_t, level: i32, opt_name: u32, option: u32) !void {
    const o: []const u8 = @ptrCast(&option);
    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.setsockopt(fd, level, opt_name, o.ptr, @intCast(o.len)))) {
            .SUCCESS => return,
            .INTR => continue,
            .CANCELED => return error.Canceled,

            .BADF => |err| return errnoBug(err), // File descriptor used after closed.
            .NOTSOCK => |err| return errnoBug(err),
            .INVAL => |err| return errnoBug(err),
            .FAULT => |err| return errnoBug(err),
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn setNonBlocking(loop: *EventLoop, fd: posix.fd_t) !void {
    var flags: usize = while (true) {
        try loop.checkCancel();
        const rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
        switch (posix.errno(rc)) {
            .SUCCESS => break @intCast(rc),
            .INTR => continue,
            .CANCELED => return error.Canceled,
            else => |err| return posix.unexpectedErrno(err),
        }
    };
    flags |= @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));

    while (true) {
        try loop.checkCancel();
        switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFL, flags))) {
            .SUCCESS => return,
            .INTR => continue,
            .CANCELED => return error.Canceled,
            else => |err| return posix.unexpectedErrno(err),
        }
    }
}

fn checkCancel(loop: *EventLoop) error{Canceled}!void {
    if (cancelRequested(loop)) return error.Canceled;
}

fn ioCheckCancel(userdata: ?*anyopaque) Io.Cancelable!void {
    const loop: *EventLoop = @ptrCast(@alignCast(userdata));
    try loop.checkCancel();
}
