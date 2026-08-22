//! Epoll readiness poller for `src/io/EventLoop.zig`.
//!
//! One `Instance` belongs to one event-loop thread and owns that thread's
//! epoll descriptor plus the eventfd used to deliver out-of-band signals.
//! Registrations are persistent and edge-triggered, matching the kqueue
//! poller: a descriptor is registered once and stays registered until it is
//! closed.
//!
//! Two differences from kqueue are absorbed here so the scheduler stays
//! platform-neutral:
//!
//! * Epoll holds one interest mask per descriptor rather than one
//!   registration per direction, so a descriptor is armed for both
//!   directions at once and a readiness event fans out to the read queue,
//!   the write queue, or both.
//! * Epoll has no user-triggered filter, so signals are a `pending` bitmask
//!   published before a byte is written to the eventfd. Distinct signals
//!   therefore never coalesce, even though the eventfd counter does.
//!
//! Allocation-free by construction. Every syscall here operates on caller
//! storage or on `Instance` fields, so a poller may be driven after the
//! static allocator is sealed.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const Io = std.Io;
const assert = std.debug.assert;

const closeFd = std.Io.Threaded.closeFd;

// The build always links libc, so epoll and eventfd come from `std.c`. The
// raw `std.os.linux` entry points take different argument types.
comptime {
    if (!builtin.link_libc) @compileError("the epoll poller requires libc");
}

/// Readiness direction. Epoll reports a single mask per descriptor; these
/// values name the queue an event fans out to.
pub const Filter = enum(i16) {
    read,
    write,
};

/// Out-of-band message delivered to a thread's idle loop.
pub const Signal = enum(usize) {
    wakeup = 1,
    cleanup = 2,
    exit = 3,
};

/// Backend-reported readiness detail. Carried to the woken fiber verbatim.
pub const Completion = struct {
    flags: u32,
    fflags: u32,
    data: isize,
};

/// One normalized poller event.
pub const Event = union(enum) {
    signal: Signal,
    ready: Ready,

    pub const Ready = struct {
        ident: usize,
        filter: Filter,
        completion: Completion,
    };
};

/// Kernel events collected by one `epoll_wait`.
const raw_buffer_len = 64;

/// Normalized events one `wait` may report. A descriptor event fans out to at
/// most two entries and the eventfd to at most three, so this bounds the
/// worst-case expansion of `raw_buffer_len` kernel events.
pub const wait_buffer_len = 2 * raw_buffer_len + 4;

/// Interest mask every descriptor is registered with. Edge-triggered, both
/// directions, plus peer shutdown so a half-closed socket wakes its reader.
const interest_mask: u32 = linux.EPOLL.IN |
    linux.EPOLL.OUT |
    linux.EPOLL.ET |
    linux.EPOLL.RDHUP;

/// Bits that make a descriptor readable. Errors and hangups wake both
/// directions so the parked fiber retries and observes the real errno.
const read_mask: u32 = linux.EPOLL.IN |
    linux.EPOLL.RDHUP |
    linux.EPOLL.HUP |
    linux.EPOLL.ERR;

/// Bits that make a descriptor writable.
const write_mask: u32 = linux.EPOLL.OUT |
    linux.EPOLL.HUP |
    linux.EPOLL.ERR;

pub const CreateError = error{
    /// The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,
    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,
    /// No memory was available to create the descriptor.
    SystemResources,
} || Io.UnexpectedError;

pub const WaitError = error{
    /// The process does not have permission to register a filter.
    AccessDenied,
    /// The event could not be found to be modified or deleted.
    EventNotFound,
    /// No memory was available to register the event.
    SystemResources,
    /// The specified process to attach to does not exist.
    ProcessNotFound,
    /// changelist or eventlist had too many items on it.
    Overflow,
};

pub const Instance = struct {
    fd: posix.fd_t,
    signal_fd: posix.fd_t,
    /// One bit per `Signal`, published before the eventfd write so a waking
    /// thread never misses a message that coalesced into the counter.
    pending: std.atomic.Value(u32),

    pub fn init(instance: *Instance) CreateError!void {
        const epoll_fd = try createFileDescriptor();
        errdefer closeFd(epoll_fd);

        const signal_fd = try createSignalDescriptor();
        errdefer closeFd(signal_fd);

        // Level-triggered: the idle loop drains the counter on every wake, so
        // a pending signal keeps re-reporting until it is consumed.
        var event: linux.epoll_event = .{
            .events = linux.EPOLL.IN,
            .data = .{ .fd = signal_fd },
        };
        switch (posix.errno(std.c.epoll_ctl(
            epoll_fd,
            linux.EPOLL.CTL_ADD,
            signal_fd,
            &event,
        ))) {
            .SUCCESS => {},
            .NOMEM, .NOSPC => return error.SystemResources,
            else => |err| return posix.unexpectedErrno(err),
        }

        instance.* = .{
            .fd = epoll_fd,
            .signal_fd = signal_fd,
            .pending = .init(0),
        };
    }

    pub fn deinit(instance: *Instance) void {
        closeFd(instance.signal_fd);
        closeFd(instance.fd);
        instance.* = undefined;
    }

    /// Blocks until at least one event is ready, or until `timeout_ns` elapses
    /// when a timeout is supplied. Returns the number of entries written to
    /// `buffer`.
    pub fn wait(
        instance: *Instance,
        buffer: []Event,
        timeout_ns: ?u64,
    ) WaitError!usize {
        assert(buffer.len >= 3);

        // Reading R kernel events yields at most 2R + 1 normalized events:
        // two per descriptor, and one extra when the eventfd reports all
        // three signals in place of a two-entry descriptor event.
        var raw: [raw_buffer_len]linux.epoll_event = undefined;
        const capacity = @min(raw.len, (buffer.len - 1) / 2);
        assert(capacity > 0);

        const timeout_ms: i32 = if (timeout_ns) |ns|
            std.math.cast(i32, ns / std.time.ns_per_ms) orelse std.math.maxInt(i32)
        else
            -1;

        const count = try epollWait(instance.fd, raw[0..capacity], timeout_ms);

        var written: usize = 0;
        for (raw[0..count]) |event| {
            if (event.data.fd == instance.signal_fd) {
                written += instance.drainSignals(buffer[written..]);
                continue;
            }
            const ident: usize = @intCast(event.data.fd);
            if (event.events & read_mask != 0) {
                buffer[written] = readyEvent(ident, .read, event.events);
                written += 1;
            }
            if (event.events & write_mask != 0) {
                buffer[written] = readyEvent(ident, .write, event.events);
                written += 1;
            }
        }
        return written;
    }

    /// Registers `ident` for `filter`. Epoll carries one interest mask per
    /// descriptor, so the first direction arms both and any later direction
    /// finds the registration already in place.
    ///
    /// The caller invokes this every time a (fd, filter) wait queue goes from
    /// empty to occupied, and expects the call to report readiness that is
    /// already present. Edge-triggered interest does not do that on its own:
    /// arming for a read leaves the descriptor writable with no write waiter,
    /// that edge is dropped, and a later write waiter would never see another
    /// one. `EPOLL_CTL_MOD` re-arms — the kernel re-polls the descriptor and
    /// queues an event when it is currently ready — so the second direction
    /// gets the report `EPOLL_CTL_ADD` refuses to repeat.
    pub fn register(
        instance: *Instance,
        ident: usize,
        filter: Filter,
        user_data: usize,
    ) void {
        _ = filter;
        _ = user_data;

        const fd = std.math.cast(posix.fd_t, ident) orelse {
            @panic("file descriptor out of range for epoll registration");
        };
        var event: linux.epoll_event = .{
            .events = interest_mask,
            .data = .{ .fd = fd },
        };
        switch (posix.errno(std.c.epoll_ctl(
            instance.fd,
            linux.EPOLL.CTL_ADD,
            fd,
            &event,
        ))) {
            .SUCCESS => return,
            // Already armed; re-arm so present readiness is reported again.
            .EXIST => {},
            .NOMEM, .NOSPC => @panic("SystemResources"),
            .PERM => @panic("file descriptor does not support epoll"),
            else => |err| @panic(@tagName(err)),
        }

        switch (posix.errno(std.c.epoll_ctl(
            instance.fd,
            linux.EPOLL.CTL_MOD,
            fd,
            &event,
        ))) {
            .SUCCESS => {},
            .NOMEM, .NOSPC => @panic("SystemResources"),
            // Closed and removed between the two calls; the waiter is woken
            // by `wakeFd` on close.
            .NOENT => {},
            else => |err| @panic(@tagName(err)),
        }
    }

    /// Delivers `message` to the thread owning this instance. Safe to call
    /// from any thread. Distinct signals never coalesce: the bit is published
    /// before the counter is bumped.
    pub fn signal(instance: *Instance, message: Signal) void {
        _ = instance.pending.fetchOr(signalBit(message), .release);

        var counter: u64 = 1;
        const bytes = std.mem.asBytes(&counter);
        while (true) {
            switch (posix.errno(std.c.write(instance.signal_fd, bytes.ptr, bytes.len))) {
                .SUCCESS => return,
                .INTR => continue,
                // The counter saturated; the receiver has not drained it yet,
                // so it is already going to wake and observe the bit.
                .AGAIN => return,
                else => |err| @panic(@tagName(err)),
            }
        }
    }

    /// Consumes the eventfd counter and expands the published bitmask into
    /// one normalized event per distinct signal.
    fn drainSignals(instance: *Instance, buffer: []Event) usize {
        var counter: u64 = undefined;
        const bytes = std.mem.asBytes(&counter);
        while (true) {
            switch (posix.errno(std.c.read(instance.signal_fd, bytes.ptr, bytes.len))) {
                .SUCCESS => break,
                .INTR => continue,
                // Another wake already drained it; the bitmask is still ours.
                .AGAIN => break,
                else => |err| @panic(@tagName(err)),
            }
        }

        const bits = instance.pending.swap(0, .acquire);
        var written: usize = 0;
        for ([_]Signal{ .wakeup, .cleanup, .exit }) |message| {
            if (bits & signalBit(message) == 0) continue;
            assert(written < buffer.len);
            buffer[written] = .{ .signal = message };
            written += 1;
        }
        return written;
    }
};

fn signalBit(message: Signal) u32 {
    return @as(u32, 1) << @intCast(@intFromEnum(message));
}

fn readyEvent(ident: usize, filter: Filter, events: u32) Event {
    return .{ .ready = .{
        .ident = ident,
        .filter = filter,
        .completion = .{
            .flags = events,
            .fflags = 0,
            .data = 0,
        },
    } };
}

fn createFileDescriptor() CreateError!posix.fd_t {
    const rc = std.c.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (posix.errno(rc)) {
        .SUCCESS => return rc,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn createSignalDescriptor() CreateError!posix.fd_t {
    const rc = std.c.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    switch (posix.errno(rc)) {
        .SUCCESS => return rc,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        else => |err| return posix.unexpectedErrno(err),
    }
}

test "arming one direction still reports the other on a later registration" {
    // A descriptor armed for reading is already writable, so its edge-
    // triggered write event fires with nobody waiting and is dropped. The
    // scheduler registers again when a write waiter appears, and that
    // registration has to surface the readiness the dropped edge carried;
    // otherwise the waiter parks until a write edge that never comes.
    var instance: Instance = undefined;
    try instance.init();
    defer instance.deinit();

    var fds: [2]posix.fd_t = undefined;
    try std.testing.expectEqual(
        posix.E.SUCCESS,
        posix.errno(std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds)),
    );
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const ident: usize = @intCast(fds[0]);
    var events: [wait_buffer_len]Event = undefined;

    instance.register(ident, .read, 0);
    _ = try instance.wait(&events, 0);

    instance.register(ident, .write, 0);
    const count = try instance.wait(&events, 0);

    var saw_write = false;
    for (events[0..count]) |event| switch (event) {
        .ready => |ready| saw_write = saw_write or ready.filter == .write,
        .signal => {},
    };
    try std.testing.expect(saw_write);
}

test "distinct signals survive one eventfd wake" {
    var instance: Instance = undefined;
    try instance.init();
    defer instance.deinit();

    instance.signal(.exit);
    instance.signal(.wakeup);

    var events: [wait_buffer_len]Event = undefined;
    const count = try instance.wait(&events, 0);

    var saw_exit = false;
    var saw_wakeup = false;
    for (events[0..count]) |event| switch (event) {
        .signal => |message| {
            saw_exit = saw_exit or message == .exit;
            saw_wakeup = saw_wakeup or message == .wakeup;
        },
        .ready => {},
    };
    try std.testing.expectEqual(2, count);
    try std.testing.expect(saw_exit);
    try std.testing.expect(saw_wakeup);
}

fn epollWait(
    epoll_fd: posix.fd_t,
    events: []linux.epoll_event,
    timeout_ms: i32,
) WaitError!usize {
    while (true) {
        const rc = std.c.epoll_wait(
            epoll_fd,
            events.ptr,
            std.math.cast(c_uint, events.len) orelse return error.Overflow,
            timeout_ms,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue, // TODO handle cancelation
            .BADF => unreachable, // Always a race condition.
            .FAULT => unreachable,
            .INVAL => unreachable,
            else => |err| @panic(@tagName(err)),
        }
    }
}
