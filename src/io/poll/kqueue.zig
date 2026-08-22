//! Kqueue readiness poller for `src/io/EventLoop.zig`.
//!
//! One `Instance` belongs to one event-loop thread and owns that thread's
//! kqueue descriptor. Registrations are persistent and edge-triggered: a
//! descriptor is registered once and stays registered across many events, so
//! the scheduler never re-arms a filter between waits.
//!
//! Allocation-free by construction. Every syscall here operates on caller
//! storage, so a poller may be driven after the static allocator is sealed.

const std = @import("std");
const posix = std.posix;
const Io = std.Io;
const assert = std.debug.assert;

const closeFd = std.Io.Threaded.closeFd;

/// Readiness direction. Kqueue tracks each direction as its own filter, so
/// these map straight onto `EVFILT` values.
pub const Filter = enum(i16) {
    read = std.c.EVFILT.READ,
    write = std.c.EVFILT.WRITE,
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

/// Normalized events one `wait` may report. Kqueue reports one event per
/// registration, so this is also the kernel event-list length.
pub const wait_buffer_len = 64;

pub const CreateError = error{
    /// The per-process limit on the number of open file descriptors has been reached.
    ProcessFdQuotaExceeded,
    /// The system-wide limit on the total number of open files has been reached.
    SystemFdQuotaExceeded,
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

    pub fn init(instance: *Instance) CreateError!void {
        instance.* = .{ .fd = try createFileDescriptor() };
    }

    pub fn deinit(instance: *Instance) void {
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
        assert(buffer.len > 0);

        var events: [wait_buffer_len]posix.Kevent = undefined;
        const capacity = @min(buffer.len, events.len);

        const timeout: ?posix.timespec = if (timeout_ns) |ns| .{
            .sec = @intCast(ns / std.time.ns_per_s),
            .nsec = @intCast(ns % std.time.ns_per_s),
        } else null;
        const timeout_ptr: ?*const posix.timespec = if (timeout) |*value| value else null;

        const count = try kevent(instance.fd, &.{}, events[0..capacity], timeout_ptr);
        for (events[0..count], buffer[0..count]) |event, *normalized| {
            normalized.* = normalize(event);
        }
        return count;
    }

    /// Registers `ident` for `filter`. The registration persists until the
    /// descriptor is closed.
    pub fn register(
        instance: *Instance,
        ident: usize,
        filter: Filter,
        user_data: usize,
    ) void {
        const changes = [_]posix.Kevent{.{
            .ident = ident,
            .filter = @intFromEnum(filter),
            .flags = std.c.EV.ADD | std.c.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = user_data,
        }};
        assert(0 == (kevent(instance.fd, &changes, &.{}, null) catch |err| {
            @panic(@errorName(err));
        }));
    }

    /// Delivers `signal` to the thread owning this instance. Safe to call from
    /// any thread. Distinct signals never coalesce.
    pub fn signal(instance: *Instance, message: Signal) void {
        const changes = [_]posix.Kevent{.{
            .ident = @intFromEnum(message),
            .filter = std.c.EVFILT.USER,
            .flags = std.c.EV.ADD | std.c.EV.ONESHOT,
            .fflags = std.c.NOTE.TRIGGER,
            .data = 0,
            .udata = @intFromEnum(message),
        }};
        _ = kevent(instance.fd, &changes, &.{}, null) catch |err| {
            @panic(@errorName(err));
        };
    }
};

fn normalize(event: posix.Kevent) Event {
    // Signal idents are registered under EVFILT.USER and never collide with a
    // descriptor registration.
    if (event.filter == std.c.EVFILT.USER) {
        return .{ .signal = @enumFromInt(event.udata) };
    }
    return .{ .ready = .{
        .ident = event.ident,
        .filter = @enumFromInt(event.filter),
        .completion = .{
            .flags = event.flags,
            .fflags = event.fflags,
            .data = event.data,
        },
    } };
}

fn createFileDescriptor() CreateError!posix.fd_t {
    const rc = posix.system.kqueue();
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn kevent(
    kq: i32,
    changelist: []const posix.Kevent,
    eventlist: []posix.Kevent,
    timeout: ?*const posix.timespec,
) WaitError!usize {
    while (true) {
        const rc = posix.system.kevent(
            kq,
            changelist.ptr,
            std.math.cast(c_int, changelist.len) orelse return error.Overflow,
            eventlist.ptr,
            std.math.cast(c_int, eventlist.len) orelse return error.Overflow,
            timeout,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .ACCES => return error.AccessDenied,
            .FAULT => unreachable, // TODO use error.Unexpected for these
            .BADF => unreachable, // Always a race condition.
            .INTR => continue, // TODO handle cancelation
            .INVAL => unreachable,
            .NOENT => return error.EventNotFound,
            .NOMEM => return error.SystemResources,
            .SRCH => return error.ProcessNotFound,
            else => unreachable,
        }
    }
}
