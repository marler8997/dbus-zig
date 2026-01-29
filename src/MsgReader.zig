const MsgReader = @This();

interface_state: std.Io.Reader,
err: ?Error = null,
net_stream: std.net.Stream,

unix_fds: UnixFds = .{ .array = @splat(-1) },

const max_fd_count = 2;

const msgfdlog = std.log.scoped(.msgfd);

pub const Error = std.net.Stream.ReadError;

/// Number of slices to store on the stack, when trying to send as many byte
/// vectors through the underlying read calls as possible.
const max_buffers_len = 16;

pub fn init(net_stream: std.net.Stream, buffer: []u8) MsgReader {
    return .{
        .interface_state = .{
            .vtable = &.{
                .stream = streamImpl,
                .discard = discard,
                .readVec = readVec,
            },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
        .net_stream = net_stream,
    };
}

pub fn deinit(r: *MsgReader) void {
    for (r.unix_fds.array) |fd| {
        if (fd != -1) std.posix.close(fd);
    }
    r.* = undefined;
}

pub fn interface(r: *MsgReader) *std.Io.Reader {
    return &r.interface_state;
}

pub fn getStream(r: *const MsgReader) std.net.Stream {
    return r.net_stream;
}

fn streamImpl(io_reader: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const dest = limit.slice(try w.writableSliceGreedy(1));
    var bufs: [1][]u8 = .{dest};
    const n = try readVec(io_reader, &bufs);
    w.advance(n);
    return n;
}

fn discard(io_reader: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
    const r: *MsgReader = @alignCast(@fieldParentPtr("interface_state", io_reader));
    var trash_buffer: [128]u8 = undefined;
    var iovecs: [max_buffers_len]std.posix.iovec = undefined;
    var iovecs_i: usize = 0;
    var remaining = @intFromEnum(limit);
    while (remaining > 0 and iovecs_i < iovecs.len) {
        iovecs[iovecs_i] = .{ .base = &trash_buffer, .len = @min(trash_buffer.len, remaining) };
        remaining -= iovecs[iovecs_i].len;
        iovecs_i += 1;
    }
    const n = std.posix.readv(r.net_stream.handle, iovecs[0..iovecs_i]) catch |err| {
        r.err = err;
        return error.ReadFailed;
    };
    return if (n == 0) error.EndOfStream else n;
}
fn readVec(io_reader: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
    const r: *MsgReader = @alignCast(@fieldParentPtr("interface_state", io_reader));
    var iovecs_buffer: [max_buffers_len]std.posix.iovec = undefined;
    const dest_n, const data_size = try io_reader.writableVectorPosix(&iovecs_buffer, data);
    std.debug.assert(iovecs_buffer[0].len > 0);

    var fd_recv: FdRecv = undefined;
    while (true) {
        var msg = std.os.linux.msghdr{
            .name = null,
            .namelen = 0,
            .iov = &iovecs_buffer,
            .iovlen = dest_n,
            .control = @ptrCast(&fd_recv),
            .controllen = @sizeOf(@TypeOf(fd_recv)),
            .flags = 0,
        };
        const rc = std.os.linux.recvmsg(r.net_stream.handle, &msg, 0);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                r.updateFds(&fd_recv, msg.controllen);
                if (rc == 0) {
                    return error.EndOfStream;
                }
                // If we read more than the user's data slices can hold,
                // the excess went into the internal buffer
                if (rc > data_size) {
                    io_reader.end += rc - data_size;
                    return data_size;
                }
                return rc;
            },
            .BADF => unreachable, // always a race condition
            .FAULT => unreachable,
            .INVAL => unreachable,
            .NOTCONN => {
                r.err = error.SocketNotConnected;
                return error.ReadFailed;
            },
            .NOTSOCK => unreachable,
            .INTR => continue,
            .AGAIN => {
                r.err = error.WouldBlock;
                return error.ReadFailed;
            },
            .NOMEM => {
                r.err = error.SystemResources;
                return error.ReadFailed;
            },
            .CONNRESET => {
                r.err = error.ConnectionResetByPeer;
                return error.ReadFailed;
            },
            .TIMEDOUT => {
                r.err = error.ConnectionTimedOut;
                return error.ReadFailed;
            },
            else => |err| {
                r.err = std.posix.unexpectedErrno(err);
                return error.ReadFailed;
            },
        }
    }
}

fn updateFds(r: *MsgReader, fd_recv: *const FdRecv, msg_controllen: usize) void {
    if (msg_controllen == 0) return;
    std.debug.assert(msg_controllen >= @sizeOf(cmsg.Header));
    std.debug.assert(fd_recv.size >= @sizeOf(cmsg.Header));
    std.debug.assert(fd_recv.level == std.os.linux.SOL.SOCKET);
    std.debug.assert(fd_recv.type == SCM.RIGHTS);
    const fd_data_size = fd_recv.size - @sizeOf(cmsg.Header);
    var fd_index: usize = 0;
    while (fd_index * @sizeOf(std.posix.fd_t) < fd_data_size) : (fd_index += 1) {
        std.debug.assert((fd_index + 1) * @sizeOf(std.posix.fd_t) <= fd_data_size);
        const fd = fd_recv.data[fd_index];
        std.debug.assert(fd != -1);
        if (fd_index >= max_fd_count) {
            msgfdlog.debug("fd[{}] would be {} but index exceeds max", .{ fd_index, fd });
            std.posix.close(fd);
            continue;
        }
        if (r.unix_fds.array[fd_index] != -1) {
            msgfdlog.debug(
                "fd[{}] = {} (replacing {})",
                .{ fd_index, fd, r.unix_fds.array[fd_index] },
            );
            std.posix.close(r.unix_fds.array[fd_index]);
        } else {
            msgfdlog.debug("fd[{}] = {}", .{ fd_index, fd });
        }
        r.unix_fds.array[fd_index] = fd;
    }

    // ensure there's no more cmsg data we aren't handling
    const end = std.mem.alignForward(usize, fd_recv.size, @alignOf(cmsg.Header));
    std.debug.assert(msg_controllen == end);
}

pub const UnixFds = struct {
    array: [max_fd_count]std.posix.fd_t,

    pub fn take(fds: *UnixFds, index: anytype) ?std.posix.fd_t {
        if (@TypeOf(index) != usize) return fds.take(std.math.cast(usize, index) orelse return null);
        if (index >= max_fd_count) return null;
        if (fds.array[index] == -1) return null;
        const fd = fds.array[index];
        fds.array[index] = -1;
        return fd;
    }
};

const FdRecv = struct {
    const unpadded_size = @sizeOf(cmsg.Header) + @sizeOf([max_fd_count]std.posix.fd_t);
    const padded_size = std.mem.alignForward(usize, unpadded_size, @alignOf(cmsg.Header));

    size: usize = unpadded_size,
    level: c_int,
    type: c_int,
    data: [max_fd_count]std.posix.fd_t,
    padding: [padded_size - unpadded_size]u8 = undefined,
};
comptime {
    std.debug.assert(@offsetOf(cmsg.Header, "size") == @offsetOf(FdRecv, "size"));
    std.debug.assert(@offsetOf(cmsg.Header, "level") == @offsetOf(FdRecv, "level"));
    std.debug.assert(@offsetOf(cmsg.Header, "type") == @offsetOf(FdRecv, "type"));
    std.debug.assert(@sizeOf(FdRecv) == FdRecv.padded_size);
}

pub const SCM = struct {
    pub const RIGHTS = 1;
};

const std = @import("std");
const cmsg = @import("cmsg.zig");
