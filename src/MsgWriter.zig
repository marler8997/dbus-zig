const MsgWriter = @This();

interface: std.Io.Writer,
err: ?Error = null,
net_stream: std.net.Stream,

control: ?cmsg.Array = null,

pub const Error = std.posix.WriteError;

pub fn init(net_stream: std.net.Stream, buffer: []u8) MsgWriter {
    return .{
        .interface = .{
            .vtable = &.{ .drain = drain },
            .buffer = buffer,
        },
        .net_stream = net_stream,
    };
}

const max_buffers_len = 16;

fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
    const w: *MsgWriter = @alignCast(@fieldParentPtr("interface", io_w));
    const handle = w.net_stream.handle;
    const buffered = io_w.buffered();
    var iovecs: [max_buffers_len]std.posix.iovec_const = undefined;

    var len: usize = 0;
    if (buffered.len > 0) {
        iovecs[len] = .{ .base = buffered.ptr, .len = buffered.len };
        len += 1;
    }
    for (data[0 .. data.len - 1]) |d| {
        if (d.len == 0) continue;
        iovecs[len] = .{ .base = d.ptr, .len = d.len };
        len += 1;
        if (iovecs.len - len == 0) break;
    }
    const pattern = data[data.len - 1];

    var backup_buffer: [64]u8 = undefined;
    if (iovecs.len - len != 0) switch (splat) {
        0 => {},
        1 => if (pattern.len != 0) {
            iovecs[len] = .{ .base = pattern.ptr, .len = pattern.len };
            len += 1;
        },
        else => switch (pattern.len) {
            0 => {},
            1 => {
                const splat_buffer_candidate = io_w.buffer[io_w.end..];
                const splat_buffer = if (splat_buffer_candidate.len >= backup_buffer.len)
                    splat_buffer_candidate
                else
                    &backup_buffer;
                const memset_len = @min(splat_buffer.len, splat);
                const buf = splat_buffer[0..memset_len];
                @memset(buf, pattern[0]);
                iovecs[len] = .{ .base = buf.ptr, .len = buf.len };
                len += 1;
                var remaining_splat = splat - buf.len;
                while (remaining_splat > splat_buffer.len and iovecs.len - len != 0) {
                    std.debug.assert(buf.len == splat_buffer.len);
                    iovecs[len] = .{ .base = splat_buffer.ptr, .len = splat_buffer.len };
                    len += 1;
                    remaining_splat -= splat_buffer.len;
                }
                if (remaining_splat > 0 and iovecs.len - len != 0) {
                    iovecs[len] = .{ .base = splat_buffer.ptr, .len = remaining_splat };
                    len += 1;
                }
            },
            else => for (0..splat) |_| {
                iovecs[len] = .{ .base = pattern.ptr, .len = pattern.len };
                len += 1;
                if (iovecs.len - len == 0) break;
            },
        },
    };
    if (len == 0) return 0;

    while (true) {
        var msg = std.os.linux.msghdr_const{
            .name = null,
            .namelen = 0,
            .iov = &iovecs,
            .iovlen = len,
            .control = if (w.control) |*control| control.ptr else null,
            .controllen = if (w.control) |*control| control.size else 0,
            .flags = 0,
        };
        const rc = std.os.linux.sendmsg(handle, &msg, std.os.linux.MSG.NOSIGNAL);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                // only send FDs once
                w.control = null;
                return io_w.consume(rc);
            },
            .ACCES => unreachable,
            .AGAIN => {
                w.err = error.WouldBlock;
                return error.WriteFailed;
            },
            .ALREADY => unreachable,
            .BADF => unreachable, // always a race condition
            .CONNRESET => {
                w.err = error.ConnectionResetByPeer;
                return error.WriteFailed;
            },
            .DESTADDRREQ => unreachable,
            .FAULT => unreachable,
            .INTR => continue,
            .INVAL => unreachable,
            .ISCONN => unreachable,
            .MSGSIZE => unreachable,
            .NOBUFS => {
                w.err = error.SystemResources;
                return error.WriteFailed;
            },
            .NOMEM => {
                w.err = error.SystemResources;
                return error.WriteFailed;
            },
            .NOTSOCK => unreachable,
            .OPNOTSUPP => unreachable,
            .PIPE => {
                w.err = error.BrokenPipe;
                return error.WriteFailed;
            },
            .NETDOWN, .NETUNREACH => {
                w.err = error.BrokenPipe;
                return error.WriteFailed;
            },
            .NOTCONN => {
                w.err = error.BrokenPipe;
                return error.WriteFailed;
            },
            else => |err| {
                w.err = std.posix.unexpectedErrno(err);
                return error.WriteFailed;
            },
        }
    }
}

const std = @import("std");
const cmsg = @import("cmsg.zig");
