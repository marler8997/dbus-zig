const MsgReader = @This();

interface: std.Io.Reader,
err: ?Error = null,
net_stream: std.net.Stream,

recv_buffer_ref: cmsg.RecvBufferRef,
pub const Error = std.net.Stream.ReadError;

/// Number of slices to store on the stack, when trying to send as many byte
/// vectors through the underlying read calls as possible.
const max_buffers_len = 16;

pub fn init(net_stream: std.net.Stream, buffer: []u8, recv_buffer_ref: cmsg.RecvBufferRef) MsgReader {
    return .{
        .interface = .{
            .vtable = &.{
                .stream = streamImpl,
                .discard = discard,
                .readVec = readVec,
                // .rebase = TODO,
                // !!!
            },
            .buffer = buffer,
            .seek = 0,
            .end = 0,
        },
        // .fd_buf = fd_buf,
        .net_stream = net_stream,
        .recv_buffer_ref = recv_buffer_ref,
    };
}

pub fn getStream(r: *const MsgReader) std.net.Stream {
    // return .{ .handle = r.file.handle };
    return r.net_stream;
}

fn streamImpl(io_reader: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = io_reader;
    _ = w;
    _ = limit;
    @panic("todo");
    // const file_reader: *std.fs.File.Reader = @alignCast(@fieldParentPtr("interface", io_reader));
    // const r: *MsgReader = @fieldParentPtr("file_reader", file_reader);
    // return w.sendFile(file_reader, limit) catch |write_err| switch (write_err) {
    //     error.Unimplemented => {
    //         file_reader.mode = file_reader.mode.toReading();
    //         return 0;
    //     },
    //     else => |e| return e,
    // };
}

fn discard(io_reader: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
    // const file_reader: *std.fs.File.Reader = @alignCast(@fieldParentPtr("interface", io_reader));
    // return file_reader.discard(limit);
    // const r: *Reader = @alignCast(@fieldParentPtr("file_reader", file_reader));
    const r: *MsgReader = @fieldParentPtr("interface", io_reader);
    // Unfortunately we can't seek forward without knowing the
    // size because the seek syscalls provided to us will not
    // return the true end position if a seek would exceed the
    // end.
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
    if (n == 0) {
        // r.size = pos;
        return error.EndOfStream;
    }
    // r.pos = pos + n;
    return n;
}
fn readVec(io_reader: *std.Io.Reader, data: [][]u8) std.Io.Reader.Error!usize {
    const r: *MsgReader = @alignCast(@fieldParentPtr("interface", io_reader));
    var iovecs_buffer: [max_buffers_len]std.posix.iovec = undefined;
    const dest_n, const data_size = try io_reader.writableVectorPosix(&iovecs_buffer, data);
    std.debug.assert(iovecs_buffer[0].len > 0);
    while (true) {
        r.recv_buffer_ref.reset();
        var msg = std.os.linux.msghdr{
            .name = null,
            .namelen = 0,
            .iov = &iovecs_buffer,
            .iovlen = dest_n,
            .control = r.recv_buffer_ref.header,
            .controllen = r.recv_buffer_ref.len,
            .flags = 0,
        };
        const rc = std.os.linux.recvmsg(r.net_stream.handle, &msg, 0);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                r.recv_buffer_ref.received(msg.controllen);
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

const std = @import("std");
const cmsg = @import("cmsg.zig");
