const zig_atleast_15 = builtin.zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

pub const ReadError = posix.ReadError || error{
    SocketNotBound,
    MessageTooBig,
    NetworkSubsystemFailed,
    ConnectionResetByPeer,
    SocketNotConnected,
};

const max_buffers_len = 8;

pub const Reader = if (zig_atleast_15) std.net.Stream.Reader else struct {
    interface_state: Io.Reader,
    net_stream: Stream,
    error_state: ?Error,

    pub const Error = ReadError;

    pub fn getStream(r: *const Reader) Stream {
        return r.net_stream;
    }
    pub fn getError(r: *const Reader) ?Error {
        return r.error_state;
    }
    pub fn interface(r: *Reader) *Io.Reader {
        return &r.interface_state;
    }

    pub fn init(net_stream: Stream, buffer: []u8) Reader {
        return .{
            .interface_state = .{
                .vtable = &.{
                    .stream = stream,
                    .readVec = readVec,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .net_stream = net_stream,
            .error_state = null,
        };
    }

    fn stream(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        if (builtin.os.tag == .windows) {
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            var bufs: [1][]u8 = .{dest};
            const n = try readVec(io_r, &bufs);
            io_w.advance(n);
            return n;
        } else {
            const r: *Reader = @alignCast(@fieldParentPtr("interface_state", io_r));
            const dest = limit.slice(try io_w.writableSliceGreedy(1));
            const n = try readStreaming(r, dest);
            io_w.advance(n);
            return n;
        }
    }

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        if (builtin.os.tag == .windows) {
            const r: *Reader = @alignCast(@fieldParentPtr("interface_state", io_r));
            var iovecs: [max_buffers_len]windows.ws2_32.WSABUF = undefined;
            const bufs_n, const data_size = try io_r.writableVectorWsa(&iovecs, data);
            const bufs = iovecs[0..bufs_n];
            assert(bufs[0].len != 0);
            const n = streamBufs(r, bufs) catch |err| {
                r.error_state = err;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            if (n > data_size) {
                io_r.end += n - data_size;
                return data_size;
            }
            return n;
        } else {
            const r: *Reader = @alignCast(@fieldParentPtr("interface_state", io_r));
            var iovecs_buffer: [max_buffers_len]posix.iovec = undefined;
            const dest_n, const data_size = try io_r.writableVectorPosix(&iovecs_buffer, data);
            const dest = iovecs_buffer[0..dest_n];
            assert(dest[0].len > 0);
            const n = posix.readv(r.net_stream.handle, dest) catch |err| {
                r.error_state = err;
                return error.ReadFailed;
            };
            if (n == 0) {
                // r.size = r.pos;
                return error.EndOfStream;
            }
            // r.pos += n;
            if (n > data_size) {
                io_r.end += n - data_size;
                return data_size;
            }
            return n;
        }
    }

    fn handleRecvError(winsock_error: windows.ws2_32.WinsockError) Error!void {
        switch (winsock_error) {
            .WSAECONNRESET => return error.ConnectionResetByPeer,
            .WSAEFAULT => unreachable, // a pointer is not completely contained in user address space.
            .WSAEINPROGRESS, .WSAEINTR => unreachable, // deprecated and removed in WSA 2.2
            .WSAEINVAL => return error.SocketNotBound,
            .WSAEMSGSIZE => return error.MessageTooBig,
            .WSAENETDOWN => return error.NetworkSubsystemFailed,
            .WSAENETRESET => return error.ConnectionResetByPeer,
            .WSAENOTCONN => return error.SocketNotConnected,
            .WSAEWOULDBLOCK => return error.WouldBlock,
            .WSANOTINITIALISED => unreachable, // WSAStartup must be called before this function
            .WSA_IO_PENDING => unreachable,
            .WSA_OPERATION_ABORTED => unreachable, // not using overlapped I/O
            else => |err| return windows.unexpectedWSAError(err),
        }
    }

    fn streamBufs(r: *Reader, bufs: []windows.ws2_32.WSABUF) Error!u32 {
        var flags: u32 = 0;
        var overlapped: windows.OVERLAPPED = std.mem.zeroes(windows.OVERLAPPED);

        var n: u32 = undefined;
        if (windows.ws2_32.WSARecv(
            r.net_stream.handle,
            bufs.ptr,
            @intCast(bufs.len),
            &n,
            &flags,
            &overlapped,
            null,
        ) == windows.ws2_32.SOCKET_ERROR) switch (windows.ws2_32.WSAGetLastError()) {
            .WSA_IO_PENDING => {
                var result_flags: u32 = undefined;
                if (windows.ws2_32.WSAGetOverlappedResult(
                    r.net_stream.handle,
                    &overlapped,
                    &n,
                    windows.TRUE,
                    &result_flags,
                ) == windows.FALSE) try handleRecvError(windows.ws2_32.WSAGetLastError());
            },
            else => |winsock_error| try handleRecvError(winsock_error),
        };

        return n;
    }

    pub fn readStreaming(r: *Reader, dest: []u8) Io.Reader.Error!usize {
        const n = r.net_stream.read(dest) catch |err| {
            r.error_state = err;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        return n;
    }
};

const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;
const windows = std.os.windows;
const posix = std.posix;
const File = std.fs.File;
const Io = struct {
    const Limit = if (zig_atleast_15) std.Io.Limit else @import("0.14/limit.zig").Limit;
    const Reader = if (zig_atleast_15) std.Io.Reader else @import("0.14/Reader.zig");
    const Writer = if (zig_atleast_15) std.Io.Writer else @import("0.14/Writer.zig");
};
const Stream = std.net.Stream;
