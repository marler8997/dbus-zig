const Connection = @This();

const std = @import("std");
const os = std.os;

const address_mod = @import("address.zig");
const Address = address_mod.Address;

fd: std.os.fd_t,

pub const ConnectError = error{
    DbusAddrUnixPathTooBig,
    DBusAddrBadEscapeSequence,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    AddressInUse,
    ConnectionRefused,
    ConnectionTimedOut,
    FileNotFound,
};

pub fn connect(addr: Address) ConnectError!Connection {
    switch (addr) {
        .unix => |unix_addr| {
            var sockaddr = os.sockaddr.un{ .family = os.AF.UNIX, .path = undefined };
            const path_len = address_mod.resolveEscapes(&sockaddr.path, unix_addr.unescaped_path) catch |err| switch (err) {
                error.DestTooSmall => return error.DbusAddrUnixPathTooBig,
                error.BadEscapeSequence => return error.DBusAddrBadEscapeSequence,
            };
            if (path_len == sockaddr.path.len) return error.DbusAddrUnixPathTooBig;
            sockaddr.path[path_len] = 0;

            const sock = os.socket(os.AF.UNIX, os.SOCK.STREAM, 0) catch |err| switch (err) {
                error.PermissionDenied,
                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                error.SystemResources,
                => |e| return e,
                error.ProtocolFamilyNotAvailable,
                error.AddressFamilyNotSupported,
                error.ProtocolNotSupported,
                error.SocketTypeNotSupported,
                error.Unexpected,
                => unreachable,
            };
            errdefer os.close(sock);

            const addr_len: os.socklen_t = @intCast(@offsetOf(os.sockaddr.un, "path") + path_len + 1);

            // TODO: should we set any socket options?
            os.connect(sock, @as(*os.sockaddr, @ptrCast(&sockaddr)), addr_len) catch |err| switch (err) {
                error.PermissionDenied,
                error.AddressInUse,
                error.SystemResources,
                error.ConnectionRefused,
                error.ConnectionTimedOut,
                error.FileNotFound,
                => |e| return e,
                error.Unexpected => @panic("unexpected errno from connect"),
                error.AddressNotAvailable, // doesn't apply to unix sockets
                error.NetworkUnreachable, // doesn't apply to unix sockets (I think)
                error.ConnectionResetByPeer, // doesn't applyt to unix sockets
                error.WouldBlock, // shouldn't happen to a blocking socket
                error.ConnectionPending, // shouldn't happen to a blocking socket
                error.AddressFamilyNotSupported,
                => unreachable,
            };
            return Connection{ .fd = sock };
        },
    }
}

pub const Writer = std.io.Writer(Connection, std.os.WriteError, write);
pub fn writer(self: Connection) Writer {
    return .{ .context = self };
}
fn write(self: Connection, buf: []const u8) std.os.WriteError!usize {
    return std.os.write(self.fd, buf);
}

pub const Reader = std.io.Reader(Connection, std.os.ReadError, read);
pub fn reader(self: Connection) Reader {
    return .{ .context = self };
}
fn read(self: Connection, buf: []u8) std.os.ReadError!usize {
    return std.os.read(self.fd, buf);
}

pub fn authenticate(self: Connection) !void {
    {
        var msg_buf: [100]u8 = undefined;
        const msg = blk: {
            //const include_uid = false;
            //if (!include_uid) break :blk "\x00AUTH EXTERNAL\r\n";
            var uid_str_buf: [40]u8 = undefined;
            const uid = std.os.system.getuid();
            const uid_str = std.fmt.bufPrint(&uid_str_buf, " {}", .{uid}) catch |err| switch (err) {
                error.NoSpaceLeft => unreachable,
            };
            break :blk std.fmt.bufPrint(&msg_buf, "\x00AUTH EXTERNAL {}\r\n", .{std.fmt.fmtSliceHexLower(uid_str)}) catch |err| switch (err) {
                error.NoSpaceLeft => unreachable,
            };
        };
        std.log.info("sending '{}'", .{std.zig.fmtEscapes(msg)});
        try self.writer().writeAll(msg);
    }

    while (true) {
        var buf: [100]u8 = undefined;
        std.log.info("reading reply...", .{});
        const reply = self.reader().readUntilDelimiter(&buf, '\n') catch |err| switch (err) {
            error.StreamTooLong => return error.MalformedReply,
            else => |e| return e,
        };
        std.log.info("reply is '{}'", .{std.zig.fmtEscapes(reply)});
        if (std.mem.startsWith(u8, reply, "OK ")) {
            // should include a guid, maybe we don't need it though?
            break;
        } else if (std.mem.startsWith(u8, reply, "REJECTED ")) {
            // TODO: maybe fallback to other auth mechanisms?
            return error.AuthenticationRejected;
        } else {
            std.log.info("unhandled reply from server '{s}'", .{reply});
            return error.UnhandledReply;
        }
    }
    try self.writer().writeAll("BEGIN\r\n");
}
