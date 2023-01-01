const std = @import("std");
const os = std.os;

const dbus = @import("dbus");

pub fn main() !u8 {

    const path = "/tmp/dbus-test";

    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| {
            std.log.err("failed to remove old socket file '{s}': {s}", .{path, @errorName(e)});
            return 0xff;
        },
    };

    const epoll_fd = os.epoll_create1(os.linux.EPOLL.CLOEXEC) catch |err| {
        std.log.err("epoll_create failed with {s}", .{@errorName(err)});
        return 0xff;
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}) {};
    //defer gpa.deinit();

    var listen_sock_handler: ListenSockHandler = undefined;

    {
        const sock = os.socket(os.AF.UNIX, os.SOCK.STREAM | os.SOCK.NONBLOCK | os.SOCK.CLOEXEC, 0) catch |err| {
            std.log.err("failed to create unix socket: {s}", .{@errorName(err)});
            return 0xff;
        };
        //errdefer os.close(sock);

        var sockaddr = os.sockaddr.un { .family = os.AF.UNIX, .path = undefined };

        const addr_len = @intCast(os.socklen_t, @offsetOf(os.sockaddr.un, "path") + path.len + 1);
        if (addr_len > @sizeOf(os.sockaddr.un)) {
            std.log.err("unix socket path len {} is too big", .{path.len});
            return 0xff;
        }
        @memcpy(&sockaddr.path, path, path.len);
        sockaddr.path[path.len] = 0;

        os.bind(sock, @ptrCast(*os.sockaddr, &sockaddr), addr_len) catch |err| {
            std.log.err("failed to bind unix socket to '{s}': {s}", .{path, @errorName(err)});
            return 0xff;
        };
        std.log.info("bound socket to '{s}'", .{path});

        os.listen(sock, 10) catch |err| {
            std.log.err("unix socket listen failed with {s}", .{@errorName(err)});
            return 0xff;
        };
        listen_sock_handler = .{
            .epoll_fd = epoll_fd,
            .allocator = gpa.allocator(),
            .sock = sock,
        };
        try epollAddHandler(epoll_fd, sock, &listen_sock_handler.base);
    }

    while (true) {
        var events : [10]os.linux.epoll_event = undefined;
        const count = os.epoll_wait(epoll_fd, &events, 0);
        switch (os.errno(count)) {
            .SUCCESS => {},
            else => |e| std.debug.panic("epoll_wait failed, errno={}", .{e}),
        }
        for (events[0..count]) |event| {
            const handler = @intToPtr(*EpollHandler, event.data.ptr);
            handler.handle(handler) catch |err| switch (err) {
                error.Handled => {},
                else => |e| return e,
            };
        }
    }
    return 0;
}

fn epollAddHandler(epoll_fd: os.fd_t, fd: os.fd_t, handler: *EpollHandler) !void {
    var event = os.linux.epoll_event {
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data { .ptr = @ptrToInt(handler) },
    };
    try os.epoll_ctl(epoll_fd, os.linux.EPOLL.CTL_ADD, fd, &event);
}

const EpollHandler = struct {
    handle: *const fn(base: *EpollHandler) anyerror!void,
};

const ListenSockHandler = struct {
    base: EpollHandler = .{ .handle = handle },
    epoll_fd: os.fd_t,
    allocator: std.mem.Allocator,
    sock: os.socket_t,

    fn handle(base: *EpollHandler) !void {
        const self = @fieldParentPtr(ListenSockHandler, "base", base);

        var addr: os.sockaddr.un = undefined;
        var len: os.socklen_t = @sizeOf(@TypeOf(addr));

        const new_fd = os.accept(self.sock, @ptrCast(*os.sockaddr, &addr), &len, os.SOCK.CLOEXEC) catch |err| switch (err) {
            error.ConnectionAborted,
            error.ProcessFdQuotaExceeded,
            error.SystemFdQuotaExceeded,
            error.SystemResources,
            error.ProtocolFailure,
            error.BlockedByFirewall,
            error.WouldBlock,
            error.ConnectionResetByPeer,
            error.NetworkSubsystemFailed,
            => |e| {
                std.log.info("accept failed with {s}", .{@errorName(e)});
                return;
            },
            error.FileDescriptorNotASocket,
            error.SocketNotListening,
            error.OperationNotSupported,
            error.Unexpected,
            => unreachable,
        };
        errdefer os.close(new_fd);

        const new_handler = self.allocator.create(DataSockHandler) catch |err| switch (err) {
            error.OutOfMemory => {
                std.log.err("s={}: failed to allocate handler", .{new_fd});
                return error.Handled;
            },
        };
        errdefer self.allocator.destroy(new_handler);
        new_handler.* = .{
            .allocator = self.allocator,
            .sock = new_fd,
        };
        epollAddHandler(self.epoll_fd, new_fd, &new_handler.base) catch |err| switch (err) {
            error.SystemResources,
            error.UserResourceLimitReached,
            => |e| {
                std.log.err("s={}: epoll add failed with {s}", .{new_fd, @errorName(e)});
                return error.Handled;
            },
            error.FileDescriptorIncompatibleWithEpoll,
            error.FileDescriptorAlreadyPresentInSet,
            error.OperationCausesCircularLoop,
            error.FileDescriptorNotRegistered,
            error.Unexpected,
            => unreachable,
        };
        std.log.info("s={}: new connection", .{new_fd});
    }
};

const DataSockHandler = struct {
    base: EpollHandler = .{ .handle = handle },
    allocator: std.mem.Allocator,
    sock: os.socket_t,
    partial: std.ArrayListAlignedUnmanaged(u8, 8) = .{},
    state: union(enum) {
        auth: struct {
            authenticated: bool = false,
        },
        begun: void,
    } = .{ .auth = .{} },

    fn deinit(self: *DataSockHandler) void {
        os.close(self.sock);
        self.partial.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    const min_read_len = 500;

    fn handle(base: *EpollHandler) !void {
        const self = @fieldParentPtr(DataSockHandler, "base", base);

        if (self.partial.items.len > 0) {
            self.partial.ensureUnusedCapacity(self.allocator, min_read_len) catch {
                std.log.err("s={}: unable to allocate more memory (already at {})", .{self.sock, self.partial.items.len});
                self.deinit();
                return;
            };
            const len = try self.read(unusedCapacitySlice(u8, 8, self.partial));
            self.partial.items.len += len;
            const processed = try self.process(self.partial.items);
            if (processed == self.partial.items.len) {
                self.partial.clearRetainingCapacity();
            } else {
                const new_len = self.partial.items.len - processed;
                std.mem.copy(u8, self.partial.items[0 .. new_len], self.partial.items[processed..]);
                self.partial.items.len = new_len;
            }
        } else {
            var buf: [2000]u8 align(8) = undefined;
            const len = try self.read(&buf);
            const processed = try self.process(buf[0 .. len]);
            if (processed < len) {
                const save_len = len - processed;
                self.partial.ensureUnusedCapacity(self.allocator, save_len) catch {
                    std.log.err("s={}: unable to allocate memory for {} bytes of partial data", .{self.sock, save_len});
                    self.deinit();
                    return;
                };
                @memcpy(self.partial.items.ptr, buf[processed..].ptr, save_len);
                self.partial.items.len = save_len;
            } else {
                std.debug.assert(processed == len);
            }
        }
    }

    fn read(self: *DataSockHandler, buf: []u8) error{Handled}!usize {
        const len = os.read(self.sock, buf) catch |err| {
            std.log.err("s={}: read failed with {s}, closing", .{self.sock, @errorName(err)});
            self.deinit();
            return error.Handled;
        };
        if (len == 0) {
            std.log.info("s={}: read EOF, closing", .{self.sock});
            self.deinit();
            return error.Handled;
        }
        //std.log.info("s={}: read {} bytes: '{}'", .{self.sock, len, std.zig.fmtEscapes(buf[0..len])});
        return len;
    }

    fn process(self: *DataSockHandler, buf: []align(8) const u8) error{Handled}!usize {
        std.debug.assert(buf.len > 0);
        var total_processed: usize = 0;
        while (true) {
            const processed = try self.processSingle(@alignCast(8, buf[total_processed..]));
            if (processed == 0) return total_processed;
            total_processed += processed;
        }
    }

    fn processSingle(self: *DataSockHandler, buf: []align(8) const u8) error{Handled}!usize {
        switch (self.state) {
            .auth => |*auth| {
                const offsets = parseLineOffsets(buf);
                if (offsets.end > 0) {
                    const line = buf[0 .. offsets.len];
                    std.log.info("s={}: got command '{}'", .{self.sock, std.zig.fmtEscapes(line)});

                    const auth_external_prefix = "\x00AUTH EXTERNAL ";
                    if (std.mem.startsWith(u8, line, auth_external_prefix)) {
                        if (auth.authenticated) {
                            std.log.info("s={}: got AUTH but already authenticatd", .{self.sock});
                            self.deinit();
                            return error.Handled;
                        }
                        const uid_str = line[auth_external_prefix.len..];
                        std.log.info("TODO: authenticate uid '{s}'", .{uid_str});
                        self.writer().writeAll("OK 993c625b4b6d3b14c4eff3a4627ea9bf\r\n") catch |err| {
                            std.log.err("s={}: failed to write reply with {s}", .{self.sock, @errorName(err)});
                            self.deinit();
                            return error.Handled;
                        };
                        auth.authenticated = true;
                    } else if (std.mem.eql(u8, line, "NEGOTIATE_UNIX_FD")) {
                        std.log.info("s={}: NEGOTIATE_UNIX_FD not implemented, sending ERROR", .{self.sock});
                        self.writer().writeAll("ERROR\r\n") catch |err| {
                            std.log.err("s={}: failed to write reply with {s}", .{self.sock, @errorName(err)});
                            self.deinit();
                            return error.Handled;
                        };
                    } else if (std.mem.eql(u8, line, "BEGIN")) {
                        self.state = .begun;
                    } else {
                        std.log.info("s={}: unhandled request '{}'", .{self.sock, std.zig.fmtEscapes(line)});
                        self.deinit();
                        return error.Handled;
                    }
                }
                return offsets.end;
            },
            .begun => {
                const msg_len = (dbus.getMsgLen(buf) catch |err| {
                    std.log.info("s={}: malformed message: {s}", .{self.sock, @errorName(err)});
                    self.deinit();
                    return error.Handled;
                }) orelse return 0;
                if (msg_len > buf.len) {
                    std.log.debug("s={}: received partial message of {} bytes", .{self.sock, buf.len});
                    return 0;
                }
                std.log.info("s={}: got msg {}-byte message '{}'", .{self.sock, msg_len, std.zig.fmtEscapes(buf)});
                return msg_len;
            },
        }
    }

    fn parseLineOffsets(buf: []const u8) struct { end: usize, len: usize } {
        const newline_index = std.mem.indexOfScalar(u8, buf, '\n') orelse return .{ .end = 0, .len = undefined };
        var len = newline_index;
        if (len > 0 and buf[len - 1] == '\r') {
            len -= 1;
        }
        return .{ .end = newline_index + 1, .len = len };
    }

    pub const Writer = std.io.Writer(DataSockHandler, std.os.WriteError, write);
    pub fn writer(self: DataSockHandler) Writer { return .{ .context = self }; }
    fn write(self: DataSockHandler, buf: []const u8) std.os.WriteError!usize {
        return std.os.write(self.sock, buf);
    }
};

// TODO: workaround a bug in Zig's std library
pub fn unusedCapacitySlice(
    comptime T: type,
    comptime alignment: u29,
    self: std.ArrayListAlignedUnmanaged(T, alignment),
) []align(alignment) T {
    return @alignCast(alignment, self.allocatedSlice()[self.items.len..]);
}
