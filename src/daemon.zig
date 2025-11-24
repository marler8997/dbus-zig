const std = @import("std");
const os = std.os;

const dbus = @import("dbus");

pub const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;
const align8 = if (zig_atleast_15) .@"8" else 8;

pub fn main() !u8 {
    const path = "/tmp/dbus-test";

    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| {
            std.log.err("failed to remove old socket file '{s}': {s}", .{ path, @errorName(e) });
            return 0xff;
        },
    };

    const epoll_fd = std.posix.epoll_create1(os.linux.EPOLL.CLOEXEC) catch |err| {
        std.log.err("epoll_create failed with {s}", .{@errorName(err)});
        return 0xff;
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //defer gpa.deinit();

    var listen_sock_handler: ListenSockHandler = undefined;

    {
        const sock = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC, 0) catch |err| {
            std.log.err("failed to create unix socket: {s}", .{@errorName(err)});
            return 0xff;
        };
        //errdefer std.posix.close(sock);

        var sockaddr = std.posix.sockaddr.un{ .family = std.posix.AF.UNIX, .path = undefined };

        const addr_len = @as(std.posix.socklen_t, @intCast(@offsetOf(std.posix.sockaddr.un, "path") + path.len + 1));
        if (addr_len > @sizeOf(std.posix.sockaddr.un)) {
            std.log.err("unix socket path len {} is too big", .{path.len});
            return 0xff;
        }
        @memcpy(sockaddr.path[0..path.len], path);
        sockaddr.path[path.len] = 0;

        std.posix.bind(sock, @as(*std.posix.sockaddr, @ptrCast(&sockaddr)), addr_len) catch |err| {
            std.log.err("failed to bind unix socket to '{s}': {s}", .{ path, @errorName(err) });
            return 0xff;
        };
        std.log.info("bound socket to '{s}'", .{path});

        std.posix.listen(sock, 10) catch |err| {
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
        var events: [10]os.linux.epoll_event = undefined;
        const count = std.posix.epoll_wait(epoll_fd, &events, 0);
        switch (std.posix.errno(count)) {
            .SUCCESS => {},
            else => |e| std.debug.panic("epoll_wait failed, errno={}", .{e}),
        }
        for (events[0..count]) |event| {
            const handler = @as(*EpollHandler, @ptrFromInt(event.data.ptr));
            handler.handle(handler) catch |err| switch (err) {
                error.Handled => {},
                else => |e| return e,
            };
        }
    }
    return 0;
}

fn epollAddHandler(epoll_fd: std.posix.fd_t, fd: std.posix.fd_t, handler: *EpollHandler) !void {
    var event = os.linux.epoll_event{
        .events = os.linux.EPOLL.IN,
        .data = os.linux.epoll_data{ .ptr = @intFromPtr(handler) },
    };
    try std.posix.epoll_ctl(epoll_fd, os.linux.EPOLL.CTL_ADD, fd, &event);
}

const EpollHandler = struct {
    handle: *const fn (base: *EpollHandler) anyerror!void,
};

const ListenSockHandler = struct {
    base: EpollHandler = .{ .handle = handle },
    epoll_fd: std.posix.fd_t,
    allocator: std.mem.Allocator,
    sock: std.posix.socket_t,

    fn handle(base: *EpollHandler) !void {
        const self: *ListenSockHandler = @fieldParentPtr("base", base);

        var addr: std.posix.sockaddr.un = undefined;
        var len: std.posix.socklen_t = @sizeOf(@TypeOf(addr));

        const new_fd = std.posix.accept(self.sock, @as(*std.posix.sockaddr, @ptrCast(&addr)), &len, std.posix.SOCK.CLOEXEC) catch |err| switch (err) {
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
        errdefer std.posix.close(new_fd);

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
                std.log.err("s={}: epoll add failed with {s}", .{ new_fd, @errorName(e) });
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

const AuthState = struct {
    authenticated: bool = false,
};

const DataSockHandler = struct {
    base: EpollHandler = .{ .handle = handle },
    allocator: std.mem.Allocator,
    sock: std.posix.socket_t,
    partial: std.ArrayListAlignedUnmanaged(u8, align8) = .{},
    state: union(enum) {
        start: void,
        auth: AuthState,
        begun: void,
    } = .start,

    fn deinit(self: *DataSockHandler) void {
        std.posix.close(self.sock);
        self.partial.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    const min_read_len = 500;

    fn handle(base: *EpollHandler) !void {
        const self: *DataSockHandler = @fieldParentPtr("base", base);

        if (self.partial.items.len > 0) {
            self.partial.ensureUnusedCapacity(self.allocator, min_read_len) catch {
                std.log.err("s={}: unable to allocate more memory (already at {})", .{ self.sock, self.partial.items.len });
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
                @memcpy(self.partial.items[0..new_len], self.partial.items[processed..]);
                self.partial.items.len = new_len;
            }
        } else {
            var buf: [2000]u8 align(8) = undefined;
            const len = try self.read(&buf);
            const processed = try self.process(buf[0..len]);
            if (processed < len) {
                const save_len = len - processed;
                self.partial.ensureUnusedCapacity(self.allocator, save_len) catch {
                    std.log.err("s={}: unable to allocate memory for {} bytes of partial data", .{ self.sock, save_len });
                    self.deinit();
                    return;
                };
                @memcpy(self.partial.items.ptr[0..save_len], buf[processed .. processed + save_len]);
                self.partial.items.len = save_len;
            } else {
                std.debug.assert(processed == len);
            }
        }
    }

    fn read(self: *DataSockHandler, buf: []u8) error{Handled}!usize {
        const len = std.posix.read(self.sock, buf) catch |err| {
            std.log.err("s={}: read failed with {s}, closing", .{ self.sock, @errorName(err) });
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
            const last_msg_was_auth = switch (self.state) {
                .start, .auth => true,
                .begun => false,
            };
            const processed = blk: {
                switch (self.state) {
                    .start => {
                        if (total_processed >= buf.len) return total_processed;
                        if (buf[total_processed] != 0) {
                            std.log.info("s={}: expected first byte to be 0 but got {}", .{ self.sock, buf[total_processed] });
                            self.deinit();
                            return error.Handled;
                        }
                        self.state = .{ .auth = .{} };
                        break :blk 1;
                    },
                    .auth => |*auth| break :blk try self.processAuth(buf[total_processed..], auth),
                    .begun => break :blk try self.processMsg(@alignCast(buf[total_processed..])),
                }
            };
            if (processed == 0) return total_processed;
            total_processed += processed;

            switch (self.state) {
                .start, .auth => {},
                .begun => if (last_msg_was_auth) {
                    // can this happen? if so then we need to do something about getting re-aligned, this
                    // could be as simple as copying the rest of the data to the beginning of the buffer
                    if (total_processed != buf.len) std.debug.panic(
                        "TODO: handle {} extra bytes of data in the same read call that got the auth data",
                        .{buf.len - total_processed},
                    );
                },
            }
        }
    }

    fn processAuth(self: *DataSockHandler, buf: []const u8, auth_state: *AuthState) error{Handled}!usize {
        const offsets = parseLineOffsets(buf);
        if (offsets.end > 0) {
            const line = buf[0..offsets.len];
            std.log.info("s={}: got command '{}'", .{ self.sock, std.zig.fmtEscapes(line) });

            const AUTH = "AUTH";
            const EXTERNAL = " EXTERNAL ";
            if (std.mem.startsWith(u8, line, AUTH)) {
                if (auth_state.authenticated) {
                    std.log.info("s={}: got AUTH but already authenticatd", .{self.sock});
                    self.deinit();
                    return error.Handled;
                }
                const the_rest = line[AUTH.len..];
                if (the_rest.len == 0) {
                    self.writer().writeAll("REJECTED EXTERNAL\r\n") catch |err| {
                        std.log.err("s={}: failed to write reply with {s}", .{ self.sock, @errorName(err) });
                        self.deinit();
                        return error.Handled;
                    };
                } else if (std.mem.startsWith(u8, the_rest, EXTERNAL)) {
                    const uid_str = the_rest[EXTERNAL.len..];
                    std.log.info("TODO: authenticate uid '{s}'", .{uid_str});
                    self.writer().writeAll("OK 993c625b4b6d3b14c4eff3a4627ea9bf\r\n") catch |err| {
                        std.log.err("s={}: failed to write reply with {s}", .{ self.sock, @errorName(err) });
                        self.deinit();
                        return error.Handled;
                    };
                    auth_state.authenticated = true;
                } else {
                    std.log.info("s={}: unhandled AUTH request '{}'", .{ self.sock, std.zig.fmtEscapes(line) });
                    self.deinit();
                    return error.Handled;
                }
            } else if (std.mem.eql(u8, line, "NEGOTIATE_UNIX_FD")) {
                std.log.info("s={}: NEGOTIATE_UNIX_FD not implemented, sending ERROR", .{self.sock});
                self.writer().writeAll("ERROR\r\n") catch |err| {
                    std.log.err("s={}: failed to write reply with {s}", .{ self.sock, @errorName(err) });
                    self.deinit();
                    return error.Handled;
                };
            } else if (std.mem.eql(u8, line, "BEGIN")) {
                self.state = .begun;
            } else {
                std.log.info("s={}: unhandled request '{}'", .{ self.sock, std.zig.fmtEscapes(line) });
                self.deinit();
                return error.Handled;
            }
        }
        return offsets.end;
    }

    fn processMsg(self: *DataSockHandler, buf: []align(8) const u8) error{Handled}!usize {
        const msg_len = (dbus.getMsgLen(buf) catch |err| {
            std.log.info("s={}: malformed message: {s}", .{ self.sock, @errorName(err) });
            self.deinit();
            return error.Handled;
        }) orelse return 0;
        if (msg_len > buf.len) {
            std.log.debug("s={}: received partial message of {} bytes", .{ self.sock, buf.len });
            return 0;
        }
        std.log.info("s={}: got msg {}-byte message '{}'", .{ self.sock, msg_len, std.zig.fmtEscapes(buf) });
        return msg_len;
    }

    fn parseLineOffsets(buf: []const u8) struct { end: usize, len: usize } {
        const newline_index = std.mem.indexOfScalar(u8, buf, '\n') orelse return .{ .end = 0, .len = undefined };
        var len = newline_index;
        if (len > 0 and buf[len - 1] == '\r') {
            len -= 1;
        }
        return .{ .end = newline_index + 1, .len = len };
    }

    pub const Writer = std.io.Writer(DataSockHandler, std.posix.WriteError, write);
    pub fn writer(self: DataSockHandler) Writer {
        return .{ .context = self };
    }
    fn write(self: DataSockHandler, buf: []const u8) std.posix.WriteError!usize {
        return std.posix.write(self.sock, buf);
    }
};

// TODO: workaround a bug in Zig's std library
pub fn unusedCapacitySlice(
    comptime T: type,
    comptime alignment: u29,
    self: std.ArrayListAlignedUnmanaged(T, alignment),
) []align(alignment) T {
    return @alignCast(self.allocatedSlice()[self.items.len..]);
}
