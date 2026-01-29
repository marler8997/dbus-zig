const State = struct {
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial: u32,
    service_serial: u32,
    client_waiting_for: ?TestCase,
};

const TestCase = enum {
    empty,
    u,
    i,
    uu,
    struct_uu,
    au,
    as,
    a_struct_uu,
    dict_uu,
    dict_us,
    dict_uv,
    v_u,
    v_uu,
    h,
    u_again, // added so h is not the last test
    pub fn sig(case: TestCase) [:0]const u8 {
        return switch (case) {
            .empty => "",
            .uu => "uu",
            .struct_uu => "(uu)",
            .a_struct_uu => "a(uu)",
            .dict_uu => "a{uu}",
            .dict_us => "a{us}",
            .dict_uv => "a{uv}",
            .v_u => "v",
            .v_uu => "v",
            .u_again => "u",
            inline else => |ct| @tagName(ct),
        };
    }
    pub fn fdCount(case: TestCase) u1 {
        return switch (case) {
            .h => 1,
            else => 0,
        };
    }
};

pub fn main() !void {
    const session_addr_str = dbus.getSessionBusAddressString();
    const addr = dbus.Address.fromString(session_addr_str.str) catch |err| errExit(
        "invalid dbus address from environment variable '{s}': {s}",
        .{ session_addr_str.str, @errorName(err) },
    );

    var service_conn: Connection = undefined;
    try service_conn.connect(session_addr_str.str, addr);

    var service_name_buf: [dbus.max_name]u8 = undefined;
    const service_name_len = try service_conn.hello(&service_name_buf);
    const service_name = service_name_buf[0..service_name_len];
    std.log.info("ServiceName '{s}'", .{service_name});

    var client_conn: Connection = undefined;
    try client_conn.connect(session_addr_str.str, addr);

    var client_name_buf: [dbus.max_name]u8 = undefined;
    const client_name_len = try client_conn.hello(&client_name_buf);
    const client_name = client_name_buf[0..client_name_len];
    std.log.info("ClientName '{s}'", .{client_name});

    var state: State = .{
        .service_name = .{ .ptr = &service_name_buf, .len = service_name_len },
        .client_serial = 2,
        .service_serial = 2,
        .client_waiting_for = null,
    };

    while (client_conn.getSource().hasBufferedData()) {
        try handleClientMessage(
            &state,
            client_conn.getWriter(),
            &client_conn.msg_reader.unix_fds,
            client_conn.getSource(),
        );
    }
    while (service_conn.getSource().hasBufferedData()) {
        try handleServiceMessage(
            &state,
            service_conn.getWriter(),
            &service_conn.msg_reader.unix_fds,
            service_conn.getSource(),
        );
    }

    try flushMethodCall(
        client_conn.getWriter(),
        .{ .ptr = &service_name_buf, .len = service_name_len },
        &state.client_serial,
        @enumFromInt(0),
    );
    state.client_waiting_for = @enumFromInt(0);

    while (state.client_waiting_for != null) {
        try handleEvent(&state, &service_conn, &client_conn);
    }
}

const Connection = struct {
    write_buf: [1000]u8,
    read_buf: [1000]u8,
    stream: std.net.Stream,
    msg_writer: dbus.MsgWriter,
    msg_reader: dbus.MsgReader,
    source_state: dbus.SourceState,

    const fd_buf_count = 10;

    pub fn connect(connection: *Connection, addr_str: []const u8, addr: dbus.Address) !void {
        const stream = dbus.connect(addr) catch |err| errExit(
            "failed to connect to '{s}': {s}",
            .{ addr_str, @errorName(err) },
        );
        std.log.info("connected to session bus '{s}', authenticating...", .{addr_str});
        connection.* = .{
            .write_buf = undefined,
            .read_buf = undefined,
            .stream = stream,
            .msg_writer = .init(stream, &connection.write_buf),
            .msg_reader = .init(stream, &connection.read_buf),
            .source_state = .auth,
        };
    }

    pub fn getWriter(connection: *Connection) *dbus.MsgWriter {
        return &connection.msg_writer;
    }
    pub fn getSource(connection: *Connection) dbus.Source {
        return .{
            .reader = connection.msg_reader.interface(),
            .state = &connection.source_state,
        };
    }

    pub fn hello(connection: *Connection, out_name_buf: *[dbus.max_name]u8) !u8 {
        const writer = &connection.getWriter().interface;
        const source = connection.getSource();

        try dbus.flushAuth(writer);
        try source.readAuth();
        std.log.info("authenticated", .{});

        try writer.writeAll("NEGOTIATE_UNIX_FD\r\n");
        try writer.flush();
        switch (try source.readNegotiateUnixFd()) {
            .agree => {},
            .err => |msg| std.debug.panic("NEGOTIATE_UNIX_FD: ERROR {s}", .{msg}),
        }

        try writer.writeAll("BEGIN\r\n");
        try dbus.writeMethodCall(
            writer,
            "", // signature
            .{
                .serial = 1,
                .destination = .initStatic("org.freedesktop.DBus"),
                .path = .initStatic("/org/freedesktop/DBus"),
                .interface = .initStatic("org.freedesktop.DBus"),
                .member = .initStatic("Hello"),
            },
            .{},
        );
        try writer.flush();

        var stderr_buf: [1000]u8 = undefined;
        var stderr_file = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_file.interface;

        while (true) {
            const msg_start = try source.readMsgStart();
            switch (msg_start.type) {
                .method_call => return error.UnexpectedDbusMethodCall,
                .method_return => break,
                .error_reply => {
                    std.log.err("received error:", .{});
                    try source.streamRemaining(stderr);
                    try stderr.flush();
                    std.process.exit(0xff);
                },
                .signal => {
                    std.log.info("ignoring signal", .{});
                    try source.streamRemaining(stderr);
                    try stderr.flush();
                },
            }
        }

        const headers = try source.readHeadersMethodReturn(&.{});
        std.debug.assert(headers.path == null);
        try headers.expectReplySerial(1);
        try source.expectSignature("s");
        const string_size: u32 = try source.readBody(.string_size, {});
        const name_len: u8 = dbus.castNameLen(string_size) orelse {
            std.log.err("assigned name is too long {}", .{string_size});
            return error.DbusProtocol;
        };
        try source.dataReadSliceAll(out_name_buf[0..name_len]);
        try source.dataReadNullTerm();
        try source.bodyEnd();
        return name_len;
    }
};

fn handleEvent(
    state: *State,
    service_conn: *Connection,
    client_conn: *Connection,
) !void {
    var fds = [_]std.posix.pollfd{
        .{ .fd = service_conn.stream.handle, .events = std.posix.POLL.IN, .revents = 0 },
        .{ .fd = client_conn.stream.handle, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const ready = try std.posix.poll(&fds, -1);
    std.debug.assert(ready != 0); // should be impossible with infinite timeout
    var handled: u32 = 0;
    if (fds[0].revents & std.posix.POLL.IN != 0) {
        handled += 1;
        try handleServiceMessage(
            state,
            service_conn.getWriter(),
            &service_conn.msg_reader.unix_fds,
            service_conn.getSource(),
        );
    }
    if (fds[1].revents & std.posix.POLL.IN != 0) {
        handled += 1;
        try handleClientMessage(
            state,
            client_conn.getWriter(),
            &client_conn.msg_reader.unix_fds,
            client_conn.getSource(),
        );
    }
    std.debug.assert(handled == ready);
    return;
}
fn handleServiceMessage(
    state: *State,
    msg_writer: *dbus.MsgWriter,
    unix_fds: *dbus.UnixFds,
    source: dbus.Source,
) !void {
    var stderr_buf: [1000]u8 = undefined;
    var stderr_file = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_file.interface;

    while (true) {
        const msg_start = try source.readMsgStart();
        const sender, const method, const signature = blk: switch (msg_start.type) {
            .method_call => {
                std.log.info("Service received method call {}", .{msg_start});
                var path_buf: [1000]u8 = undefined;
                const headers = try source.readHeadersMethodCall(&path_buf);
                std.debug.assert(headers.path.len == 1);
                std.debug.assert(std.mem.eql(u8, path_buf[0..1], "/"));
                std.debug.assert(headers.interface == null);
                std.debug.assert(headers.error_name == null);
                std.debug.assert(headers.reply_serial == null);
                std.debug.assert(headers.sender != null);
                try dbus.writeHeaders(stderr, &path_buf, source.bodySignature(), headers.asGeneric());
                try stderr.flush();
                break :blk .{ headers.sender.?, headers.member, source.bodySignatureCopy() };
            },
            .method_return => @panic("service received unexpected method return"),
            .error_reply => {
                std.log.err("Service received error", .{});
                try source.streamRemaining(stderr);
                try stderr.flush();
                @panic("todo");
            },
            .signal => {
                std.log.info("Service received signal (ignoring)", .{});
                try source.streamRemaining(stderr);
                try stderr.flush();
                return;
            },
        };

        const test_case = std.meta.stringToEnum(TestCase, method.slice()) orelse std.debug.panic(
            "unknown method/test case '{s}'",
            .{method.slice()},
        );
        std.log.info("service handling {s}", .{@tagName(test_case)});
        std.debug.assert(std.mem.eql(u8, signature.slice(), test_case.sig()));

        try echo.handle(unix_fds, source, msg_writer, .{
            .serial = state.service_serial,
            .reply_serial = msg_start.serial,
            .destination = .{ .ptr = &sender.buffer, .len = sender.len },
            .unix_fds = switch (test_case.fdCount()) {
                0 => null,
                1 => 1,
            },
        });
        try msg_writer.interface.flush();
        state.service_serial += 1;

        if (!source.hasBufferedData()) break;
    }
}

fn handleClientMessage(
    state: *State,
    msg_writer: *dbus.MsgWriter,
    unix_fds: *dbus.UnixFds,
    source: dbus.Source,
) !void {
    var stderr_buf: [1000]u8 = undefined;
    var stderr_file = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_file.interface;

    while (true) {
        const msg_start = try source.readMsgStart();
        switch (msg_start.type) {
            .method_call => @panic("client received unexpected method call"),
            .method_return => {
                std.log.info("Client received method return", .{});
                var path_buf: [1000]u8 = undefined;
                const headers = try source.readHeadersMethodReturn(&path_buf);
                std.debug.assert(headers.path == null);
                std.debug.assert(headers.interface == null);
                std.debug.assert(headers.member == null);
                std.debug.assert(headers.error_name == null);
                std.debug.assert(headers.reply_serial == state.client_serial - 1);

                const waiting_for = state.client_waiting_for orelse unreachable;
                std.debug.assert(std.mem.eql(u8, waiting_for.sig(), source.bodySignatureSlice()));

                switch (waiting_for) {
                    .empty => {
                        try source.bodyEnd();
                    },
                    .u => {
                        std.debug.assert(msg_start.body_len == 4);
                        std.debug.assert(testValues(.u)[0] == try source.readBody(.u32, {}));
                        try source.bodyEnd();
                    },
                    .i => {
                        std.debug.assert(msg_start.body_len == 4);
                        std.debug.assert(testValues(.i)[0] == try source.readBody(.i32, {}));
                        try source.bodyEnd();
                    },
                    .uu => {
                        std.debug.assert(testValues(.uu)[0] == try source.readBody(.u32, {}));
                        std.debug.assert(testValues(.uu)[1] == try source.readBody(.u32, {}));
                        try source.bodyEnd();
                    },
                    .struct_uu => {
                        std.debug.assert(testValues(.struct_uu)[0][0] == try source.readBody(.u32, {}));
                        std.debug.assert(testValues(.struct_uu)[0][1] == try source.readBody(.u32, {}));
                        try source.bodyEnd();
                    },
                    .au => {
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const value = try source.readBody(.u32, {});
                            std.debug.assert(testValues(.au)[0][value_index] == value);
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .as => {
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const string_size = try source.readBody(.string_size, {});
                            const string = try source.dataTake(string_size);
                            try source.dataReadNullTerm();
                            std.debug.assert(std.mem.eql(u8, testValues(.as)[0][value_index].nativeSlice(), string));
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .a_struct_uu => {
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const first = try source.readBody(.u32, {});
                            std.debug.assert(first == testValues(.a_struct_uu)[0][value_index][0]);
                            const second = try source.readBody(.u32, {});
                            std.debug.assert(second == testValues(.a_struct_uu)[0][value_index][1]);
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .dict_uu => {
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const key = try source.readBody(.u32, {});
                            std.debug.assert(key == testValues(.dict_uu)[0][value_index].key);
                            const value = try source.readBody(.u32, {});
                            std.debug.assert(value == testValues(.dict_uu)[0][value_index].value);
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .dict_us => {
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const key = try source.readBody(.u32, {});
                            std.debug.assert(key == testValues(.dict_us)[0][value_index].key);
                            const string_size = try source.readBody(.string_size, {});
                            const string = try source.dataTake(string_size);
                            try source.dataReadNullTerm();
                            std.debug.assert(std.mem.eql(u8, testValues(.dict_us)[0][value_index].value.nativeSlice(), string));
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .dict_uv => {
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const key = try source.readBody(.u32, {});
                            std.debug.assert(key == testValues(.dict_uv)[0][value_index].key);
                            var variant: dbus.SourceVariant = undefined;
                            try source.readBody(.variant_sig, &variant);
                            if (std.mem.eql(u8, variant.signature.slice(), "u")) {
                                const value = try source.readBody(.u32, {});
                                std.debug.assert(testValues(.dict_uv)[0][value_index].value.u32 == value);
                            } else if (std.mem.eql(u8, variant.signature.slice(), "s")) {
                                const string_size = try source.readBody(.string_size, {});
                                const string = try source.dataTake(string_size);
                                try source.dataReadNullTerm();
                                std.debug.assert(
                                    std.mem.eql(u8, testValues(.dict_uv)[0][value_index].value.string.nativeSlice(), string),
                                );
                            } else {
                                std.debug.panic("todo: sig '{s}'", .{variant.signature.slice()});
                            }
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .v_u => {
                        var variant: dbus.SourceVariant = undefined;
                        try source.readBody(.variant_sig, &variant);
                        std.debug.assert(std.mem.eql(u8, source.currentSignature().slice(), "u"));
                        const value = try source.readBody(.u32, {});
                        std.debug.assert(value == testValues(.v_u)[0].u32);
                        try source.bodyEnd();
                    },
                    .v_uu => {
                        var variant: dbus.SourceVariant = undefined;
                        try source.readBody(.variant_sig, &variant);
                        std.debug.assert(std.mem.eql(u8, source.currentSignature().slice(), "(uu)"));
                        const first = try source.readBody(.u32, {});
                        std.debug.assert(first == testValues(.v_uu)[0].struct_uu[0]);
                        const second = try source.readBody(.u32, {});
                        std.debug.assert(second == testValues(.v_uu)[0].struct_uu[1]);
                        try source.bodyEnd();
                    },
                    .h => {
                        std.debug.assert(msg_start.body_len == 4);
                        std.debug.assert(0 == try source.readBody(.unix_fd_index, {}));
                        try source.bodyEnd();
                        const fd = unix_fds.take(0).?;
                        defer std.posix.close(fd);
                        std.debug.assert(try isTestMemfd(fd));
                    },
                    .u_again => {
                        std.debug.assert(msg_start.body_len == 4);
                        std.debug.assert(testValues(.u_again)[0] == try source.readBody(.u32, {}));
                        try source.bodyEnd();
                    },
                }

                const next_case: TestCase = blk: {
                    const int = @as(u32, @intFromEnum(waiting_for)) + 1;
                    if (int == std.meta.fields(TestCase).len) {
                        state.client_waiting_for = null;
                        return;
                    }
                    break :blk @enumFromInt(int);
                };
                try flushMethodCall(
                    msg_writer,
                    state.service_name,
                    &state.client_serial,
                    next_case,
                );
                state.client_waiting_for = next_case;
            },
            .error_reply => {
                std.log.err("Client received error", .{});
                try source.streamRemaining(stderr);
                try stderr.flush();
                @panic("DBUS error");
            },
            .signal => {
                std.log.info("Client received signal (ignoring)", .{});
                try source.streamRemaining(stderr);
                try stderr.flush();
            },
        }

        if (!source.hasBufferedData()) break;
    }
}

const au_values = [_]u32{ 100, 42, 0, 0xffffffff };
const as_values = [_]dbus.Slice(u32, [*]const u8){
    .initStatic("hello"),
    .initStatic("there"),
    .initStatic("yay!"),
};
const a_struct_uu_values = [_]struct { u32, u32 }{
    .{ 0x12345678, 0xffffffff },
    .{ 0, 1 },
    .{ 0x7fffffff, 0x80000000 },
};
const dict_uu_values = [_]dbus.DictElement(u32, u32){
    .{ .key = 0x12345678, .value = 0xffffffff },
    .{ .key = 0, .value = 1 },
    .{ .key = 0x7fffffff, .value = 0x80000000 },
};
const dict_us_values = [_]dbus.DictElement(u32, dbus.Slice(u32, [*]const u8)){
    .{ .key = 10, .value = .initStatic("The value for the 10 key") },
    .{ .key = 100, .value = .initStatic("FooBar") },
    .{ .key = 0x7fffffff, .value = .initStatic("Another string\nHello\n") },
    .{ .key = 123, .value = .initStatic("a") },
    .{ .key = 456, .value = .initStatic("") },
};
const dict_uv_values = [_]dbus.DictElement(u32, dbus.Variant){
    .{ .key = 10, .value = .{ .u32 = 0x123 } },
    .{ .key = 11, .value = .{ .string = .initStatic("a string") } },
    // TODO: add sub variant/array values
};

fn testValues(comptime case: TestCase) dbus.Tuple(case.sig()) {
    return switch (case) {
        .empty => .{},
        .u => .{0x12345678},
        .i => .{0x7f00aba2},
        .uu => .{ 0x9abcdef0, 0x12f0a4d7 },
        .struct_uu => .{.{ 0xb9bfbcc0, 0x264ecbea }},
        .au => .{&au_values},
        .as => .{&as_values},
        .a_struct_uu => .{&a_struct_uu_values},
        .dict_uu => .{&dict_uu_values},
        .dict_us => .{&dict_us_values},
        .dict_uv => .{&dict_uv_values},
        .v_u => .{.{ .u32 = 0xf02958ab }},
        .v_uu => .{.{ .struct_uu = .{ 0xd2be463a, 0xa193801e } }},
        .h => .{0}, // fd index 0
        .u_again => .{0x9abcdef0},
    };
}

const test_memfd_name = "TestDbusMemfd";

fn flushMethodCall(
    msg_writer: *dbus.MsgWriter,
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial_ref: *u32,
    test_case: TestCase,
) !void {
    const call: dbus.MethodCall = .{
        .serial = client_serial_ref.*,
        .destination = service_name,
        .path = .initStatic("/"),
        .member = .initAssume(@tagName(test_case)),
        .unix_fds = switch (test_case.fdCount()) {
            0 => null,
            1 => 1,
        },
    };
    std.log.info("client sending {s}...", .{call.member.?.nativeSlice()});

    std.debug.assert(msg_writer.control == null);
    defer std.debug.assert(msg_writer.control == null);

    const memfd: std.posix.fd_t = switch (test_case.fdCount()) {
        0 => undefined,
        1 => try std.posix.memfd_createZ(test_memfd_name, 0),
    };
    defer switch (test_case.fdCount()) {
        0 => {},
        1 => {
            std.log.info("closing fd {} (client message sent)", .{memfd});
            std.posix.close(memfd);
        },
    };

    var write_entry: dbus.cmsg.Entry(std.posix.fd_t) = switch (test_case.fdCount()) {
        0 => undefined,
        1 => .{
            .level = std.os.linux.SOL.SOCKET,
            .type = dbus.SCM.RIGHTS,
            .data = memfd,
        },
    };
    switch (test_case.fdCount()) {
        0 => {},
        1 => msg_writer.control = write_entry.singleEntryArray(),
    }
    defer switch (test_case.fdCount()) {
        0 => {},
        1 => msg_writer.control = null,
    };

    switch (test_case) {
        inline else => |test_case_ct| try dbus.writeMethodCall(
            &msg_writer.interface,
            test_case_ct.sig(),
            call,
            testValues(test_case_ct),
        ),
    }
    try msg_writer.interface.flush();
    client_serial_ref.* += 1;
}

fn isTestMemfd(fd: std.posix.fd_t) !bool {
    var buf: [200]u8 = undefined;
    const path = std.fmt.bufPrintZ(&buf, "/proc/self/fd/{d}", .{fd}) catch unreachable;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_target = try std.posix.readlinkZ(path, &link_buf);
    return std.mem.startsWith(u8, link_target, "/memfd:" ++ test_memfd_name);
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
const dbus = @import("dbus");

const echo = @import("echo.zig");
