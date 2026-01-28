const State = struct {
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial: u32,
    service_serial: u32,
    client_waiting_for: ?WaitingFor,

    const WaitingFor = union(TestCase) {
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
        h: std.posix.fd_t, // pipe read end for verification
    };
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
    h, // unix_fd - must be last since it requires special sendmsg/recvmsg handling

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
            inline else => |ct| @tagName(ct),
        };
    }
};

pub fn main() !void {
    try testFdPassingNoDbus();

    const session_addr_str = dbus.getSessionBusAddressString();
    const addr = dbus.Address.fromString(session_addr_str.str) catch |err| errExit(
        "invalid dbus address from environment variable '{s}': {s}",
        .{ session_addr_str.str, @errorName(err) },
    );

    var service_conn: Connection = undefined;
    try service_conn.connect(session_addr_str.str, addr);

    var service_name_buf: [dbus.max_name]u8 = undefined;
    const service_name_len, const service_unix_fds = try service_conn.hello(&service_name_buf);
    const service_name = service_name_buf[0..service_name_len];
    std.log.info("ServiceName '{s}' unix_fds={}", .{ service_name, service_unix_fds });

    var client_conn: Connection = undefined;
    try client_conn.connect(session_addr_str.str, addr);

    var client_name_buf: [dbus.max_name]u8 = undefined;
    const client_name_len, const client_unix_fds = try client_conn.hello(&client_name_buf);
    const client_name = client_name_buf[0..client_name_len];
    std.log.info("ClientName '{s}' unix_fds={}", .{ client_name, client_unix_fds });

    var state: State = .{
        .service_name = .{ .ptr = &service_name_buf, .len = service_name_len },
        .client_serial = 2,
        .service_serial = 2,
        .client_waiting_for = null,
    };

    while (client_conn.getSource().hasBufferedData()) {
        try handleClientMessage(&state, client_conn.stream.handle, client_conn.getWriter(), client_conn.getSource(), null);
    }
    while (service_conn.getSource().hasBufferedData()) {
        try handleServiceMessage(&state, service_conn.stream.handle, service_conn.getSource(), null);
    }

    state.client_waiting_for = try flushMethodCall(
        client_conn.getWriter(),
        client_conn.stream.handle,
        state.service_name,
        &state.client_serial,
        @enumFromInt(0),
    );

    while (state.client_waiting_for != null) {
        try handleEvent(&state, &service_conn, &client_conn);
    }
}

fn testFdPassingNoDbus() !void {
    var pair: [2]std.posix.fd_t = undefined;
    if (std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair) != 0) {
        return error.SocketPairFailed;
    }
    defer std.posix.close(pair[0]);
    defer std.posix.close(pair[1]);

    const send_data = "hello from sender";

    const pipe = try std.posix.pipe();
    defer std.posix.close(pipe[0]); // read end stays with us

    {
        defer std.posix.close(pipe[1]);
        var control: dbus.Cmsg(std.posix.fd_t) = .{
            .level = std.posix.SOL.SOCKET,
            .type = dbus.SCM.RIGHTS,
            .data = pipe[1],
        };
        _ = try dbus.sendCmsg(std.posix.fd_t, pair[0], send_data, &control);
    }

    const received_fd = blk: {
        var recv_buf: [100]u8 = undefined;
        var recv_control: dbus.Cmsg(std.posix.fd_t) = undefined;
        const data_len, const control_len = try dbus.recvCmsg(std.posix.fd_t, pair[1], &recv_buf, &recv_control);
        std.debug.assert(data_len == send_data.len);
        std.debug.assert(std.mem.eql(u8, recv_buf[0..data_len], send_data));

        std.debug.assert(control_len == @sizeOf(@TypeOf(recv_control)));
        break :blk recv_control.data;
    };
    defer std.posix.close(received_fd);

    const test_message = "message through passed fd";
    {
        const len = try std.posix.write(received_fd, test_message);
        std.debug.assert(len == test_message.len);
    }

    // Read from the pipe's read end to verify the FD works
    {
        var pipe_buf: [100]u8 = undefined;
        const n = try std.posix.read(pipe[0], &pipe_buf);
        std.debug.assert(n == test_message.len);
        std.debug.assert(std.mem.eql(u8, pipe_buf[0..n], test_message));
    }
}

const Connection = struct {
    write_buf: [1000]u8,
    read_buf: [1000]u8,
    stream: std.net.Stream,
    stream_writer: dbus.Stream15.Writer,
    stream_reader: dbus.Stream15.Reader,
    source_state: dbus.SourceState,

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
            .stream_writer = .init(stream, &connection.write_buf),
            .stream_reader = .init(stream, &connection.read_buf),
            .source_state = .auth,
        };
    }

    pub fn getWriter(connection: *Connection) *dbus.Writer {
        return &connection.stream_writer.interface;
    }
    pub fn getSource(connection: *Connection) dbus.Source {
        return .{
            .reader = connection.stream_reader.interface(),
            .state = &connection.source_state,
        };
    }

    pub fn hello(connection: *Connection, out_name_buf: *[dbus.max_name]u8) !struct { u8, bool } {
        const writer = connection.getWriter();
        const source = connection.getSource();

        try dbus.flushAuth(writer);
        try source.readAuth();
        std.log.info("authenticated", .{});

        try writer.writeAll("NEGOTIATE_UNIX_FD\r\n");
        try writer.flush();
        const unix_fd = blk: switch (try source.readNegotiateUnixFd()) {
            .agree => {
                std.log.info("NEGOTIATE_UNIX_FD: agree", .{});
                break :blk true;
            },
            .err => |msg| {
                std.log.warn("NEGOTIATE_UNIX_FD: ERROR {s}", .{msg});
                break :blk false;
            },
        };

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
        return .{ name_len, unix_fd };
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

    const expecting_fd = if (state.client_waiting_for) |wf| wf == .h else false;

    if (fds[0].revents & std.posix.POLL.IN != 0) {
        handled += 1;
        if (expecting_fd) {
            var recv_buf: [1000]u8 = undefined;
            var recv_control: dbus.Cmsg(std.posix.fd_t) = undefined;
            const data_len, const control_len = try dbus.recvCmsg(
                std.posix.fd_t,
                service_conn.stream.handle,
                &recv_buf,
                &recv_control,
            );
            std.debug.assert(control_len == @sizeOf(@TypeOf(recv_control)));
            var reader: dbus.Reader = .fixed(recv_buf[0..data_len]);
            var source_state: dbus.SourceState = .msg_start;
            const source = dbus.Source{ .reader = &reader, .state = &source_state };
            try handleServiceMessage(state, service_conn.stream.handle, source, recv_control.data);
        } else {
            try handleServiceMessage(state, service_conn.stream.handle, service_conn.getSource(), null);
        }
    }
    if (fds[1].revents & std.posix.POLL.IN != 0) {
        handled += 1;
        if (expecting_fd) {
            var recv_buf: [1000]u8 = undefined;
            var recv_control: dbus.Cmsg(std.posix.fd_t) = undefined;
            const data_len, const control_len = try dbus.recvCmsg(
                std.posix.fd_t,
                client_conn.stream.handle,
                &recv_buf,
                &recv_control,
            );
            std.debug.assert(control_len == @sizeOf(@TypeOf(recv_control)));
            var reader: dbus.Reader = .fixed(recv_buf[0..data_len]);
            var source_state: dbus.SourceState = .msg_start;
            const source = dbus.Source{ .reader = &reader, .state = &source_state };
            try handleClientMessage(state, client_conn.stream.handle, client_conn.getWriter(), source, recv_control.data);
        } else {
            try handleClientMessage(state, client_conn.stream.handle, client_conn.getWriter(), client_conn.getSource(), null);
        }
    }
    std.debug.assert(handled == ready);
}
fn handleServiceMessage(state: *State, socket_handle: std.posix.fd_t, source: dbus.Source, received_fd: ?std.posix.fd_t) !void {
    defer if (received_fd) |fd| std.posix.close(fd);
    if (received_fd) |fd| std.log.info("Service received 'h' message with FD {}", .{fd});

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

        const test_sig = std.meta.stringToEnum(TestCase, method.slice()) orelse std.debug.panic(
            "unknown method/test case '{s}'",
            .{method.slice()},
        );
        std.log.info("service handling {s}", .{@tagName(test_sig)});
        std.debug.assert(std.mem.eql(u8, signature.slice(), test_sig.sig()));

        if (received_fd) |fd| {
            // Handle 'h' (unix_fd) - need sendmsg to attach FD to reply
            const fd_index = try source.readBody(.unix_fd, {});
            std.debug.assert(fd_index == 0);
            try source.bodyEnd();

            var reply_buf: [500]u8 = undefined;
            var reply_writer: dbus.Writer = .fixed(&reply_buf);
            try dbus.writeMethodReturn(&reply_writer, "h", .{
                .serial = state.service_serial,
                .reply_serial = msg_start.serial,
                .destination = .{ .ptr = &sender.buffer, .len = sender.len },
                .unix_fds = 1,
            }, .{@as(u32, 0)});

            var reply_control: dbus.Cmsg(std.posix.fd_t) = .{
                .level = std.posix.SOL.SOCKET,
                .type = dbus.SCM.RIGHTS,
                .data = fd,
            };
            _ = try dbus.sendCmsg(std.posix.fd_t, socket_handle, reply_buf[0..reply_writer.end], &reply_control);
            std.log.info("Service sent 'h' reply with FD attached", .{});
        } else {
            // Normal case - use buffered writer
            var write_buf: [1000]u8 = undefined;
            const stream = std.net.Stream{ .handle = socket_handle };
            var stream_writer: dbus.Stream15.Writer = .init(stream, &write_buf);
            const writer = &stream_writer.interface;

            try echo.handle(source, writer, .{
                .serial = state.service_serial,
                .reply_serial = msg_start.serial,
                .destination = .{ .ptr = &sender.buffer, .len = sender.len },
            });
            try writer.flush();
        }
        state.service_serial += 1;

        if (!source.hasBufferedData()) break;
    }
}

fn handleClientMessage(
    state: *State,
    socket_handle: std.posix.fd_t,
    writer: *dbus.Writer,
    source: dbus.Source,
    received_fd: ?std.posix.fd_t,
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
                const test_case = std.meta.activeTag(waiting_for);
                std.debug.assert(std.mem.eql(u8, test_case.sig(), source.bodySignatureSlice()));

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
                    .h => |pipe_read_fd| {
                        defer std.posix.close(pipe_read_fd);
                        const echoed_fd = received_fd orelse unreachable;
                        defer std.posix.close(echoed_fd);
                        std.log.info("Client received 'h' reply with FD {}", .{echoed_fd});

                        const fd_index = try source.readBody(.unix_fd, {});
                        std.debug.assert(fd_index == 0);
                        try source.bodyEnd();

                        // Verify the FD works by writing through it and reading from the test pipe
                        const test_message = "FD passed through D-Bus!";
                        _ = try std.posix.write(echoed_fd, test_message);

                        var verify_buf: [100]u8 = undefined;
                        const n = try std.posix.read(pipe_read_fd, &verify_buf);
                        std.debug.assert(n == test_message.len);
                        std.debug.assert(std.mem.eql(u8, verify_buf[0..n], test_message));

                        std.log.info("FD passing test PASSED!", .{});
                    },
                }

                const next_case: TestCase = blk: {
                    const int = @as(u32, @intFromEnum(test_case)) + 1;
                    if (int == std.meta.fields(TestCase).len) {
                        state.client_waiting_for = null;
                        return;
                    }
                    break :blk @enumFromInt(int);
                };
                state.client_waiting_for = try flushMethodCall(
                    writer,
                    socket_handle,
                    state.service_name,
                    &state.client_serial,
                    next_case,
                );
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
        .h => .{@as(u32, 0)}, // fd_index = 0
    };
}

/// Sends a method call. For 'h' test case, returns the pipe read fd to store in WaitingFor.
fn flushMethodCall(
    writer: *dbus.Writer,
    socket_handle: std.posix.fd_t,
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial_ref: *u32,
    test_case: TestCase,
) !State.WaitingFor {
    const call: dbus.MethodCall = .{
        .serial = client_serial_ref.*,
        .destination = service_name,
        .path = .initStatic("/"),
        .member = .initAssume(@tagName(test_case)),
        .unix_fds = if (test_case == .h) 1 else null,
    };
    std.log.info("client sending {s}...", .{call.member.?.nativeSlice()});

    client_serial_ref.* += 1;

    if (test_case == .h) {
        // Special handling for 'h' - need sendmsg with FD
        // Create the test pipe
        const pipe = try std.posix.pipe();

        // Build the message to a fixed buffer
        var send_buf: [500]u8 = undefined;
        var fixed_writer: dbus.Writer = .fixed(&send_buf);
        try dbus.writeMethodCall(&fixed_writer, "h", call, .{@as(u32, 0)});

        // Send with FD attached via SCM_RIGHTS
        var control: dbus.Cmsg(std.posix.fd_t) = .{
            .level = std.posix.SOL.SOCKET,
            .type = dbus.SCM.RIGHTS,
            .data = pipe[1], // send write end
        };
        _ = try dbus.sendCmsg(std.posix.fd_t, socket_handle, send_buf[0..fixed_writer.end], &control);
        std.posix.close(pipe[1]); // close our copy after sending

        return .{ .h = pipe[0] }; // return read end for verification
    } else {
        switch (test_case) {
            .h => unreachable,
            inline else => |test_case_ct| {
                try dbus.writeMethodCall(
                    writer,
                    test_case_ct.sig(),
                    call,
                    testValues(test_case_ct),
                );
                try writer.flush();
                return @unionInit(State.WaitingFor, @tagName(test_case_ct), {});
            },
        }
    }
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
const dbus = @import("dbus");

const echo = @import("echo.zig");
