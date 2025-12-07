const State = struct {
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial: u32,
    service_serial: u32,
    client_waiting_for: ?TestSig,
};

const TestSig = enum {
    empty,
    u,
    au,
    as,
    @"a{uu}",
    pub fn sig(s: TestSig) [:0]const u8 {
        return switch (s) {
            .empty => "",
            inline else => |ct| @tagName(ct),
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
    const client_name = client_name_buf[0..try client_conn.hello(&client_name_buf)];
    std.log.info("ClientName '{s}'", .{client_name});

    var state: State = .{
        .service_name = .{ .ptr = &service_name_buf, .len = service_name_len },
        .client_serial = 2,
        .service_serial = 2,
        .client_waiting_for = null,
    };

    while (client_conn.getSource().hasBufferedData()) {
        try handleClientMessage(&state, client_conn.getWriter(), client_conn.getSource());
    }
    while (service_conn.getSource().hasBufferedData()) {
        try handleServiceMessage(&state, service_conn.getWriter(), service_conn.getSource());
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

    pub fn hello(connection: *Connection, out_name_buf: *[dbus.max_name]u8) !u8 {
        const writer = connection.getWriter();
        const source = connection.getSource();

        try dbus.flushAuth(writer);
        try source.readAuth();
        std.log.info("authenticated", .{});

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
        try handleServiceMessage(state, service_conn.getWriter(), service_conn.getSource());
    }
    if (fds[1].revents & std.posix.POLL.IN != 0) {
        handled += 1;
        try handleClientMessage(state, client_conn.getWriter(), client_conn.getSource());
    }
    std.debug.assert(handled == ready);
    return;
}
fn handleServiceMessage(state: *State, writer: *dbus.Writer, source: dbus.Source) !void {
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

        if (std.mem.eql(u8, method.sliceConst(), "echo_empty")) {
            std.debug.assert(std.mem.eql(u8, signature.sliceConst(), ""));
            try source.bodyEnd();
            try dbus.writeMethodReturn(
                writer,
                "",
                .{
                    .serial = state.service_serial,
                    .reply_serial = msg_start.serial,
                    .destination = .{ .ptr = &sender.buffer, .len = sender.len },
                },
                .{},
            );
            try writer.flush();
            std.log.info("service sent echo return", .{});
            state.service_serial += 1;
        } else if (std.mem.eql(u8, method.sliceConst(), "echo_u")) {
            std.debug.assert(std.mem.eql(u8, signature.sliceConst(), "u"));
            std.debug.assert(msg_start.body_len == 4);
            const value = try source.readBody(.u32, {});
            try source.bodyEnd();

            try dbus.writeMethodReturn(
                writer,
                "u",
                .{
                    .serial = state.service_serial,
                    .reply_serial = msg_start.serial,
                    .destination = .{ .ptr = &sender.buffer, .len = sender.len },
                },
                .{value},
            );
            try writer.flush();
            std.log.info("service sent echo_u return", .{});
            state.service_serial += 1;
        } else if (std.mem.eql(u8, method.sliceConst(), "echo_au")) {
            std.debug.assert(std.mem.eql(u8, signature.sliceConst(), "au"));
            var array: dbus.SourceArray = undefined;
            try source.readBody(.array_size, &array);
            var value_index: usize = 0;
            while (source.bodyOffset() < array.body_limit) {
                const value = try source.readBody(.u32, {});
                std.debug.assert(echo_au_values[value_index] == value);
                value_index += 1;
            }
            try source.bodyEnd();

            try dbus.writeMethodReturn(
                writer,
                "au",
                .{
                    .serial = state.service_serial,
                    .reply_serial = msg_start.serial,
                    .destination = .{ .ptr = &sender.buffer, .len = sender.len },
                },
                .{&echo_au_values},
            );
            try writer.flush();
            std.log.info("service sent echo_au return", .{});
            state.service_serial += 1;
        } else if (std.mem.eql(u8, method.sliceConst(), "echo_as")) {
            std.debug.assert(std.mem.eql(u8, signature.sliceConst(), "as"));
            var array: dbus.SourceArray = undefined;
            try source.readBody(.array_size, &array);
            var value_index: usize = 0;
            while (source.bodyOffset() < array.body_limit) {
                const string_size = try source.readBody(.string_size, {});
                const string = try source.dataTake(string_size);
                try source.dataReadNullTerm();
                std.debug.assert(std.mem.eql(u8, echo_as_values[value_index].nativeSlice(), string));
                value_index += 1;
            }
            try source.bodyEnd();

            try dbus.writeMethodReturn(
                writer,
                "as",
                .{
                    .serial = state.service_serial,
                    .reply_serial = msg_start.serial,
                    .destination = .{ .ptr = &sender.buffer, .len = sender.len },
                },
                .{&echo_as_values},
            );
            try writer.flush();
            std.log.info("service sent echo_as return", .{});
            state.service_serial += 1;
        } else {
            std.debug.panic("unsupported method '{s}'", .{method.sliceConst()});
        }

        if (!source.hasBufferedData()) break;
    }
}

fn handleClientMessage(state: *State, writer: *dbus.Writer, source: dbus.Source) !void {
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
                switch (waiting_for) {
                    .empty => {
                        std.debug.assert(std.mem.eql(u8, "", source.bodySignatureSlice()));
                        try source.bodyEnd();
                    },
                    .u => {
                        std.debug.assert(std.mem.eql(u8, "u", source.bodySignatureSlice()));
                        std.debug.assert(msg_start.body_len == 4);
                        const value = try source.readBody(.u32, {});
                        std.debug.assert(value == 0x12345678);
                        try source.bodyEnd();
                    },
                    .au => {
                        std.debug.assert(std.mem.eql(u8, "au", source.bodySignatureSlice()));
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const value = try source.readBody(.u32, {});
                            std.debug.assert(echo_au_values[value_index] == value);
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .as => {
                        std.debug.assert(std.mem.eql(u8, "as", source.bodySignatureSlice()));
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            const string_size = try source.readBody(.string_size, {});
                            const string = try source.dataTake(string_size);
                            try source.dataReadNullTerm();
                            std.debug.assert(std.mem.eql(u8, echo_as_values[value_index].nativeSlice(), string));
                            value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                    .@"a{uu}" => {
                        std.debug.assert(std.mem.eql(u8, "a{uu}", source.bodySignatureSlice()));
                        var array: dbus.SourceArray = undefined;
                        try source.readBody(.array_size, &array);
                        if (true) @panic("todo");
                        // var value_index: usize = 0;
                        while (source.bodyOffset() < array.body_limit) {
                            // const value1 = try source.readBody(.u32, {});
                            // const value2 = try source.readBody(.u32, {});
                            @panic("todo");
                            // value_index += 1;
                        }
                        try source.bodyEnd();
                    },
                }

                const next_sig: TestSig = blk: {
                    const int = @as(u32, @intFromEnum(waiting_for)) + 1;
                    if (int == std.meta.fields(TestSig).len) {
                        state.client_waiting_for = null;
                        return;
                    }
                    break :blk @enumFromInt(int);
                };
                try flushMethodCall(
                    writer,
                    state.service_name,
                    &state.client_serial,
                    next_sig,
                );
                state.client_waiting_for = next_sig;
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

const echo_au_values = [_]u32{ 100, 42, 0, 0xffffffff };
const echo_as_values = [_]dbus.Slice(u32, [*]const u8){
    .initStatic("hello"),
    .initStatic("there"),
    .initStatic("yay!"),
};

const @"echo_a{uu}_values" = [_]dbus.DictElement(u32, u32){
    .{ .key = 0x12345678, .value = 0xffffffff },
    .{ .key = 0, .value = 1 },
    .{ .key = 0x7fffffff, .value = 0x80000000 },
};

fn testSigData(comptime test_sig: TestSig) dbus.WriteData(test_sig.sig()) {
    return switch (test_sig) {
        .empty => .{},
        .u => .{0x12345678},
        .au => .{&echo_au_values},
        .as => .{&echo_as_values},
        .@"a{uu}" => .{&@"echo_a{uu}_values"},
    };
}

fn flushMethodCall(
    writer: *dbus.Writer,
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial_ref: *u32,
    test_sig: TestSig,
) !void {
    const call: dbus.MethodCall = .{
        .serial = client_serial_ref.*,
        .destination = service_name,
        .path = .initStatic("/"),
        .member = switch (test_sig) {
            inline else => |ct| .initStatic("echo_" ++ @tagName(ct)),
        },
    };
    std.log.info("client sending {s}...", .{call.member.?.nativeSlice()});
    switch (test_sig) {
        inline else => |ct| try dbus.writeMethodCall(writer, ct.sig(), call, testSigData(ct)),
    }
    try writer.flush();
    client_serial_ref.* += 1;
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
const dbus = @import("dbus");
