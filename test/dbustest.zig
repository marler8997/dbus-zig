const State = struct {
    service_name: dbus.Slice(u32, [*]const u8),
    client_serial: u32,
    service_serial: u32,
    client: ClientState,
};

const ClientState = enum {
    sent_echo,
    sent_echou32,
    done,
};

pub fn main() !void {
    const session_addr_str = dbus.getSessionBusAddressString();
    const addr = dbus.Address.fromString(session_addr_str.str) catch |err| errExit(
        "invalid dbus address from environment variable '{s}': {s}",
        .{ session_addr_str.str, @errorName(err) },
    );

    var service_name_buf: [dbus.max_name]u8 = undefined;
    const service_stream, const service_name_len = try connect(session_addr_str.str, addr, &service_name_buf);
    const service_name = service_name_buf[0..service_name_len];
    std.log.info("ServiceName '{s}'", .{service_name});

    var client_name_buf: [dbus.max_name]u8 = undefined;
    const client_stream, const client_name_len = try connect(session_addr_str.str, addr, &client_name_buf);
    const client_name = client_name_buf[0..client_name_len];
    std.log.info("ClientName '{s}'", .{client_name});

    var state: State = .{
        .service_name = .{ .ptr = &service_name_buf, .len = service_name_len },
        .client_serial = 2,
        .service_serial = 2,
        .client = .sent_echo,
    };

    try writeMethodCall(
        client_stream,
        .{ .ptr = &service_name_buf, .len = service_name_len },
        .Echo,
        &state.client_serial,
    );

    while (switch (state.client) {
        .sent_echo, .sent_echou32 => true,
        .done => false,
    }) {
        try handleEvent(&state, service_stream, client_stream);
    }
}

fn connect(addr_str: []const u8, addr: dbus.Address, out_name_buf: *[dbus.max_name]u8) !struct { std.net.Stream, u8 } {
    const stream = dbus.connect(addr) catch |err| errExit(
        "failed to connect to '{s}': {s}",
        .{ addr_str, @errorName(err) },
    );
    // defer stream.deinit();
    std.log.info("connected to session bus '{s}', authenticating...", .{addr_str});
    var write_buf: [1000]u8 = undefined;
    var read_buf: [1000]u8 = undefined;
    var socket_writer = dbus.socketWriter(stream, &write_buf);
    var socket_reader = dbus.socketReader(stream, &read_buf);
    const writer = &socket_writer.interface;
    const reader = socket_reader.interface();

    try dbus.flushAuth(writer);
    try dbus.readAuth(reader);
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

    const name_len: u8 = blk_name: {
        const fixed = blk_fixed: {
            while (true) {
                const fixed = try dbus.readFixed(reader);
                switch (fixed.type) {
                    .method_call => return error.UnexpectedDbusMethodCall,
                    .method_return => break :blk_fixed fixed,
                    .error_reply => {
                        std.log.err("received error after sending Hello:", .{});
                        readError(reader, &fixed) catch |err| switch (err) {
                            error.ReadFailed => return socket_reader.getError() orelse error.Unexpected,
                            else => |e| return e,
                        };
                        std.process.exit(0xff);
                    },
                    .signal => {
                        std.log.info("ignoring signal", .{});
                        var stderr_buf: [1000]u8 = undefined;
                        var stderr_file = std.fs.File.stderr().writer(&stderr_buf);
                        try fixed.stream(reader, &stderr_file.interface);
                        try stderr_file.interface.flush();
                    },
                }
            }
        };
        const headers = try fixed.readMethodReturnHeaders(reader, &.{});
        try headers.expectReplySerial(1);
        try headers.expectSignature("s");
        var it: dbus.BodyIterator = .{
            .endian = fixed.endian,
            .body_len = fixed.body_len,
            .signature = headers.signatureSlice(),
        };
        comptime var sig_index: usize = 0;
        const string_size: u32 = try dbus.read("s", &sig_index, .string_size)(&it, reader);
        const string_size_u8 = dbus.castNameLen(string_size) orelse std.debug.panic("assigned name is too long {}", .{string_size});
        try reader.readSliceAll(out_name_buf[0..string_size]);
        try dbus.consumeStringNullTerm(reader);
        it.notifyConsumed(.string);
        try it.finish("s", sig_index);
        break :blk_name string_size_u8;
    };
    return .{ stream, name_len };
}

fn readError(reader: *dbus.Reader, fixed: *const dbus.Fixed) !void {
    const headers = try fixed.readErrorHeaders(reader, &.{});
    var it: dbus.BodyIterator = .{
        .endian = fixed.endian,
        .body_len = fixed.body_len,
        .signature = headers.signatureSlice(),
    };
    if (try it.next(reader)) |result| switch (result) {
        .string_size => |string_size| {
            var msg_buf: [1024]u8 = undefined;
            const msg_len = @min(string_size, msg_buf.len);
            try reader.readSliceAll(msg_buf[0..msg_len]);
            // Skip remaining bytes if message was truncated
            if (string_size > msg_len) {
                try reader.discardAll(string_size - msg_len);
            }
            try dbus.consumeStringNullTerm(reader);
            it.notifyConsumed(.string);
            std.log.err("Message: {s}", .{msg_buf[0..msg_len]});
        },
        else => {
            std.log.err("unknown error body type {s}", .{@tagName(result)});
        },
    };
}

fn handleEvent(
    state: *State,
    service_stream: std.net.Stream,
    client_stream: std.net.Stream,
) !void {
    var fds = [_]std.posix.pollfd{
        .{ .fd = service_stream.handle, .events = std.posix.POLL.IN, .revents = 0 },
        .{ .fd = client_stream.handle, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const ready = try std.posix.poll(&fds, -1);
    std.debug.assert(ready != 0); // should be impossible with infinite timeout
    var serviced: u32 = 0;
    if (fds[0].revents & std.posix.POLL.IN != 0) {
        serviced += 1;
        try handleServiceMessage(state, service_stream);
    }
    if (fds[1].revents & std.posix.POLL.IN != 0) {
        serviced += 1;
        try handleClientMessage(state, client_stream);
    }
    std.debug.assert(serviced == ready);
    return;
}
fn handleServiceMessage(state: *State, stream: std.net.Stream) !void {
    var read_buf: [4096]u8 = undefined;
    var socket_reader = dbus.socketReader(stream, &read_buf);
    const reader = socket_reader.interface();
    const fixed = try dbus.readFixed(reader);
    const sender, const method, const signature = blk: switch (fixed.type) {
        .method_call => {
            std.log.info("Service received method call {}", .{fixed});
            var path_buf: [1000]u8 = undefined;
            const headers = try fixed.readMethodCallHeaders(socket_reader.interface(), &path_buf);
            std.debug.assert(headers.path.len == 1);
            std.debug.assert(std.mem.eql(u8, path_buf[0..1], "/"));
            std.debug.assert(headers.interface == null);
            std.debug.assert(headers.error_name == null);
            std.debug.assert(headers.reply_serial == null);
            std.debug.assert(headers.sender != null);

            var stderr_buf: [1000]u8 = undefined;
            var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
            try dbus.writeHeaders(&stderr_writer.interface, &path_buf, headers.asGeneric());
            try stderr_writer.interface.flush();
            break :blk .{ headers.sender.?, headers.member, headers.signature };
        },
        .method_return => @panic("service received unexpected method return"),
        .error_reply => {
            std.log.err("Service received error", .{});
            readError(reader, &fixed) catch {};
            @panic("todo");
        },
        .signal => {
            std.log.info("Service received signal (ignoring)", .{});
            try reader.discardAll(fixed.body_len);
            return;
        },
    };

    if (std.mem.eql(u8, method.sliceConst(), "Echo")) {
        std.debug.assert(signature == null);
        std.debug.assert(reader.seek == reader.end);
        var write_buf: [1000]u8 = undefined;
        var socket_writer = dbus.socketWriter(stream, &write_buf);
        try dbus.writeMethodReturn(
            &socket_writer.interface,
            "",
            .{
                .serial = state.service_serial,
                .reply_serial = fixed.serial,
                .destination = .{ .ptr = &sender.buffer, .len = sender.len },
            },
            .{},
        );
        try socket_writer.interface.flush();
        std.log.info("service sent echo return", .{});
        state.service_serial += 1;
    } else if (std.mem.eql(u8, method.sliceConst(), "EchoU32")) {
        std.debug.assert(std.mem.eql(u8, signature.?.sliceConst(), "u"));
        std.debug.assert(fixed.body_len == 4);
        const value = try reader.takeInt(u32, dbus.native_endian);
        std.debug.assert(reader.seek == reader.end);

        var write_buf: [1000]u8 = undefined;
        var socket_writer = dbus.socketWriter(stream, &write_buf);
        try dbus.writeMethodReturn(
            &socket_writer.interface,
            "u",
            .{
                .serial = state.service_serial,
                .reply_serial = fixed.serial,
                .destination = .{ .ptr = &sender.buffer, .len = sender.len },
            },
            .{value},
        );
        try socket_writer.interface.flush();
        std.log.info("service sent EchoU32 return", .{});
        state.service_serial += 1;
    } else {
        std.debug.panic("unsupported method '{s}'", .{method.sliceConst()});
    }
}

fn handleClientMessage(state: *State, stream: std.net.Stream) !void {
    var read_buf: [4096]u8 = undefined;
    var socket_reader = dbus.socketReader(stream, &read_buf);
    const reader = socket_reader.interface();

    const fixed = try dbus.readFixed(reader);

    switch (fixed.type) {
        .method_call => @panic("client received unexpected method call"),
        .method_return => {
            std.log.info("Client received method return", .{});
            var path_buf: [1000]u8 = undefined;
            const headers = try fixed.readMethodReturnHeaders(reader, &path_buf);
            std.debug.assert(headers.path == null);
            std.debug.assert(headers.interface == null);
            std.debug.assert(headers.member == null);
            std.debug.assert(headers.error_name == null);
            std.debug.assert(headers.reply_serial == state.client_serial - 1);

            switch (state.client) {
                .sent_echo => {
                    std.debug.assert(headers.signature == null);
                    std.debug.assert(reader.seek == reader.end);
                    try writeMethodCall(stream, state.service_name, .{ .EchoU32 = 0x12345678 }, &state.client_serial);
                    state.client = .sent_echou32;
                },
                .sent_echou32 => {
                    std.debug.assert(std.mem.eql(u8, headers.signature.?.sliceConst(), "u"));
                    std.debug.assert(fixed.body_len == 4);
                    const value = try reader.takeInt(u32, dbus.native_endian);
                    std.debug.assert(value == 0x12345678);
                    std.debug.assert(reader.seek == reader.end);
                    state.client = .done;
                },
                .done => @panic("impossible?"),
            }
        },
        .error_reply => {
            std.log.err("Client received error", .{});
            readError(reader, &fixed) catch {};
            @panic("todo");
        },
        .signal => {
            std.log.info("Client received signal (ignoring)", .{});
            try reader.discardAll(fixed.body_len);
        },
    }
}

const Method = union(enum) {
    Echo,
    EchoU32: u32,
};

fn writeMethodCall(
    stream: std.net.Stream,
    service_name: dbus.Slice(u32, [*]const u8),
    method: Method,
    client_serial_ref: *u32,
) !void {
    var write_buf: [1000]u8 = undefined;
    var socket_writer = dbus.socketWriter(stream, &write_buf);
    const call: dbus.MethodCall = .{
        .serial = client_serial_ref.*,
        .destination = service_name,
        .path = .initStatic("/"),
        .member = .initAssume(@tagName(method)),
    };
    switch (method) {
        .Echo => try dbus.writeMethodCall(&socket_writer.interface, "", call, .{}),
        .EchoU32 => |value| try dbus.writeMethodCall(&socket_writer.interface, "u", call, .{value}),
    }

    try socket_writer.interface.flush();
    client_serial_ref.* += 1;
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
const dbus = @import("dbus");
