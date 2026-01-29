pub fn main() !u8 {
    var args_arena = switch (builtin.os.tag) {
        .windows => std.heap.ArenaAllocator.init(std.heap.page_allocator),
        else => {},
    };
    const cmdline: Cmdline = switch (builtin.os.tag) {
        .windows => .alloc(args_arena.allocator()),
        else => .{ .win32_slice = {} },
    };
    if (cmdline.len() <= 1) {
        const usage =
            \\Usage:
            \\  dbus call DEST PATH IFACE.METHOD SIG [ARGS...]
            \\
        ;
        if (dbus.zig_atleast_15) {
            var stderr_writer = std.fs.File.stderr().writer(&.{});
            stderr_writer.interface.writeAll(usage) catch return stderr_writer.err orelse error.Unexpected;
            return 0xff;
        } else {
            @panic("todo");
        }
    }
    const cmd = cmdline.arg(1);
    const cmd_args = switch (builtin.os.tag) {
        .windows => cmdline.win32_slice[2..],
        else => std.os.argv[2..],
    };
    if (std.mem.eql(u8, cmd, "call")) return call(cmd_args);
    errExit("unknown command '{s}'", .{cmd});
}

fn connect() !std.net.Stream {
    const session_addr_str = dbus.getSessionBusAddressString();
    const addr = dbus.Address.fromString(session_addr_str.str) catch |err| errExit(
        "invalid dbus address from environment variable '{s}': {s}",
        .{ session_addr_str.str, @errorName(err) },
    );

    const stream = dbus.connect(addr) catch |err| errExit(
        "failed to connect to '{s}': {s}",
        .{ session_addr_str.str, @errorName(err) },
    );
    // defer stream.deinit();
    std.log.info("connected to session bus '{s}', authenticating...", .{session_addr_str.str});
    var write_buf: [1000]u8 = undefined;
    var read_buf: [1000]u8 = undefined;
    var msg_writer: dbus.MsgWriter = .init(stream, &write_buf);
    var msg_reader: dbus.MsgReader = .init(stream, &read_buf);
    const writer = &msg_writer.interface;
    var source_state: dbus.SourceState = .auth;
    var source: dbus.Source = .{ .reader = msg_reader.interface(), .state = &source_state };

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

    var name_buf: [dbus.max_name:0]u8 = undefined;

    var stderr_buf: [1000]u8 = undefined;
    var stderr_file = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_file.interface;

    const name = blk_name: {
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
        try source.dataReadSliceAll(name_buf[0..name_len]);
        try source.dataReadNullTerm();
        try source.bodyEnd();
        break :blk_name name_buf[0..name_len];
    };

    std.log.info("our name is '{s}'", .{name});
    return stream;
}

fn call(call_args: []const Arg) !u8 {
    if (call_args.len < 4) errExit("call requires at least 5 args (DEST PATH IFACE.METHOD SIG) but got {}", .{call_args.len});
    const dest = spanArg(call_args[0]);
    const path = spanArg(call_args[1]);
    const iface_dot_method = spanArg(call_args[2]);
    const sig = spanArg(call_args[3]);
    const args = call_args[4..];

    const iface, const method = blk: {
        const last_dot = std.mem.lastIndexOfScalar(u8, iface_dot_method, '.') orelse errExit(
            "expected IFACE.METHOD but got '{s}' (no dot separator)",
            .{iface_dot_method},
        );
        break :blk .{ iface_dot_method[0..last_dot], iface_dot_method[last_dot + 1 ..] };
    };

    const stream = try connect();
    var write_buf: [1000]u8 = undefined;
    var read_buf: [1000]u8 = undefined;
    var msg_writer: dbus.MsgWriter = .init(stream, &write_buf);
    var msg_reader: dbus.MsgReader = .init(stream, &read_buf);
    const writer = &msg_writer.interface;
    var source_state: dbus.SourceState = .msg_start;
    var source: dbus.Source = .{ .reader = msg_reader.interface(), .state = &source_state };

    const body_len: u32 = calcBodyLen(sig, args) catch |err| switch (err) {
        error.BodyTooBig => errExit("the body of this method call is too big", .{}),
        error.NotEnoughArgs => errExit("{} is NOT ENOUGH arguments for this signature '{s}'", .{ args.len, sig }),
        error.TooManyArgs => errExit("{} is TOO MANY arguments for this signature '{s}'", .{ args.len, sig }),
    };
    std.log.info("call body len is {}", .{body_len});

    const method_call: dbus.MethodCall = .{
        .serial = 2,
        .destination = dbus.Slice(u32, [*]const u8).init(dest) orelse errExit("destination too long", .{}),
        .path = dbus.Slice(u32, [*]const u8).init(path) orelse errExit("path too long", .{}),
        .interface = dbus.Slice(u32, [*]const u8).init(iface) orelse errExit("interface too long", .{}),
        .member = dbus.Slice(u32, [*]const u8).init(method) orelse errExit("method too long", .{}),
    };
    const sig_typed: ?dbus.Slice(u8, [*]const u8) = if (sig.len > 0) dbus.Slice(u8, [*]const u8).init(sig) orelse errExit("signature too long", .{}) else null;
    const array_data_len = method_call.calcHeaderArrayLen(sig_typed);
    try writer.writeAll(&[_]u8{
        dbus.endian_header_value,
        @intFromEnum(dbus.MessageType.method_call), // 1
        0, // flags,
        1, // protocol version
    });
    try writer.writeInt(u32, body_len, dbus.native_endian);
    try writer.writeInt(u32, method_call.serial, dbus.native_endian);
    try writer.writeInt(u32, array_data_len, dbus.native_endian);
    var header_align: u3 = 0;
    try dbus.writeHeaderString(writer, &header_align, .path, method_call.path);
    if (method_call.destination) |d| {
        try dbus.writeHeaderString(writer, &header_align, .destination, d);
    }
    if (method_call.interface) |i| {
        try dbus.writeHeaderString(writer, &header_align, .interface, i);
    }
    if (method_call.member) |m| {
        try dbus.writeHeaderString(writer, &header_align, .member, m);
    }
    if (sig.len > 0) {
        try dbus.writeHeaderSig(writer, &header_align, sig_typed.?);
    }
    try writer.splatByteAll(0, dbus.pad8Len(header_align));

    {
        const written = writeBody(sig, args, writer) catch unreachable;
        std.debug.assert(written == body_len);
    }

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
    try headers.expectReplySerial(2);
    std.log.info("result signature '{s}'", .{source.bodySignatureSlice()});

    var stdout_buf: [1000]u8 = undefined;
    var stdout_file = std.fs.File.stdout().writer(&stdout_buf);
    try source.streamBody(&stdout_file.interface);
    try stdout_file.interface.flush();
    std.log.info("success", .{});
    return 0;
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

const Arg = switch (builtin.os.tag) {
    .windows => [:0]const u8,
    else => [*:0]const u8,
};
fn spanArg(arg: Arg) [:0]const u8 {
    return switch (builtin.os.tag) {
        .windows => arg,
        else => std.mem.span(arg),
    };
}

fn calcBodyLen(
    sig: []const u8,
    args: []const Arg,
) error{ BodyTooBig, NotEnoughArgs, TooManyArgs }!u32 {
    var total_len: u32 = 0;
    var body_align: u3 = 0;
    var sig_offset: usize = 0;
    var arg_index: usize = 0;
    while (sig_offset < sig.len) {
        if (arg_index >= args.len) return error.NotEnoughArgs;
        const arg = spanArg(args[arg_index]);
        arg_index += 1;
        const field = try calcBodyLenField(body_align, sig[sig_offset..], arg);
        total_len, const overflow = @addWithOverflow(total_len, field.len);
        if (overflow == 1) return error.BodyTooBig;
        body_align +%= @truncate(field.len);
        sig_offset += field.sig_consumed;
    }

    if (arg_index != args.len) return error.TooManyArgs;
    return total_len;
}

fn calcBodyLenField(body_align: u3, sig: []const u8, arg: []const u8) error{BodyTooBig}!struct {
    sig_consumed: usize,
    len: u32,
} {
    std.debug.assert(sig.len > 0);
    return switch (sig[0]) {
        's', 'o' => {
            const pad_len: u32 = dbus.pad4Len(@truncate(body_align));
            return .{
                .sig_consumed = 1,
                .len = std.math.cast(u32, pad_len + 4 + arg.len + 1) orelse return error.BodyTooBig,
            };
        },
        else => @panic("todo"),
    };
}

fn writeBody(
    sig: []const u8,
    args: []const Arg,
    writer: *dbus.Writer,
) error{ BodyTooBig, NotEnoughArgs, TooManyArgs, WriteFailed }!u32 {
    var total_len: u32 = 0;
    var body_align: u3 = 0;
    var sig_offset: usize = 0;
    var arg_index: usize = 0;
    while (sig_offset < sig.len) {
        if (arg_index >= args.len) return error.NotEnoughArgs;
        const arg = spanArg(args[arg_index]);
        arg_index += 1;
        const field = try writeBodyField(body_align, sig[sig_offset..], arg, writer);
        total_len, const overflow = @addWithOverflow(total_len, field.len);
        if (overflow == 1) return error.BodyTooBig;
        body_align +%= @truncate(field.len);
        sig_offset += field.sig_consumed;
    }

    if (arg_index != args.len) return error.TooManyArgs;
    return total_len;
}

fn writeBodyField(
    body_align: u3,
    sig: []const u8,
    arg: []const u8,
    writer: *dbus.Writer,
) error{ WriteFailed, BodyTooBig }!struct {
    sig_consumed: usize,
    len: u32,
} {
    std.debug.assert(sig.len > 0);
    switch (sig[0]) {
        's', 'o' => {
            const pad_len: u32 = dbus.pad4Len(@truncate(body_align));
            try writer.splatByteAll(0, pad_len);
            const string_len: u32 = std.math.cast(u32, arg.len) orelse return error.BodyTooBig;
            try writer.writeInt(u32, string_len, dbus.native_endian);
            try writer.writeAll(arg);
            try writer.writeByte(0);
            return .{
                .sig_consumed = 1,
                .len = std.math.cast(u32, pad_len + 4 + arg.len + 1) orelse return error.BodyTooBig,
            };
        },
        else => @panic("todo"),
    }
}

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const builtin = @import("builtin");
const std = @import("std");
const dbus = @import("dbus");

const Cmdline = @import("Cmdline.zig");
