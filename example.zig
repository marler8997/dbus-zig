const std = @import("std");
const dbus = @import("dbus");

pub fn main() !u8 {
    const session_addr_str = dbus.getSessionBusAddressString();
    const addr = dbus.Address.fromString(session_addr_str.str) catch |err| {
        switch (session_addr_str.origin) {
            .hardcoded_default => unreachable,
            .environment_variable=> {
                std.log.err("invalid dbus address from environment variable '{s}': {s}", .{session_addr_str.str, @errorName(err)});
            },
        }
        return 0xff;
    };

    var connection = dbus.Connection.connect(addr) catch |err| {
        std.log.info("failed to connect to '{s}': {s}", .{session_addr_str.str, @errorName(err)});
        return 0xff;
    };
    // defer connection.deinit();
    std.log.info("connected to session bus '{s}', authenticating...", .{session_addr_str.str});
    try connection.authenticate();

    std.log.info("authenticated", .{});

    {
        const args = comptime dbus.method_call_msg.Args {
            .serial = 1,
            .path = dbus.strSlice(u32, "/org/freedesktop/DBus"),
            // TODO: do we need a destination?
            .destination = dbus.strSlice(u32, "org.freedesktop.DBus"),
            .interface = dbus.strSlice(u32, "org.freedesktop.DBus"),
            .member = dbus.strSlice(u32, "Hello"),
            //.signature = "su",
        };
        var msg: [dbus.method_call_msg.getHeaderLen(args)]u8 = undefined;
        dbus.method_call_msg.serialize(&msg, args);
        try connection.writer().writeAll(&msg);
    }

    while (true) {
        std.log.info("reading msg...", .{});
        var buf: [1000]u8 align(8) = undefined;
        const msg_len = dbus.readOneMsg(connection.reader(), &buf) catch |err| {
            std.log.err("failed to read dbus msg with {s}", .{@errorName(err)});
            return 0xff;
        };
        if (msg_len > buf.len) {
            std.log.err("buffer of size {} is not large enough (need {})", .{buf.len, msg_len});
            return 0xff;
        }
        std.log.info("got {}-byte msg:", .{msg_len});
        const func = struct {
            pub fn log(line: []const u8) void {
                std.log.info("{s}", .{line});
            }
        };
        @import("hexdump.zig").hexdump(func.log, buf[0..msg_len], .{});
        const parsed = dbus.parseMsgAssumeGetMsgLen(dbus.sliceLen(@as([*]const align(8) u8, &buf), msg_len));
        const msg_type = dbus.parseMsgType(&buf) orelse {
            std.log.err("malformed reply, unknown msg type", .{});
            return 0xff;
        };
        std.log.info("type={s} serial={}", .{@tagName(msg_type), parsed.serial(&buf)});
        {
            var it = parsed.headerArrayIterator();
            while (it.next(&buf) catch |err| switch (err) {
                error.FieldTooBig,
                error.UnexpectedTypeSig,
                error.NoNullTerm,
                => {
                    std.log.info("malformed reply {s}", .{@errorName(err)});
                    return 0xff;
                },
            }) |header_field| {
                switch (header_field) {
                    .unknown => |id| {
                        std.log.info("malformed reply, uknown header field {}", .{id});
                        return 0xff;
                    },
                    .string => |str| std.log.info("header_field {s} '{s}'", .{@tagName(str.kind), str.str}),
                    .uint32 => |u| std.log.info("header_field {s} {}", .{@tagName(u.kind), u.val}),
                    .sig => |s| std.log.info("header_field signature '{s}'", .{s}),
                }
            }
        }
        _ = parsed;
    }

//    {
//        var buf: [1000]u8 align(8) = undefined;
//        std.log.info("reading reply...", .{});
//        const len = connection.reader().read(&buf) catch |err| switch (err) {
//            //error.StreamTooLong => return error.MalformedReply,
//            else => |e| return e,
//        };
//        if (len == 0) {
//            std.log.info("read EOF", .{});
//            return 0xff;
//        }
//        //std.log.info("reply is {} bytes: '{}'", .{len, std.zig.fmtEscapes(buf[0..len])});
//
//        var offset: usize = 0;
//        while (true) {
//            const msg_len = (try dbus.getMsgLen(buf[offset..len])) orelse break;
//            const msg_end = offset + msg_len;
//            if (msg_end > buf.len) break;
//            const msg = buf[offset..msg_end];
//            std.log.info("got {}-byte msg '{}'", .{msg_len, std.zig.fmtEscapes(msg)});
//            offset = msg_end;
//            if (offset == len) break;
//        }
//        if (offset != len) {
//            std.debug.panic("todo: handle partial messages", .{});
//        }
//
//    }
//

//    {
//        const args = comptime dbus.signal_msg.Args {
//            .serial = 1,
//            .path = dbus.strSlice(u32, "/org/freedesktop/DBus"),
//            .interface = dbus.strSlice(u32, "org.freedesktop.DBus"),
//            .member = dbus.strSlice(u32, "RequestName"),
//            .signature = "su",
//        };
//        var msg: [dbus.signal_msg.getHeaderLen(args)]u8 = undefined;
//        dbus.signal_msg.serialize(&msg, args);
//        try connection.writer().writeAll(&msg);
//    }

//    {
//        const args = comptime dbus.signal_msg.Args {
//            .serial = 1,
//            .path = dbus.strSlice(u32, "/test/signal/Object"),
//            .interface = dbus.strSlice(u32, "test.signal.Type"),
//            .member = dbus.strSlice(u32, "Test"),
//        };
//        var msg: [dbus.signal_msg.getHeaderLen(args)]u8 = undefined;
//        dbus.signal_msg.serialize(&msg, args);
//        try connection.writer().writeAll(&msg);
//    }
    return 0;
}
