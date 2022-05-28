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

    {
        var buf: [1000]u8 align(8) = undefined;
        std.log.info("reading reply...", .{});
        const len = connection.reader().read(&buf) catch |err| switch (err) {
            //error.StreamTooLong => return error.MalformedReply,
            else => |e| return e,
        };
        if (len == 0) {
            std.log.info("read EOF", .{});
            return 0xff;
        }
        //std.log.info("reply is {} bytes: '{}'", .{len, std.zig.fmtEscapes(buf[0..len])});

        var offset: usize = 0;
        while (true) {
            const msg_len = (try dbus.getMsgLen(buf[offset..len])) orelse break;
            const msg_end = offset + msg_len;
            if (msg_end > buf.len) break;
            const msg = buf[offset..msg_end];
            std.log.info("got {}-byte msg '{}'", .{msg_len, std.zig.fmtEscapes(msg)});
            offset = msg_end;
            if (offset == len) break;
        }
        if (offset != len) {
            std.debug.panic("todo: handle partial messages", .{});
        }

        //switch (try dbus.parseMsg(buf[0..len])) {
        //.partial => {
        //@panic("todo");
    //},
    //}
    }


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
