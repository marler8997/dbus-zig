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

    std.log.info("authenticated, requesting name...", .{});

//    {
//        const args = comptime dbus.signal_msg.Args {
//            .serial = 1,
//            .path = dbus.Slice(u32, [*]const u8).initComptime("/org/freedesktop/DBus"),
//            .interface = dbus.Slice(u32, [*]const u8).initComptime("org.freedesktop.DBus"),
//            .member = dbus.Slice(u32, [*]const u8).initComptime("RequestName"),
//            .signature = "su",
//        };
//        var msg: [dbus.signal_msg.getHeaderLen(args)]u8 = undefined;
//        dbus.signal_msg.serialize(&msg, args);
//        try connection.writer().writeAll(&msg);
//    }

    {
        const args = comptime dbus.signal_msg.Args {
            .serial = 1,
            .path = dbus.Slice(u32, [*]const u8).initComptime("/test/signal/Object"),
            .interface = dbus.Slice(u32, [*]const u8).initComptime("test.signal.Type"),
            .member = dbus.Slice(u32, [*]const u8).initComptime("Test"),
        };
        var msg: [dbus.signal_msg.getHeaderLen(args)]u8 = undefined;
        dbus.signal_msg.serialize(&msg, args);
        try connection.writer().writeAll(&msg);
    }
    return 0;
}
