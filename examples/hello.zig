const std = @import("std");
const dbus = @import("dbus");

pub fn main() !u8 {
    const session_addr_str = dbus.getSessionBusAddressString();
    const addr = dbus.Address.fromString(session_addr_str.str) catch |err| {
        switch (session_addr_str.origin) {
            .hardcoded_default => unreachable,
            .environment_variable => {
                std.log.err("invalid dbus address from environment variable '{s}': {s}", .{ session_addr_str.str, @errorName(err) });
            },
        }
        return 0xff;
    };

    const stream = dbus.connect(addr) catch |err| {
        std.log.info("failed to connect to '{s}': {s}", .{ session_addr_str.str, @errorName(err) });
        return 0xff;
    };
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
        "",
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
                    return 0xff;
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

    try dbus.writeMethodCall(
        writer,
        "", // signature
        .{
            .serial = 2,
            .path = .initStatic("/org/freedesktop/portal/desktop"),
            .destination = .initStatic("org.freedesktop.portal.Desktop"),
            .interface = .initStatic("org.freedesktop.DBus.Introspectable"),
            .member = .initStatic("Introspect"),
        },
        .{}, // No body
    );
    try writer.flush();

    {
        while (true) {
            const msg_start = try source.readMsgStart();
            switch (msg_start.type) {
                .method_call => return error.UnexpectedDbusMethodCall,
                .method_return => break,
                .error_reply => {
                    std.log.err("received error:", .{});
                    try source.streamRemaining(stderr);
                    try stderr.flush();
                    return 0xff;
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
        try headers.expectReplySerial(2);
        try source.expectSignature("s");
        const string_size = try source.readBody(.string_size, {});
        const string_limit = source.bodyOffset() + string_size + 1;
        std.log.info("--- Introspect reply:", .{});
        while (source.bodyOffset() + 1 < string_limit) {
            const remaining = source.dataRemaining();
            if (remaining == 1) break;
            const take_len = @min(remaining - 1, source.reader.buffer.len);
            std.debug.print("{s}", .{try source.dataTake(take_len)});
        }
        std.log.info("---- end of Introspect reply", .{});
        try source.dataReadNullTerm();
        try source.bodyEnd();
    }

    return 0;
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}
