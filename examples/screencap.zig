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
        //.signature = "su",
        &[0]dbus.Type{},
        .{
            .serial = 1,
            .path = .initStatic("/org/freedesktop/DBus"),
            // TODO: do we need a destination?
            .destination = .initStatic("org.freedesktop.DBus"),
            .interface = .initStatic("org.freedesktop.DBus"),
            .member = .initStatic("Hello"),
        },
        .{},
    );

    try writer.flush();

    var name_buf: [dbus.max_name:0]u8 = undefined;

    const name = blk_name: {
        const fixed = blk_fixed: {
            while (true) {
                const fixed = try dbus.readFixed(reader);
                switch (fixed.type) {
                    .method_call => return error.UnexpectedDbusMethodCall,
                    .method_return => break :blk_fixed fixed,
                    .error_reply => {
                        @panic("todo: handle error_reply");
                    },
                    .signal => {
                        std.log.info("ignoring signal", .{});
                        try fixed.discardHeaders(reader);
                        try fixed.discardBody(reader);
                    },
                }
            }
        };
        const headers = try fixed.readMethodReturnHeaders(reader, &.{});
        if (headers.reply_serial != 1) std.debug.panic("unexpected serial {}", .{headers.reply_serial});
        var it: dbus.BodyIterator = .{
            .endian = fixed.endian,
            .body_len = fixed.body_len,
            .signature = headers.signatureSlice(),
        };
        const string_len = blk: {
            switch (try it.next(reader) orelse @panic("Hello reply is missing string name")) {
                .string => |string| {
                    if (string.len > dbus.max_name) std.debug.panic("assigned name is too long {}", .{string.len});
                    try reader.readSliceAll(name_buf[0..string.len]);
                    try dbus.consumeStringNullTerm(reader);
                    it.notifyStringConsumed();
                    break :blk string.len;
                },
            }
        };
        if (try it.next(reader) != null) @panic("Hello reply body contains more than expected");
        break :blk_name name_buf[0..string_len];
    };

    std.log.info("our name is '{s}'", .{name});

    try dbus.writeMethodCall(
        writer,
        &[_]dbus.Type{ .string, .string },
        .{
            .serial = 2,
            .path = .initStatic("/org/freedesktop/portal/desktop"),
            .destination = .initStatic("org.freedesktop.portal.Desktop"),
            .interface = .initStatic("org.freedesktop.DBus.Properties"),
            .member = .initStatic("Get"),
        },
        .{
            .initStatic("org.freedesktop.portal.Desktop"), // Changed!
            // .initStatic("org.freedesktop.portal.ScreenCast"),
            .initStatic("version"),
        },
    );

    try writer.flush();

    // Read the version response
    const version = blk_version: {
        const fixed = blk_fixed: {
            while (true) {
                const fixed = try dbus.readFixed(reader);
                switch (fixed.type) {
                    .method_call => return error.UnexpectedDbusMethodCall,
                    .method_return => break :blk_fixed fixed,
                    .error_reply => {
                        @panic("todo: handle error reply");
                    },
                    .signal => {
                        std.log.info("ignoring signal", .{});
                        try fixed.readAndLog(reader);
                    },
                }
            }
        };

        const headers = try fixed.readMethodReturnHeaders(reader, &.{});
        if (headers.reply_serial != 2) std.debug.panic("unexpected serial {}", .{headers.reply_serial});
        var it: dbus.BodyIterator = .{
            .endian = fixed.endian,
            .body_len = fixed.body_len,
            .signature = headers.signatureSlice(),
        };
        _ = &it;
        if (true) @panic("todo");
        break :blk_version "";
        // const string_len = blk: {
        //     switch (try it.next(reader) orelse @panic("Hello reply is missing string name")) {
        //         .string => |string| {
        //             if (string.len > dbus.max_name) std.debug.panic("assigned name is too long {}", .{string.len});
        //             try reader.readSliceAll(name_buf[0..string.len]);
        //             try dbus.consumeStringNullTerm(reader);
        //             it.notifyStringConsumed();
        //             break :blk string.len;
        //         },
        //     }
        // };
        // if (try it.next(reader) != null) @panic("Hello reply body contains more than expected");
        // break :blk_name name_buf[0..string_len];

        // const msg = blk_recv: {
        //     while (true) {
        //         const msg = try readMsg(connection.reader(), &read_al);
        //         switch (msg.headers) {
        //             .signal => {
        //                 std.log.info("ignoring signal {}", .{msg});
        //                 read_al.clearRetainingCapacity();
        //             },
        //             .method_return => |result| {
        //                 std.debug.assert(result.reply_serial == 2);
        //                 break :blk_recv msg;
        //             },
        //             .err => |err| {
        //                 std.debug.assert(err.reply_serial == 2);
        //                 fatal("Get version failed with error '{s}'", .{err.name});
        //             },
        //         }
        //     }
        // };

        // defer read_al.clearRetainingCapacity();
        // // The response should be a VARIANT containing a UINT32
        // // TODO: parse the variant and extract the version number
        // _ = msg;
        // std.log.info("received version response, parsing...", .{});

        // // Placeholder - you'll need to properly parse the D-Bus variant
        // const version: u32 = 4; // Default assumption
        // break :blk_version version;
    };

    std.log.info("ScreenCast portal version: {}", .{version});

    // TODO: list the available source types

    try dbus.writeMethodCall(
        writer,
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // "a{sv}
        &[_]dbus.Type{},
        .{
            .serial = 2,
            .path = .initStatic("/org/freedesktop/portal/desktop"),
            .destination = .initStatic("org.freedesktop.portal.Desktop"),
            .interface = .initStatic("org.freedesktop.portal.ScreenCast"),
            .member = .initStatic("CreateSession"),
        },
        // CreateSession (
        //   IN handle o,
        //   IN session_handle o,
        //   IN app_id s,
        //   IN options a{sv},
        //   OUT response u,
        //   OUT results a{sv}
        // )
        .{},
    );

    // const wait_count = 2;
    // var msg_recv_count: u32 = 0;
    // while (true) {
    //     const msg = try readMsg(connection.reader(), &read_al);
    //     std.log.debug("--------------------------------------------------", .{});
    //     std.log.debug("got {}-byte msg:", .{read_al.items.len});
    //     const func = struct {
    //         pub fn log(line: []const u8) void {
    //             std.log.debug("{s}", .{line});
    //         }
    //     };
    //     @import("hexdump.zig").hexdump(func.log, read_al.items, .{});
    //     switch (msg.headers) {
    //         .method_return => |headers| {
    //             std.log.err("unexpected MethodReturn {}", .{headers});
    //             std.posix.exit(0xff);
    //         },
    //         .signal => |s| std.log.info(
    //             "Signal path='{s}' interface='{s}' member='{s}' dest='{?s}' sender='{?s}' sig='{?s}' unix_fds={?}",
    //             .{
    //                 s.path,
    //                 s.interface,
    //                 s.member,
    //                 s.destination,
    //                 s.sender,
    //                 s.signature,
    //                 s.unix_fds,
    //             },
    //         ),
    //         .err => |err| {
    //             fatal("got error '{s}'", .{err.name});
    //         },
    //     }
    //     read_al.clearRetainingCapacity();
    //     msg_recv_count += 1;
    //     if (msg_recv_count >= wait_count) break;
    // }

    if (true) {
        std.log.err("todo", .{});
        return 0;
    }

    return 0;
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}
