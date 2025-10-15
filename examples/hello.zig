const std = @import("std");
const dbus = @import("dbus");
const hexdump = @import("hexdump.zig").hexdump;

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
                        try fixed.discard(reader);
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
    return 0;
}

fn hexdumpLine(line: []const u8) void {
    std.log.debug("{s}", .{line});
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}
