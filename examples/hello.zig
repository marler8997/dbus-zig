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

    const name = blk: {
        while (true) {
            const fixed = try dbus.readFixed(reader);
            switch (fixed.type) {
                .method_call => return error.UnexpectedDbusMethodCall,
                .method_return => {
                    const headers = try fixed.readMethodReturnHeaders(reader, &.{});
                    if (headers.reply_serial != 1) std.debug.panic("unexpected serial {}", .{headers.reply_serial});
                    const signature: ?[]const u8 = if (headers.signature) |*s| s.sliceConst() else null;
                    if (!std.mem.eql(u8, "s", if (signature) |s| s else "")) std.debug.panic("unexpected signature '{?s}'", .{signature});
                    const string_len = try reader.takeInt(u32, fixed.endian);
                    if (string_len > dbus.max_name) std.debug.panic("assigned name is too long {}", .{string_len});
                    const name_slice = try reader.take(string_len);
                    @memcpy(name_buf[0..string_len], name_slice);
                    const nullterm = try reader.takeByte();
                    if (nullterm != 0) {
                        std.log.err("Hello reply name missing null-terminator", .{});
                        return error.DbusProtocol;
                    }
                    break :blk name_buf[0..string_len];
                },
                .error_reply => {
                    @panic("todo");
                },
                .signal => {
                    std.log.info("ignoring signal", .{});
                    try fixed.discard(reader);
                },
            }
        }
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
