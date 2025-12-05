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
        const string_size = try dbus.read("s", &sig_index, .string_size)(&it, reader);
        const name_len: u8 = dbus.castNameLen(string_size) orelse std.debug.panic("assigned name is too long {}", .{string_size});
        try reader.readSliceAll(name_buf[0..name_len]);
        try dbus.consumeStringNullTerm(reader);
        it.notifyConsumed(.string);
        try it.finish("s", sig_index);
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
                        var stderr_buf: [1000]u8 = undefined;
                        var stderr_file = std.fs.File.stderr().writer(&stderr_buf);
                        try fixed.stream(reader, &stderr_file.interface);
                        try stderr_file.interface.flush();
                    },
                }
            }
        };

        const headers = try fixed.readMethodReturnHeaders(reader, &.{});
        try headers.expectReplySerial(2);
        try headers.expectSignature("s");
        var it: dbus.BodyIterator = .{
            .endian = fixed.endian,
            .body_len = fixed.body_len,
            .signature = headers.signatureSlice(),
        };
        comptime var sig_index: usize = 0;
        const string_size: u32 = try dbus.read("s", &sig_index, .string_size)(&it, reader);
        std.log.info("--- Introspect reply:", .{});
        var remaining: u32 = string_size;
        while (remaining > 0) {
            const take_len = @min(reader.buffer.len, remaining);
            const slice = try reader.take(take_len);
            std.debug.print("{s}", .{slice});
            remaining -= @intCast(slice.len);
        }
        try dbus.consumeStringNullTerm(reader);
        it.notifyConsumed(.string);
        std.log.info("---- end of Introspect reply", .{});
        try it.finish("s", sig_index);
    }

    return 0;
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}
