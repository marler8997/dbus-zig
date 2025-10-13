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

    while (true) {
        const fixed = try dbus.readFixed(reader);
        switch (fixed.type) {
            .method_call => return error.UnexpectedDbusMethodCall,
            .method_return => return error.UnexpectedDbugsMethodReturn,
            .error_reply => {
                @panic("todo: deserialize error reply");
            },
            .signal => {
                var path_buf: [100]u8 = undefined;
                const headers = try fixed.readSignalHeaders(reader, &path_buf);
                std.log.info("signal:", .{});
                if (headers.path.len > path_buf.len) {
                    std.log.info("  path '{s}' (truncated from {} bytes to {})", .{ path_buf[0..headers.path.len], headers.path.len, path_buf.len });
                } else {
                    std.log.info("  path '{s}'", .{path_buf[0..headers.path.len]});
                }
                std.log.info("  interface '{f}'", .{headers.interface});
                std.log.info("  member '{f}'", .{headers.member});
                if (headers.error_name) |error_name| {
                    std.log.info("  error_name '{f}'", .{error_name});
                } else {
                    std.log.info("  error_name (none)", .{});
                }
                if (headers.reply_serial) |reply_serial| {
                    std.log.info("  reply_serial '{d}'", .{reply_serial});
                } else {
                    std.log.info("  reply_serial (none)", .{});
                }
                if (headers.destination) |destination| {
                    std.log.info("  destination '{f}'", .{destination});
                } else {
                    std.log.info("  destination (none)", .{});
                }
                if (headers.sender) |sender| {
                    std.log.info("  sender '{f}'", .{sender});
                } else {
                    std.log.info("  sender (none)", .{});
                }
                if (headers.signature) |signature| {
                    std.log.info("  signature '{f}'", .{signature});
                } else {
                    std.log.info("  signature (none)", .{});
                }
                std.log.info("  --- body ({} bytes) ---", .{fixed.body_len});
                var it: dbus.BodyIterator = .{
                    .endian = fixed.endian,
                    .body_len = fixed.body_len,
                    .signature = if (headers.signature) |s| s.sliceConst() else "",
                };
                while (try it.next(reader)) |value| switch (value) {
                    .string => |string| {
                        std.log.info("  string ({} bytes)", .{string.len});
                        var string_buf: [16]u8 = undefined;
                        var remaining: u32 = string.len;
                        while (remaining > 0) {
                            const consume_len = @min(string_buf.len, remaining);
                            try reader.readSliceAll(string_buf[0..consume_len]);
                            hexdump(hexdumpLine, string_buf[0..consume_len], .{});
                            remaining -= consume_len;
                        }
                        try dbus.consumeStringNullTerm(reader);
                        it.notifyStringConsumed();
                    },
                };
            },
        }
    }

    return 0;
}

fn hexdumpLine(line: []const u8) void {
    std.log.debug("{s}", .{line});
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}
