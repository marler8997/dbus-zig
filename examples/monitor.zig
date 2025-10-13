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

    var connection = dbus.Connection.connect(addr) catch |err| {
        std.log.info("failed to connect to '{s}': {s}", .{ session_addr_str.str, @errorName(err) });
        return 0xff;
    };
    // defer connection.deinit();
    std.log.info("connected to session bus '{s}', authenticating...", .{session_addr_str.str});
    try connection.authenticate();

    std.log.info("authenticated", .{});

    var write_buf: [1000]u8 = undefined;
    var socket_writer = dbus.socketWriter(connection.fd, &write_buf);
    const writer = &socket_writer.interface;

    try dbus.writeMethodCall(
        writer,
        //.signature = "su",
        &[0]dbus.Type{},
        .{
            .serial = 1,
            .path = dbus.strSlice(u32, "/org/freedesktop/DBus"),
            // TODO: do we need a destination?
            .destination = dbus.strSlice(u32, "org.freedesktop.DBus"),
            .interface = dbus.strSlice(u32, "org.freedesktop.DBus"),
            .member = dbus.strSlice(u32, "Hello"),
            //.signature = "su",
        },
        .{},
    );

    var read_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    var read_al: std.ArrayListAligned(u8, 8) = .init(read_arena.allocator());

    var name_buf: [dbus.max_name:0]u8 = undefined;

    const name = blk_name: {
        const msg = blk_recv: {
            while (true) {
                const msg = try readMsg(connection.reader(), &read_al);
                switch (msg.headers) {
                    .signal => {
                        std.log.info("ignoring signal {}", .{msg});
                        read_al.clearRetainingCapacity();
                    },
                    .method_return => |result| {
                        std.debug.assert(result.reply_serial == 1);
                        break :blk_recv msg;
                    },
                    .err => |err| {
                        std.debug.assert(err.reply_serial == 1);
                        fatal("Hello failed with error '{s}'", .{err.name});
                    },
                }
            }
        };

        defer read_al.clearRetainingCapacity();
        const name = dbus.parseString(msg.endian, read_al.items, msg.header_end) orelse fatal(
            "unexpected Hello response, invalid name string",
            .{},
        );
        if (name.end != read_al.items.len) fatal(
            "Hello response had {} bytes of extra data",
            .{read_al.items.len - name.end},
        );
        if (name.string.len > dbus.max_name) fatal(
            "our assigned name '{s}' is too big({} > {})",
            .{ name.string, name.string.len, dbus.max_name },
        );
        @memcpy(name_buf[0..name.string.len], name.string);
        name_buf[name.string.len] = 0;
        break :blk_name name_buf[0..name.string.len :0];
    };
    std.log.info("our name is '{s}'", .{name});

    while (true) {
        const msg = try readMsg(connection.reader(), &read_al);
        std.log.debug("--------------------------------------------------", .{});
        std.log.debug("got {}-byte msg:", .{read_al.items.len});
        const func = struct {
            pub fn log(line: []const u8) void {
                std.log.debug("{s}", .{line});
            }
        };
        @import("hexdump.zig").hexdump(func.log, read_al.items, .{});
        switch (msg.headers) {
            .method_return => |headers| {
                std.log.err("unexpected MethodReturn {}", .{headers});
                std.posix.exit(0xff);
            },
            .signal => |s| std.log.info(
                "Signal path='{s}' interface='{s}' member='{s}' dest='{?s}' sender='{?s}' sig='{?s}' unix_fds={?}",
                .{
                    s.path,
                    s.interface,
                    s.member,
                    s.destination,
                    s.sender,
                    s.signature,
                    s.unix_fds,
                },
            ),
            .err => |err| {
                fatal("got error '{s}'", .{err.name});
            },
        }
        read_al.clearRetainingCapacity();
    }

    return 0;
}

fn readMsg(reader: anytype, arraylist: *std.ArrayListAligned(u8, 8)) !dbus.ParsedMsg {
    std.debug.assert(arraylist.items.len == 0);
    try dbus.readOneMsgArrayList(reader, arraylist);
    return dbus.parseMsg(arraylist.items) catch |e| fatal(
        "parse dbus message failed with {s}",
        .{@errorName(e)},
    );
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}
