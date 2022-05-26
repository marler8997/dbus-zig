const std = @import("std");
const os = std.os;

const dbus = @import("dbus");

pub fn main() !u8 {

    const path = "/tmp/dbus-test";

    std.fs.cwd().deleteFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => |e| {
            std.log.err("failed to remove old socket file '{s}': {s}", .{path, @errorName(e)});
            return 0xff;
        },
    };
    
    const sock = os.socket(os.AF.UNIX, os.SOCK.STREAM, 0) catch |err| {
        std.log.err("failed to create unix socket: {s}", .{@errorName(err)});
        return 0xff;
    };
    //errdefer os.close(sock);

    var sockaddr = os.sockaddr.un { .family = os.AF.UNIX, .path = undefined };

    const addr_len = @intCast(os.socklen_t, @offsetOf(os.sockaddr.un, "path") + path.len + 1);
    if (addr_len > @sizeOf(os.sockaddr.un)) {
        std.log.err("unix socket path len {} is too big", .{path.len});
        return 0xff;
    }
    @memcpy(&sockaddr.path, path, path.len);
    sockaddr.path[path.len] = 0;
    
    os.bind(sock, @ptrCast(*os.sockaddr, &sockaddr), addr_len) catch |err| {
        std.log.err("failed to bind unix socket to '{s}': {s}", .{path, @errorName(err)});
        return 0xff;
    };
    std.log.info("bound socket to '{s}'", .{path});

    os.listen(sock, 10) catch |err| {
        std.log.err("unix socket listen failed with {s}", .{@errorName(err)});
        return 0xff;
    };

    
    while (true) {
        var buf: [2000]u8 = undefined;
        const len = os.read(sock, &buf) catch |err| {
            std.log.err("failed to read unix socket: {s}", .{@errorName(err)});
            return 0xff;
        };
        if (len == 0) {
            std.log.err("read EOF on unix socket?", .{});
            return 0xff;
        }
        std.log.info("read {} from unix socket: '{}'", .{len, std.zig.fmtEscapes(buf[0 .. len])});
    }

    return 0;
}
