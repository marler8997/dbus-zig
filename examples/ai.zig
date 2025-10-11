const std = @import("std");
const dbus = @import("dbus");

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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

    var serial: u32 = 1;

    // Send Hello to get our unique name
    {
        const args = comptime dbus.method_call_msg.Args{
            .serial = 1,
            .path = dbus.strSlice(u32, "/org/freedesktop/DBus"),
            .destination = dbus.strSlice(u32, "org.freedesktop.DBus"),
            .interface = dbus.strSlice(u32, "org.freedesktop.DBus"),
            .member = dbus.strSlice(u32, "Hello"),
        };
        var msg: [dbus.method_call_msg.getHeaderLen(args)]u8 = undefined;
        dbus.method_call_msg.serialize(&msg, args);
        try connection.writer().writeAll(&msg);
        serial += 1;
    }

    const recv_buf_len = 8192;

    // Get our unique name
    var our_name: []const u8 = undefined;
    {
        var buf: [recv_buf_len]u8 align(8) = undefined;
        const result = recvMethodReturn(connection.reader(), &buf, 1);

        // Parse the string from the body: signature + string length + string
        if (result.body.len >= 4) {
            const str_len = std.mem.readInt(u32, result.body[0..4], .little);
            our_name = result.body[4 .. 4 + str_len];
            std.log.info("our unique name: {s}", .{our_name});
        }
    }

    // Generate tokens
    const session_token = try generateToken(allocator);
    defer allocator.free(session_token);

    const request_token = try generateToken(allocator);
    defer allocator.free(request_token);

    // Build request path - strip leading ':' from unique name
    const sender_token = if (our_name[0] == ':') our_name[1..] else our_name;
    const request_path = try std.fmt.allocPrint(allocator, "/org/freedesktop/portal/desktop/request/{s}/{s}", .{ sender_token, request_token });
    defer allocator.free(request_path);

    std.log.info("request path: {s}", .{request_path});

    // Step 1: CreateSession
    {
        std.log.info("calling CreateSession...", .{});
        try callCreateSession(&connection, serial, request_token, session_token);
        serial += 1;
    }

    // Wait for Response signal with session handle
    var session_handle: []const u8 = undefined;
    var session_handle_owned: ?[]u8 = null;
    defer if (session_handle_owned) |h| allocator.free(h);

    {
        var buf: [recv_buf_len]u8 align(8) = undefined;
        session_handle_owned = try waitForResponse(connection.reader(), &buf, request_path, allocator);
        session_handle = session_handle_owned.?;
        std.log.info("session handle: {s}", .{session_handle});
    }

    // Step 2: SelectSources
    const select_token = try generateToken(allocator);
    defer allocator.free(select_token);

    const select_path = try std.fmt.allocPrint(allocator, "/org/freedesktop/portal/desktop/request/{s}/{s}", .{ sender_token, select_token });
    defer allocator.free(select_path);

    {
        std.log.info("calling SelectSources...", .{});
        try callSelectSources(&connection, serial, session_handle, select_token);
        serial += 1;
    }

    // Wait for SelectSources response
    {
        var buf: [recv_buf_len]u8 align(8) = undefined;
        const result = try waitForResponse(connection.reader(), &buf, select_path, allocator);
        defer allocator.free(result);
        std.log.info("sources selected", .{});
    }

    // Step 3: Start
    const start_token = try generateToken(allocator);
    defer allocator.free(start_token);

    const start_path = try std.fmt.allocPrint(allocator, "/org/freedesktop/portal/desktop/request/{s}/{s}", .{ sender_token, start_token });
    defer allocator.free(start_path);

    {
        std.log.info("calling Start...", .{});
        try callStart(&connection, serial, session_handle, start_token);
        serial += 1;
    }

    // Wait for Start response with stream info
    {
        var buf: [recv_buf_len]u8 align(8) = undefined;
        const result = try waitForResponse(connection.reader(), &buf, start_path, allocator);
        defer allocator.free(result);
        std.log.info("stream started!", .{});

        // TODO: Parse the streams array to get PipeWire node ID
        // The response contains: a(ua{sv}) - array of (node_id, properties)
    }

    std.log.info("Screen capture session active!", .{});

    // Keep receiving messages
    while (true) {
        var buf: [recv_buf_len]u8 align(8) = undefined;
        const msg_len = switch (dbus.readOneMsg(connection.reader(), &buf) catch |err| {
            std.log.err("failed to read dbus msg with {s}", .{@errorName(err)});
            std.posix.exit(0xff);
        }) {
            .partial => |len| {
                std.log.err("buffer of size {} is not large enough (need {})", .{ buf.len, len });
                std.posix.exit(0xff);
            },
            .complete => |len| len,
        };

        std.log.debug("got {}-byte msg:", .{msg_len});
        const parsed = dbus.parseMsgAssumeGetMsgLen(dbus.sliceLen(@as([*]align(8) const u8, &buf), msg_len)) catch |err| {
            std.log.err("malformed reply: {s}", .{@errorName(err)});
            continue;
        };
        switch (parsed.headers) {
            .method_return => |headers| {
                std.log.info("unexpected MethodReturn (serial={})", .{headers.reply_serial});
            },
            .signal => |headers| {
                const member = std.mem.sliceTo(&headers.member, 0);
                std.log.info("Signal: {s}", .{member});
            },
        }
    }

    return 0;
}

fn generateToken(allocator: std.mem.Allocator) ![]const u8 {
    var buf: [16]u8 = undefined;
    std.crypto.random.bytes(&buf);
    return std.fmt.allocPrint(allocator, "token{x}", .{std.fmt.fmtSliceHexLower(&buf)});
}

fn callCreateSession(connection: *dbus.Connection, serial: u32, handle_token: []const u8, session_token: []const u8) !void {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    // Serialize header
    const args = comptime dbus.method_call_msg.Args{
        .serial = 0, // Will be set below
        .path = dbus.strSlice(u32, "/org/freedesktop/portal/desktop"),
        .destination = dbus.strSlice(u32, "org.freedesktop.portal.Desktop"),
        .interface = dbus.strSlice(u32, "org.freedesktop.portal.ScreenCast"),
        .member = dbus.strSlice(u32, "CreateSession"),
        .signature = "a{sv}",
    };

    var header_buf: [dbus.method_call_msg.getHeaderLen(args)]u8 = undefined;
    dbus.method_call_msg.serialize(&header_buf, args);
    std.mem.writeInt(u32, header_buf[8..12], serial, .little);

    try writer.writeAll(&header_buf);

    // Align to 8 for body
    const padding = (8 - (header_buf.len % 8)) % 8;
    try writer.writeByteNTimes(0, padding);

    const body_start = fbs.pos;

    // Write options dictionary: a{sv}
    const dict_len_pos = fbs.pos;
    try writer.writeInt(u32, 0, .little); // Placeholder
    const dict_start = fbs.pos;

    // Add handle_token entry
    try writeDictEntry(writer, "handle_token", 's', handle_token);

    // Add session_handle_token entry
    try writeDictEntry(writer, "session_handle_token", 's', session_token);

    // Write dict length
    const dict_len = fbs.pos - dict_start;
    std.mem.writeInt(u32, buf[dict_len_pos..][0..4], @intCast(dict_len), .little);

    // Update body length in header
    const body_len = fbs.pos - body_start;
    std.mem.writeInt(u32, buf[4..8], @intCast(body_len), .little);

    try connection.writer().writeAll(buf[0..fbs.pos]);
}

fn callSelectSources(connection: *dbus.Connection, serial: u32, session_handle: []const u8, handle_token: []const u8) !void {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    const args = comptime dbus.method_call_msg.Args{
        .serial = 0,
        .path = dbus.strSlice(u32, "/org/freedesktop/portal/desktop"),
        .destination = dbus.strSlice(u32, "org.freedesktop.portal.Desktop"),
        .interface = dbus.strSlice(u32, "org.freedesktop.portal.ScreenCast"),
        .member = dbus.strSlice(u32, "SelectSources"),
        .signature = "oa{sv}",
    };

    var header_buf: [dbus.method_call_msg.getHeaderLen(args)]u8 = undefined;
    dbus.method_call_msg.serialize(&header_buf, args);
    std.mem.writeInt(u32, header_buf[8..12], serial, .little);

    try writer.writeAll(&header_buf);
    const padding = (8 - (header_buf.len % 8)) % 8;
    try writer.writeByteNTimes(0, padding);

    const body_start = fbs.pos;

    // Write session handle (object path)
    try writer.writeInt(u32, @intCast(session_handle.len), .little);
    try writer.writeAll(session_handle);
    try writer.writeByte(0);

    // Align to 4 for dict
    const pos = fbs.pos;
    const align_padding = (4 - (pos % 4)) % 4;
    try writer.writeByteNTimes(0, align_padding);

    // Write options dictionary
    const dict_len_pos = fbs.pos;
    try writer.writeInt(u32, 0, .little);
    const dict_start = fbs.pos;

    try writeDictEntry(writer, "handle_token", 's', handle_token);

    // types: 1=monitor, 2=window, 4=virtual
    try writeDictEntryUint(writer, "types", 7); // All types

    // multiple: allow multiple selections
    try writeDictEntryBool(writer, "multiple", false);

    const dict_len = fbs.pos - dict_start;
    std.mem.writeInt(u32, buf[dict_len_pos..][0..4], @intCast(dict_len), .little);

    const body_len = fbs.pos - body_start;
    std.mem.writeInt(u32, buf[4..8], @intCast(body_len), .little);

    try connection.writer().writeAll(buf[0..fbs.pos]);
}

fn callStart(connection: *dbus.Connection, serial: u32, session_handle: []const u8, handle_token: []const u8) !void {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    const args = comptime dbus.method_call_msg.Args{
        .serial = 0,
        .path = dbus.strSlice(u32, "/org/freedesktop/portal/desktop"),
        .destination = dbus.strSlice(u32, "org.freedesktop.portal.Desktop"),
        .interface = dbus.strSlice(u32, "org.freedesktop.portal.ScreenCast"),
        .member = dbus.strSlice(u32, "Start"),
        .signature = "osa{sv}",
    };

    var header_buf: [dbus.method_call_msg.getHeaderLen(args)]u8 = undefined;
    dbus.method_call_msg.serialize(&header_buf, args);
    std.mem.writeInt(u32, header_buf[8..12], serial, .little);

    try writer.writeAll(&header_buf);
    const padding = (8 - (header_buf.len % 8)) % 8;
    try writer.writeByteNTimes(0, padding);

    const body_start = fbs.pos;

    // Session handle (object path)
    try writer.writeInt(u32, @intCast(session_handle.len), .little);
    try writer.writeAll(session_handle);
    try writer.writeByte(0);

    // Align to 4 for string
    var pos = fbs.pos;
    var align_padding = (4 - (pos % 4)) % 4;
    try writer.writeByteNTimes(0, align_padding);

    // Parent window (empty string)
    try writer.writeInt(u32, 0, .little);
    try writer.writeByte(0);

    // Align to 4 for dict
    pos = fbs.pos;
    align_padding = (4 - (pos % 4)) % 4;
    try writer.writeByteNTimes(0, align_padding);

    // Options dictionary
    const dict_len_pos = fbs.pos;
    try writer.writeInt(u32, 0, .little);
    const dict_start = fbs.pos;

    try writeDictEntry(writer, "handle_token", 's', handle_token);

    const dict_len = fbs.pos - dict_start;
    std.mem.writeInt(u32, buf[dict_len_pos..][0..4], @intCast(dict_len), .little);

    const body_len = fbs.pos - body_start;
    std.mem.writeInt(u32, buf[4..8], @intCast(body_len), .little);

    try connection.writer().writeAll(buf[0..fbs.pos]);
}

fn writeDictEntry(writer: anytype, key: []const u8, type_char: u8, value: []const u8) !void {
    // Align dict entry to 8
    const pos = try writer.context.getPos();
    const padding = (8 - (pos % 8)) % 8;
    try writer.writeByteNTimes(0, padding);

    // Key (string)
    try writer.writeInt(u32, @intCast(key.len), .little);
    try writer.writeAll(key);
    try writer.writeByte(0);

    // Variant signature
    try writer.writeByte(1); // Signature length
    try writer.writeByte(type_char);
    try writer.writeByte(0);

    // Value (string)
    try writer.writeInt(u32, @intCast(value.len), .little);
    try writer.writeAll(value);
    try writer.writeByte(0);
}

fn writeDictEntryUint(writer: anytype, key: []const u8, value: u32) !void {
    const pos = try writer.context.getPos();
    const padding = (8 - (pos % 8)) % 8;
    try writer.writeByteNTimes(0, padding);

    try writer.writeInt(u32, @intCast(key.len), .little);
    try writer.writeAll(key);
    try writer.writeByte(0);

    try writer.writeByte(1);
    try writer.writeByte('u');
    try writer.writeByte(0);

    // Align to 4 for u32
    const pos2 = try writer.context.getPos();
    const padding2 = (4 - (pos2 % 4)) % 4;
    try writer.writeByteNTimes(0, padding2);

    try writer.writeInt(u32, value, .little);
}

fn writeDictEntryBool(writer: anytype, key: []const u8, value: bool) !void {
    const pos = try writer.context.getPos();
    const padding = (8 - (pos % 8)) % 8;
    try writer.writeByteNTimes(0, padding);

    try writer.writeInt(u32, @intCast(key.len), .little);
    try writer.writeAll(key);
    try writer.writeByte(0);

    try writer.writeByte(1);
    try writer.writeByte('b');
    try writer.writeByte(0);

    // Align to 4 for bool
    const pos2 = try writer.context.getPos();
    const padding2 = (4 - (pos2 % 4)) % 4;
    try writer.writeByteNTimes(0, padding2);

    try writer.writeInt(u32, if (value) 1 else 0, .little);
}

fn waitForResponse(reader: anytype, buf: []align(8) u8, expected_path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    while (true) {
        const msg_len = switch (dbus.readOneMsg(reader, buf) catch |err| {
            std.log.err("failed to read msg: {s}", .{@errorName(err)});
            return error.ReadFailed;
        }) {
            .partial => |len| {
                std.log.err("buffer too small (need {})", .{len});
                return error.BufferTooSmall;
            },
            .complete => |len| len,
        };

        const parsed = dbus.parseMsgAssumeGetMsgLen(dbus.sliceLen(@as([*]align(8) const u8, buf.ptr), msg_len)) catch |err| {
            std.log.err("malformed msg: {s}", .{@errorName(err)});
            continue;
        };

        switch (parsed.headers) {
            .signal => |headers| {
                const path = std.mem.sliceTo(&headers.path, 0);
                const member = std.mem.sliceTo(&headers.member, 0);

                if (std.mem.eql(u8, path, expected_path) and
                    std.mem.eql(u8, member, "Response"))
                {

                    // Parse response: (ua{sv})
                    const response_code = std.mem.readInt(u32, parsed.body[0..4], .little);
                    std.log.info("response code: {}", .{response_code});

                    if (response_code != 0) {
                        return error.PortalRequestFailed;
                    }

                    // Try to extract session_handle if present
                    const key = "session_handle";
                    if (std.mem.indexOf(u8, parsed.body, key)) |idx| {
                        var pos = idx + key.len + 1;

                        // Find variant signature
                        while (pos < parsed.body.len and parsed.body[pos] != 1) : (pos += 1) {}
                        if (pos >= parsed.body.len) return try allocator.dupe(u8, "");

                        pos += 1;
                        if (pos >= parsed.body.len) return try allocator.dupe(u8, "");
                        const sig = parsed.body[pos];
                        if (sig != 'o' and sig != 's') return try allocator.dupe(u8, "");
                        pos += 2;

                        // Align to 4
                        pos = std.mem.alignForward(usize, pos, 4);
                        if (pos + 4 > parsed.body.len) return try allocator.dupe(u8, "");

                        const str_len = std.mem.readInt(u32, parsed.body[pos..][0..4], .little);
                        pos += 4;

                        if (pos + str_len > parsed.body.len) return try allocator.dupe(u8, "");
                        return try allocator.dupe(u8, parsed.body[pos .. pos + str_len]);
                    }

                    return try allocator.dupe(u8, "");
                }
            },
            .method_return => {},
        }
    }
}

fn recvMethodReturn(reader: anytype, buf: []align(8) u8, serial: u32) dbus.ParsedMsg {
    while (true) {
        std.log.info("waiting for method return msg (serial={})...", .{serial});
        const msg_len = switch (dbus.readOneMsg(reader, buf) catch |err| {
            std.log.err("failed to read dbus msg with {s}", .{@errorName(err)});
            std.posix.exit(0xff);
        }) {
            .partial => |len| {
                std.log.err("buffer of size {} is not large enough (need {})", .{ buf.len, len });
                std.posix.exit(0xff);
            },
            .complete => |len| len,
        };

        const parsed = dbus.parseMsgAssumeGetMsgLen(dbus.sliceLen(@as([*]align(8) const u8, buf.ptr), msg_len)) catch |err| {
            std.log.err("malformed reply: {s}", .{@errorName(err)});
            std.posix.exit(0xff);
        };
        switch (parsed.headers) {
            .method_return => |headers| {
                if (serial != headers.reply_serial) {
                    std.log.info("expected method return serial {} but got {}", .{ serial, headers.reply_serial });
                    continue;
                }
                return parsed;
            },
            .signal => |headers| {
                const member = std.mem.sliceTo(&headers.member, 0);
                std.log.info("Signal: {s}", .{member});
            },
        }
    }
}
