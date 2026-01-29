pub fn handle(
    read_cmsg_buf: *dbus.cmsg.RecvBuffer(std.posix.fd_t),
    source: dbus.Source,
    response_writer: *dbus.MsgWriter,
    return_args: dbus.MethodReturn,
) !void {
    // this code tests and demonstrates that we can dynamically read/write data with
    // signatures that are not known until runtime

    // we first write the entire message to our own buffer so we can fill in the
    // body size (near the start of the message) after we've finished serializing it
    var hold_buffer: [2000]u8 = undefined;
    var hold_writer: dbus.Writer = .fixed(&hold_buffer);
    const writer = &hold_writer;

    _ = try dbus.write(writer, 0, "yyyyuu", .{
        dbus.endian_header_value,
        @intFromEnum(dbus.MessageType.method_return),
        0, // flags
        1, // protocol version
        0, // body placeholder
        return_args.serial,
    });
    const maybe_sig = source.bodySignature();
    const array_data_len = return_args.calcHeaderArrayLen(if (maybe_sig) |sig| .initAssume(sig.slice()) else null);
    try writer.writeInt(u32, array_data_len, dbus.native_endian);
    var header_align: u3 = 0;
    try dbus.writeHeaderU32(writer, &header_align, .reply_serial, return_args.reply_serial);
    if (return_args.destination) |arg| {
        try dbus.writeHeaderString(writer, &header_align, .destination, arg);
    }
    if (maybe_sig) |sig| {
        try dbus.writeHeaderSig(writer, &header_align, .initAssume(sig.slice()));
    }
    if (dbus.nonZeroFdCount(return_args.unix_fds)) |count| {
        try dbus.writeHeaderU32(writer, &header_align, .unix_fds, count);
    }
    try writer.splatByteAll(0, dbus.pad8Len(header_align));

    const body_start = writer.end;
    var fd: std.posix.fd_t = -1;
    defer if (fd != -1) {
        std.log.info("closing fd {} (echo sent)", .{fd});
        std.posix.close(fd);
    };

    const body_size: u32 = try echoBody(
        read_cmsg_buf,
        source,
        writer,
        if (maybe_sig) |s| s.slice() else "",
        0,
        &fd,
    );
    try source.bodyEnd();

    switch (return_args.unix_fds orelse 0) {
        0 => std.debug.assert(fd == -1),
        1 => std.debug.assert(fd != -1),
        else => unreachable,
    }

    std.debug.assert(writer.end - body_start == body_size);
    std.mem.writeInt(u32, hold_buffer[4..8], body_size, dbus.native_endian);

    std.debug.assert(response_writer.control == null);
    var write_entry: dbus.cmsg.Entry(std.posix.fd_t) = if (fd == -1) undefined else .{
        .level = std.os.linux.SOL.SOCKET,
        .type = dbus.SCM.RIGHTS,
        .data = fd,
    };
    if (fd != -1) response_writer.control = write_entry.singleEntryArray();
    defer response_writer.control = null;
    try response_writer.interface.writeAll(hold_buffer[0..writer.end]);
    try response_writer.interface.flush();
}

fn echoBody(
    read_cmsg_buf: *dbus.cmsg.RecvBuffer(std.posix.fd_t),
    source: dbus.Source,
    writer: *dbus.Writer,
    sig: []const u8,
    body_start: u32,
    fd_ref: *std.posix.fd_t,
) !u32 {
    var sig_offset: usize = 0;
    var write_body_offset: u32 = body_start;

    while (sig_offset < sig.len) switch (sig[sig_offset]) {
        'u' => {
            const value = try source.readBody(.u32, {});
            write_body_offset = try dbus.write(writer, write_body_offset, "u", .{value});
            sig_offset += 1;
        },
        'i' => {
            const value = try source.readBody(.i32, {});
            write_body_offset = try dbus.write(writer, write_body_offset, "i", .{value});
            sig_offset += 1;
        },
        'h' => {
            const fd_index = try source.readBody(.unix_fd_index, {});
            std.debug.assert(fd_index == 0);
            std.debug.assert(fd_ref.* == -1);
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            std.log.info("read_cmsg_buf.recv_len={}", .{read_cmsg_buf.recv_len});
            const data_len = read_cmsg_buf.dataLen();
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            std.log.info("data_len={}", .{data_len});
            std.debug.assert(data_len == @sizeOf(std.posix.fd_t));
            fd_ref.* = read_cmsg_buf.entry.data;
            std.debug.assert(fd_ref.* != -1);
            std.log.info("fd={}", .{fd_ref.*});
            write_body_offset = try dbus.write(writer, write_body_offset, "h", .{0});
            sig_offset += 1;
        },
        's' => {
            const string_size = try source.readBody(.string_size, {});
            write_body_offset = try dbus.writeStringSize(writer, write_body_offset, string_size);
            try source.dataStreamExact(writer, string_size + 1);
            write_body_offset += (string_size + 1);
            sig_offset += 1;
        },
        'v' => {
            var variant: dbus.SourceVariant = undefined;
            try source.readBody(.variant_sig, &variant);
            write_body_offset = try dbus.write(
                writer,
                write_body_offset,
                "g",
                .{variant.signature.sliceDbus()},
            );
            write_body_offset = try echoBody(
                read_cmsg_buf,
                source,
                writer,
                variant.signature.slice(),
                write_body_offset,
                fd_ref,
            );
            sig_offset += 1;
        },
        'a' => {
            std.debug.assert(sig_offset + 1 < sig.len);
            var array: dbus.SourceArray = undefined;
            try source.readBody(.array_size, &array);
            write_body_offset = try dbus.writeArraySize(
                writer,
                .fromSig(sig[sig_offset + 1]),
                write_body_offset,
                array.body_limit - source.bodyOffset(),
            );
            sig_offset += 1;

            const element_sig, const is_dict = blk: {
                if (sig[sig_offset] == '{') {
                    std.debug.assert(sig[array.sig_end - 1] == '}');
                    break :blk .{ sig[sig_offset + 1 .. array.sig_end - 1], true };
                }
                break :blk .{ sig[sig_offset..array.sig_end], false };
            };

            while (source.bodyOffset() < array.body_limit) {
                {
                    const pad_len = if (is_dict) dbus.pad8Len(@truncate(write_body_offset)) else 0;
                    try writer.splatByteAll(0, pad_len);
                    write_body_offset += pad_len;
                }
                write_body_offset = try echoBody(
                    read_cmsg_buf,
                    source,
                    writer,
                    element_sig,
                    write_body_offset,
                    fd_ref,
                );
            }
            sig_offset = array.sig_end;
        },
        '(' => {
            {
                const pad_len = dbus.pad8Len(@truncate(write_body_offset));
                try writer.splatByteAll(0, pad_len);
                write_body_offset += pad_len;
            }
            const sig_end = dbus.scanStructSig(sig, @intCast(sig_offset + 1));
            write_body_offset = try echoBody(
                read_cmsg_buf,
                source,
                writer,
                sig[sig_offset + 1 .. sig_end - 1],
                write_body_offset,
                fd_ref,
            );
            sig_offset = sig_end;
        },
        else => std.debug.panic("todo: handle sig char '{c}'", .{sig[sig_offset]}),
    };
    return write_body_offset;
}

const std = @import("std");
const dbus = @import("dbus");
