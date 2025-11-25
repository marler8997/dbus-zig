const builtin = @import("builtin");
const std = @import("std");

pub const address = @import("dbus/address.zig");
pub const Address = address.Address;

const log_dbus = std.log.scoped(.dbus);

pub const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;
const zig_atleast_15_2 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 2 }) != .lt;

const std15 = if (zig_atleast_15) std else @import("std15");
pub const Stream15 = if (zig_atleast_15) std.net.Stream else std15.net.Stream15;
pub const File15 = if (zig_atleast_15) std.fs.File else std15.fs.File15;

pub const Writer = std15.Io.Writer;
pub const Reader = std15.Io.Reader;

pub fn socketWriter(stream: std.net.Stream, buffer: []u8) Stream15.Writer {
    if (zig_atleast_15) return stream.writer(buffer);
    return .init(stream, buffer);
}
pub fn socketReader(stream: std.net.Stream, buffer: []u8) Stream15.Reader {
    if (zig_atleast_15) return stream.reader(buffer);
    return .init(stream, buffer);
}

const default_system_bus_path = "/var/run/dbus/system_bus_socket";
pub const default_system_bus_address_str = "unix:path=" ++ default_system_bus_path;
//pub const default_system_bus_address = comptime blk: {
//    .unix = .{ .path =
//};

// This maximum length applies to bus names, interfaces and members
pub const max_name = 255;
pub const max_sig = 255;

pub const BusAddressString = struct {
    origin: enum { hardcoded_default, environment_variable },
    str: []const u8,
};

pub const DBUS_SESSION_BUS_ADDRESS = "DBUS_SESSION_BUS_ADDRESS";

pub fn getSystemBusAddress() Address {
    @panic("todo");
    //return std.os.getenv("DBUS_SYSTEM_BUS_ADDRESS") orelse default_system_bus_address;
}
pub fn getSessionBusAddressString() BusAddressString {
    if (std.posix.getenv(DBUS_SESSION_BUS_ADDRESS)) |s|
        return BusAddressString{ .origin = .environment_variable, .str = s };
    return BusAddressString{ .origin = .hardcoded_default, .str = default_system_bus_address_str };
}

pub const ConnectError = if (zig_atleast_15) error{
    DbusAddrUnixPathTooBig,
    DbusAddrBadEscapeSequence,
    AccessDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    AddressInUse,
    ConnectionRefused,
    ConnectionTimedOut,
    FileNotFound,
} else error{
    DbusAddrUnixPathTooBig,
    DbusAddrBadEscapeSequence,
    PermissionDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    AddressInUse,
    ConnectionRefused,
    ConnectionTimedOut,
    FileNotFound,
};
pub fn connect(addr: Address) ConnectError!std.net.Stream {
    switch (addr) {
        .unix => |unix_addr| {
            var sockaddr = std.posix.sockaddr.un{ .family = std.posix.AF.UNIX, .path = undefined };
            const path_len = address.resolveEscapes(&sockaddr.path, unix_addr.unescaped_path) catch |err| switch (err) {
                error.DestTooSmall => return error.DbusAddrUnixPathTooBig,
                error.BadEscapeSequence => return error.DbusAddrBadEscapeSequence,
            };
            if (path_len == sockaddr.path.len) return error.DbusAddrUnixPathTooBig;
            sockaddr.path[path_len] = 0;

            const sock = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0) catch |err| if (zig_atleast_15) switch (err) {
                error.AccessDenied,
                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                error.SystemResources,
                => |e| return e,
                error.ProtocolFamilyNotAvailable,
                error.AddressFamilyNotSupported,
                error.ProtocolNotSupported,
                error.SocketTypeNotSupported,
                error.Unexpected,
                => unreachable,
            } else switch (err) {
                error.PermissionDenied,
                error.ProcessFdQuotaExceeded,
                error.SystemFdQuotaExceeded,
                error.SystemResources,
                => |e| return e,
                error.ProtocolFamilyNotAvailable,
                error.AddressFamilyNotSupported,
                error.ProtocolNotSupported,
                error.SocketTypeNotSupported,
                error.Unexpected,
                => unreachable,
            };
            errdefer std.posix.close(sock);

            const addr_len: std.posix.socklen_t = @intCast(@offsetOf(std.posix.sockaddr.un, "path") + path_len + 1);

            // TODO: should we set any socket options?
            std.posix.connect(sock, @as(*std.posix.sockaddr, @ptrCast(&sockaddr)), addr_len) catch |err| if (zig_atleast_15) switch (err) {
                error.PermissionDenied => return error.AccessDenied,
                error.AccessDenied,
                error.AddressInUse,
                error.SystemResources,
                error.ConnectionRefused,
                error.ConnectionTimedOut,
                error.FileNotFound,
                => |e| return e,
                error.Unexpected => @panic("unexpected errno from connect"),
                error.AddressNotAvailable, // doesn't apply to unix sockets
                error.NetworkUnreachable, // doesn't apply to unix sockets (I think)
                error.ConnectionResetByPeer, // doesn't applyt to unix sockets
                error.WouldBlock, // shouldn't happen to a blocking socket
                error.ConnectionPending, // shouldn't happen to a blocking socket
                error.AddressFamilyNotSupported,
                => unreachable,
            } else switch (err) {
                error.PermissionDenied,
                error.AddressInUse,
                error.SystemResources,
                error.ConnectionRefused,
                error.ConnectionTimedOut,
                error.FileNotFound,
                => |e| return e,
                error.Unexpected => @panic("unexpected errno from connect"),
                error.AddressNotAvailable, // doesn't apply to unix sockets
                error.NetworkUnreachable, // doesn't apply to unix sockets (I think)
                error.ConnectionResetByPeer, // doesn't applyt to unix sockets
                error.WouldBlock, // shouldn't happen to a blocking socket
                error.ConnectionPending, // shouldn't happen to a blocking socket
                error.AddressFamilyNotSupported,
                => unreachable,
            };
            return .{ .handle = sock };
        },
    }
}

pub const MessageType = enum(u8) {
    method_call = 1,
    method_return = 2,
    error_reply = 3,
    signal = 4,
};
pub const MessageFlags = packed struct(u8) {
    no_reply: bool,
    no_auto_start: bool,
    reserved1: bool,
    allow_interactive_auth: bool,
    reserved2: u4,
};

pub const native_endian = builtin.cpu.arch.endian();
pub const endian_header_value = switch (native_endian) {
    .big => 'B',
    .little => 'l',
};

pub fn Slice(comptime LenType: type, comptime Ptr: type) type {
    return struct {
        const Self = @This();
        const ptr_info = @typeInfo(Ptr).pointer;
        pub const NativeSlice = @Type(std.builtin.Type{
            .pointer = .{
                .size = .slice,
                .is_const = ptr_info.is_const,
                .is_volatile = ptr_info.is_volatile,
                .alignment = ptr_info.alignment,
                .address_space = ptr_info.address_space,
                .child = ptr_info.child,
                .is_allowzero = ptr_info.is_allowzero,
                .sentinel_ptr = ptr_info.sentinel_ptr,
            },
        });

        ptr: Ptr,
        len: LenType,

        pub fn init(slice: NativeSlice) ?@This() {
            return .{
                .ptr = slice.ptr,
                .len = std.math.cast(LenType, slice.len) orelse return null,
            };
        }

        pub fn initStatic(comptime ct_slice: NativeSlice) @This() {
            return .{ .ptr = ct_slice.ptr, .len = @intCast(ct_slice.len) };
        }

        pub fn nativeSlice(self: @This()) NativeSlice {
            return self.ptr[0..self.len];
        }

        pub fn lenCast(self: @This(), comptime NewLenType: type) Slice(NewLenType, Ptr) {
            return .{ .ptr = self.ptr, .len = @intCast(self.len) };
        }

        pub const format = switch (@typeInfo(Ptr).pointer.child) {
            u8 => (struct {
                pub const format = if (zig_atleast_15) formatNew else formatLegacy;
                fn formatNew(self: Self, writer: *std.Io.Writer) error{WriteFailed}!void {
                    try writer.writeAll(self.ptr[0..self.len]);
                }
                fn formatLegacy(
                    self: Self,
                    comptime fmt: []const u8,
                    options: std.fmt.FormatOptions,
                    writer: anytype,
                ) !void {
                    _ = fmt;
                    _ = options;
                    try writer.writeAll(self.ptr[0..self.len]);
                }
            }).format,
            else => @compileError("can't format non-u8 slice"),
        };
    };
}

const HeaderFieldSignature = enum {
    string,
    object_path,
    signature,
    u32,
    // unix_fd,
    pub fn char(sig: HeaderFieldSignature) u8 {
        return switch (sig) {
            .string => 's',
            .object_path => 'o',
            .signature => 'g',
            .u32 => 'u',
            // .unix_fd => 'h',
        };
    }
};

const HeaderFieldStringKind = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
    destination = 6,
    sender = 7,
    sig = 8,

    pub fn signature(kind: HeaderFieldStringKind) HeaderFieldSignature {
        return switch (kind) {
            .path => .object_path,
            .interface,
            .member,
            .error_name,
            .destination,
            .sender,
            => .string,
            .sig => .signature,
        };
    }
};
const HeaderFieldUint32Kind = enum(u8) {
    reply_serial = 5,
    unix_fds = 9,
};

const HeaderFieldKind = enum {
    path,
    interface,
    member,
    error_name,
    reply_serial,
    destination,
    sender,
    signature,
    unix_fds,

    pub fn init(value: u8) ?HeaderFieldKind {
        return switch (value) {
            1 => .path,
            2 => .interface,
            3 => .member,
            4 => .error_name,
            5 => .reply_serial,
            6 => .destination,
            7 => .sender,
            8 => .signature,
            9 => .unix_fds,
            // NOTE: according the the spec we must ignore
            // unknown header codes
            else => null,
        };
    }

    pub fn sig(kind: HeaderFieldKind) HeaderFieldSignature {
        return switch (kind) {
            .path => .object_path,
            .interface => .string,
            .member => .string,
            .error_name => .string,
            .reply_serial => .u32,
            .destination => .string,
            .sender => .string,
            .signature => .signature,
            // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            // Is this not supposed to be the unix_fd type 'h' ?
            .unix_fds => .u32,
        };
    }

    pub fn getField(kind: HeaderFieldKind, headers: *DynamicHeaders(null)) union(enum) {
        path: struct { ref: *?String, kind: HeaderStringKind },
        u32: *?u32,
        name: *?Bounded(255),
        sig: *?Bounded(255),
    } {
        return switch (kind) {
            .path => .{ .path = .{ .ref = &headers.path, .kind = .path } },
            .interface => .{ .name = &headers.interface },
            .member => .{ .name = &headers.member },
            .error_name => .{ .name = &headers.error_name },
            .reply_serial => .{ .u32 = &headers.reply_serial },
            .destination => .{ .name = &headers.destination },
            .sender => .{ .name = &headers.sender },
            .signature => .{ .sig = &headers.signature },
            .unix_fds => @panic("todo"),
        };
    }
};

fn Pad(comptime align_to: comptime_int) type {
    return switch (align_to) {
        4 => u2,
        8 => u3,
        else => @compileError("unsupported alignment"),
    };
}
/// Returns the padding needed to align the given len.
pub fn padLen(comptime align_to: comptime_int, len: Pad(align_to)) Pad(align_to) {
    return (0 -% len) & (align_to - 1);
}

// Returns the padding needed to align the given content len to 4-bytes.
// Note that it returns 0 for values already 4-byte aligned.
pub fn pad4Len(len: u2) u2 {
    return padLen(4, len);
}

// Returns the padding needed to align the given content len to 8-bytes.
// Note that it returns 0 for values already 8-byte aligned.
pub fn pad8Len(len: u3) u3 {
    return padLen(8, len);
}
test pad8Len {
    try std.testing.expectEqual(0, pad8Len(0));
    try std.testing.expectEqual(0, pad8Len(@truncate(8)));
    try std.testing.expectEqual(0, pad8Len(@truncate(16)));
    try std.testing.expectEqual(7, pad8Len(1)); // 1 -> 8
    try std.testing.expectEqual(6, pad8Len(2)); // 2 -> 8
    try std.testing.expectEqual(2, pad8Len(6)); // 6 -> 8
    try std.testing.expectEqual(1, pad8Len(7)); // 7 -> 8
    try std.testing.expectEqual(2, pad8Len(@truncate(14)));
    try std.testing.expectEqual(3, pad8Len(@truncate(29)));

    inline for (&.{ 4, 8 }) |align_to| {
        for (0..10) |multiplier| {
            std.debug.print("test align={} value={}\n", .{ align_to, multiplier * align_to });
            try std.testing.expectEqual(0, padLen(align_to, @truncate(multiplier * align_to)));
        }
        for (1..align_to + 1) |i| {
            std.debug.print("test align={} value={}\n", .{ align_to, i });
            try std.testing.expectEqual(align_to - i, padLen(align_to, @truncate(i)));
        }
    }
}

// NOTE: strings may not contain the codepoint 0
//       strings are ALWAYS null-terminated
//       they also must not contain OVERLONG sequences or exceed the value 0x10ffff
pub const max_codepoint = 0x10ffff;

pub const Type = union(enum) {
    u8, // 'y'
    bool, // 'b'
    i16, // 'n'
    u16, // 'q'
    i32, // 'i'
    u32, // 'u'
    i64, // 'x'
    u64, // 't'
    f64, // 'd'
    unix_fd, // 'h'
    string,
    object_path, // a string that is also a "syntactically valid object path"
    signature, // zero or more "single complete types"
    // @"struct",
    array: *const Type, // 'a<TYPE>'

    pub fn Native(self: Type) type {
        return switch (self) {
            .string => Slice(u32, [*]const u8),
            .object_path => Slice(u32, [*]const u8),
            .signature => []const Type,
            .u8 => u8,
            .bool => bool,
            .i16 => i16,
            .u16 => u16,
            .i32 => i32,
            .u32 => u32,
            .i64 => i64,
            .u64 => u64,
            .f64 => f64,
            .unix_fd => std.posix.fd_t,
        };
    }
    fn getLen(comptime sig_type: Type, body_align: u3, value: *const sig_type.Native()) u32 {
        switch (sig_type) {
            .string, .object_path => {
                const pad_len: u32 = pad4Len(@truncate(body_align));
                return pad_len + 4 + value.len + 1;
            },
            else => @compileError("todo: support type: " ++ @tagName(sig_type)),
        }
    }
};
pub fn Body(comptime signature: []const Type) type {
    var fields: [signature.len]std.builtin.Type.StructField = undefined;
    inline for (signature, &fields, 0..) |signature_type, *field, i| {
        const name = std.fmt.comptimePrint("{d}", .{i});
        const FieldType = signature_type.Native();
        field.* = .{
            .name = name,
            .type = FieldType,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(FieldType),
        };
    }
    return @Type(std.builtin.Type{
        .@"struct" = .{
            .layout = .auto,
            .fields = &fields,
            .decls = &.{},
            .is_tuple = true,
        },
    });
}

fn calcBodyLen(comptime signature: []const Type, body: *const Body(signature)) error{BodyTooBig}!u32 {
    var total_len: u32 = 0;
    var body_align: u3 = 0;
    inline for (signature, 0..) |sig_type, i| {
        const name = std.fmt.comptimePrint("{d}", .{i});
        const field_len = sig_type.getLen(body_align, &@field(body, name));
        total_len, const overflow = @addWithOverflow(total_len, field_len);
        if (overflow == 1) return error.BodyTooBig;
        body_align +%= @truncate(field_len);
    }
    return total_len;
}

pub fn flushAuth(writer: *Writer) error{WriteFailed}!void {
    var auth_buf: [100]u8 = undefined;
    const auth_len = serializeAuth(&auth_buf, if (zig_atleast_15)
        std.posix.system.getuid()
    else
        std.os.linux.getuid());
    const auth = auth_buf[0..auth_len];
    // if (zig_atleast_15)
    //     std.log.info("sending '{f}'", .{std.zig.fmtString(auth)})
    // else
    //     std.log.info("sending '{}'", .{std.zig.fmtEscapes(auth)});
    try writer.writeAll(auth);
    try writer.flush();
}

fn serializeAuth(out_buf: *[100]u8, uid: std.posix.uid_t) usize {
    const prefix = "\x00AUTH EXTERNAL ";
    @memcpy(out_buf[0..prefix.len], prefix);

    var uid_str_buf: [40]u8 = undefined;
    const uid_str = std.fmt.bufPrint(&uid_str_buf, "{}", .{uid}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    };
    const uid_hex = if (zig_atleast_15) std.fmt.bufPrint(out_buf[prefix.len..], "{x}", .{uid_str}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    } else std.fmt.bufPrint(out_buf[prefix.len..], "{}", .{std.fmt.fmtSliceHexLower(uid_str)}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    };
    @memcpy(out_buf[prefix.len + uid_hex.len ..][0..2], "\r\n");
    return prefix.len + uid_hex.len + 2;
}

// big enough to read 1 full 255-char signature
pub const min_read_buf = 256;

pub fn readAuth(reader: *Reader) (error{ DbusProtocol, DbusAuthRejected } || Reader.Error)!void {
    std.debug.assert(reader.buffer.len >= min_read_buf);

    const reply = reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.EndOfStream => return error.EndOfStream,
        error.StreamTooLong => {
            log_dbus.err("DBUS Protocol: AUTH reply exceeded {} bytes", .{reader.buffer.len});
            return error.DbusProtocol;
        },
    };
    // 0.15.2 doesn't toss the delimiter
    if (zig_atleast_15_2) reader.toss(1);

    if (zig_atleast_15)
        std.log.info("AUTH reply: '{f}'", .{std.zig.fmtString(reply)})
    else
        std.log.info("AUTH reply: '{}'", .{std.zig.fmtEscapes(reply)});
    if (std.mem.startsWith(u8, reply, "OK ")) {
        // should include a guid, maybe we don't need it though?
        return;
    }
    if (std.mem.startsWith(u8, reply, "REJECTED ")) {
        // TODO: maybe fallback to other auth mechanisms?
        return error.DbusAuthRejected;
    }

    std.log.info("DBUS Protocol: unhandled reply from server '{s}'", .{reply});
    return error.DbusProtocol;
}

fn calcHeaderStringLen(header_align: *u3, str: Slice(u32, [*]const u8)) u32 {
    const pad_len = pad8Len(header_align.*);
    const string_len: u32 = @as(u32, pad_len) + 8 + str.len + 1;
    header_align.* +%= @truncate(string_len);
    return string_len;
}
pub fn writeHeaderString(
    writer: *Writer,
    header_align: *u3,
    kind: HeaderFieldStringKind,
    str: Slice(u32, [*]const u8),
) error{WriteFailed}!void {
    const pad_len = pad8Len(header_align.*);
    var buf: [8]u8 = undefined;
    buf[0] = @intFromEnum(kind);
    buf[1] = 1; // type-sig length
    buf[2] = kind.signature().char();
    buf[3] = 0; // type-sig null terminator
    std.mem.writeInt(u32, buf[4..8], str.len, native_endian);
    const pad_buf = [1]u8{0} ** 8;
    var data = [_][]const u8{
        pad_buf[0..pad_len],
        &buf,
        str.nativeSlice(),
        &[_]u8{0},
    };
    try writer.writeVecAll(&data);
    const string_len: u32 = @as(u32, pad_len) + 8 + str.len + 1;
    header_align.* +%= @truncate(string_len);
}

fn calcHeaderSigLen(header_align: *u3, sig: Slice(u8, [*]const u8)) u32 {
    const pad_len = pad8Len(header_align.*);
    const sig_len: u32 = @as(u32, pad_len) + 5 + @as(u32, sig.len) + 1;
    header_align.* +%= @truncate(sig_len);
    return sig_len;
}
pub fn writeHeaderSig(
    writer: *Writer,
    header_align: *u3,
    sig: Slice(u8, [*]const u8),
) error{WriteFailed}!void {
    const pad_len = pad8Len(header_align.*);
    const pad_buf = [1]u8{0} ** 8;
    var data = [_][]const u8{
        pad_buf[0..pad_len],
        &.{
            @intFromEnum(HeaderFieldStringKind.sig),
            1, // type-sig length
            'g', // signature type
            0, // type-sig null terminator
            sig.len,
        },
        sig.nativeSlice(),
        &[_]u8{0},
    };
    try writer.writeVecAll(&data);
    const total_len: u32 = @as(u32, pad_len) + 5 + @as(u32, sig.len) + 1;
    header_align.* +%= @truncate(total_len);
}

pub fn writeMethodCall(
    writer: *Writer,
    comptime signature: []const Type,
    args: MethodCall,
    body: Body(signature),
) (error{BodyTooBig} || error{WriteFailed})!void {
    const body_len = try calcBodyLen(signature, &body);
    const array_data_len = args.calcHeaderArrayLen();
    try writer.writeAll(&[_]u8{
        endian_header_value,
        @intFromEnum(MessageType.method_call), // 1
        0, // flags,
        1, // protocol version
    });
    try writer.writeInt(u32, body_len, native_endian);
    try writer.writeInt(u32, args.serial, native_endian);
    try writer.writeInt(u32, array_data_len, native_endian);
    var header_align: u3 = 0;
    try writeHeaderString(writer, &header_align, .path, args.path);
    if (args.destination) |arg| {
        try writeHeaderString(writer, &header_align, .destination, arg);
    }
    if (args.interface) |arg| {
        try writeHeaderString(writer, &header_align, .interface, arg);
    }
    if (args.member) |arg| {
        try writeHeaderString(writer, &header_align, .member, arg);
    }
    try writer.splatByteAll(0, pad8Len(header_align));
}

pub const MethodCall = struct {
    serial: u32,
    path: Slice(u32, [*]const u8),
    destination: ?Slice(u32, [*]const u8) = null,
    interface: ?Slice(u32, [*]const u8) = null,
    member: ?Slice(u32, [*]const u8) = null,
    signature: ?Slice(u8, [*]const u8),
    pub fn calcHeaderArrayLen(self: *const MethodCall) u32 {
        var header_align: u3 = 0;
        const path_len = calcHeaderStringLen(&header_align, self.path);
        const dest_len = if (self.destination) |s| calcHeaderStringLen(&header_align, s) else 0;
        const iface_len = if (self.interface) |s| calcHeaderStringLen(&header_align, s) else 0;
        const member_len = if (self.member) |s| calcHeaderStringLen(&header_align, s) else 0;
        const sig_len = if (self.signature) |s| calcHeaderSigLen(&header_align, s) else 0;
        return path_len + dest_len + iface_len + member_len + sig_len;
    }
};

fn Bounded(comptime max: comptime_int) type {
    return struct {
        buffer: [max:0]u8,
        len: std.math.IntFittingRange(0, max),

        const Self = @This();
        pub fn slice(self: *Self) []u8 {
            return self.buffer[0..self.len];
        }
        pub fn sliceConst(self: *const Self) []const u8 {
            return self.buffer[0..self.len];
        }

        pub const format = if (zig_atleast_15) formatNew else formatLegacy;
        pub fn formatNew(self: Self, writer: *std.Io.Writer) error{WriteFailed}!void {
            try writer.print("{s}", .{self.sliceConst()});
        }
        pub fn formatLegacy(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try writer.print("{s}", .{self.sliceConst()});
        }
    };
}

const DbusProtocolError = error{
    DbusProtocol,
};

pub const HeaderStringKind = enum {
    path,
};

const HeaderFieldKindNe = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
    reply_serial = 5,
    destination = 6,
    sender = 7,
    signature = 8,
    unix_fds = 9,
    _,
    pub fn init(value: u8) DbusProtocolError!HeaderFieldKindNe {
        if (value == 0) {
            log_dbus.err("DBUS Protocol: 0 header field code", .{});
            return error.DbusProtocol;
        }
        return @enumFromInt(value);
    }
    pub fn expectedSignature(self: HeaderFieldKindNe) ?HeaderFieldSignature {
        return switch (self) {
            .path => .object_path,
            .interface => .string,
            .member => .string,
            .error_name => .string,
            .reply_serial => .u32,
            .destination => .string,
            .sender => .string,
            .signature => .signature,
            .unix_fds => .u32,
            _ => null,
        };
    }
};
const BoundedString = enum {
    interface,
    member,
    error_name,
    destination,
    sender,
    signature,
};

pub const HeaderFieldIterator = struct {
    pub const Field = union(enum) {
        path: struct { len: u32 },
        interface: Bounded(255),
        member: Bounded(255),
        error_name: Bounded(255),
        reply_serial: u32,
        destination: Bounded(255),
        sender: Bounded(255),
        signature: Bounded(255),
    };

    endian: std.builtin.Endian,
    header_array_len: u32,
    bytes_read: u32 = 0,

    pending_path: ?u32 = null,

    path_found: bool = false,
    interface_found: bool = false,
    member_found: bool = false,
    error_name_found: bool = false,
    reply_serial_found: bool = false,
    destination_found: bool = false,
    sender_found: bool = false,
    signature_found: bool = false,
    unix_fds_found: bool = false,

    fn getFoundRef(it: *HeaderFieldIterator, kind: HeaderFieldKindNe) ?*bool {
        return switch (kind) {
            .path => &it.path_found,
            .interface => &it.interface_found,
            .member => &it.member_found,
            .error_name => &it.error_name_found,
            .reply_serial => &it.reply_serial_found,
            .destination => &it.destination_found,
            .sender => &it.sender_found,
            .signature => &it.signature_found,
            .unix_fds => &it.unix_fds_found,
            _ => null,
        };
    }

    pub fn notifyPathConsumed(it: *HeaderFieldIterator) void {
        it.bytes_read += it.pending_path.?;
        it.pending_path = null;
    }

    pub fn next(it: *HeaderFieldIterator, reader: *Reader) (DbusProtocolError || Reader.Error)!?Field {
        if (it.pending_path != null) {
            @panic("notifyPathConsumed was not called");
        }

        if (it.bytes_read >= it.header_array_len) {
            const pad_len = pad8Len(@truncate(it.header_array_len));
            // std.log.info("discarding {} bytes of header padding...", .{pad_len});
            try reader.discardAll(pad_len);
            return null;
        }

        // every header field is aligned to 8 bytes
        {
            const pad_len = pad8Len(@truncate(it.bytes_read));
            // std.log.info("discarding {} bytes of field padding...", .{pad_len});
            try reader.discardAll(pad_len);
            it.bytes_read += pad_len;
        }

        const kind: HeaderFieldKindNe = try .init(try reader.takeByte());
        if (it.getFoundRef(kind)) |found_ref| {
            if (found_ref.*) {
                log_dbus.err("multiple '{s}' headers", .{@tagName(kind)});
                return error.DbusProtocol;
            }
            found_ref.* = true;
        }
        var sig_buf: [std.math.maxInt(u8)]u8 = undefined;
        const sig_len: u8 = try reader.takeByte();
        const sig = sig_buf[0..sig_len];
        it.bytes_read += 2;

        {
            const src = try reader.take(sig.len);
            it.bytes_read += @intCast(sig.len);
            @memcpy(sig, src);
            const sentinel = try reader.takeByte();
            it.bytes_read += 1;
            if (sentinel != 0) {
                // todo: include the header kind
                log_dbus.err("DBUS protocol violation: header signature missing 0-terminator", .{});
                return error.DbusProtocol;
            }
        }

        if (kind.expectedSignature()) |expected_sig| {
            if (sig.len != 1 or sig[0] != expected_sig.char()) {
                log_dbus.err("DBUS protocol: expected header {s} to have signature '{c}' but got '{s}'", .{ @tagName(kind), expected_sig.char(), sig });
                return error.DbusProtocol;
            }
        }

        switch (@as(union(enum) {
            path,
            bounded_string: BoundedString,
            reply_serial,
            unix_fds,
            unknown,
        }, switch (kind) {
            .path => .path,
            .interface => .{ .bounded_string = .interface },
            .member => .{ .bounded_string = .member },
            .error_name => .{ .bounded_string = .error_name },
            .reply_serial => .reply_serial,
            .destination => .{ .bounded_string = .destination },
            .sender => .{ .bounded_string = .sender },
            .signature => .{ .bounded_string = .signature },
            .unix_fds => .unix_fds,
            _ => .unknown,
        })) {
            .path => {
                // we should already be aligned on a 4-byte boundary
                std.debug.assert(pad4Len(@truncate(it.bytes_read)) == 0);
                const len = try reader.takeInt(u32, it.endian);
                it.bytes_read += 4;
                std.debug.assert(it.pending_path == null);
                it.pending_path = len;
                return .{ .path = .{ .len = len } };
            },
            .bounded_string => |bounded_kind| {
                const string_len = blk: {
                    switch (bounded_kind) {
                        .interface,
                        .member,
                        .error_name,
                        .destination,
                        .sender,
                        => {
                            // we should already be aligned on a 4-byte boundary
                            std.debug.assert(pad4Len(@truncate(it.bytes_read)) == 0);
                            const string_len = try reader.takeInt(u32, it.endian);
                            it.bytes_read += 4;
                            break :blk string_len;
                        },
                        .signature => {
                            const string_len = try reader.takeByte();
                            it.bytes_read += 1;
                            break :blk string_len;
                        },
                    }
                };

                // all known header fields except path have a max length of 255
                const string_len_u8 = std.math.cast(u8, string_len) orelse {
                    log_dbus.err("DBUS protocol: field '{s}' is {}-bytes but max is 255", .{ @tagName(bounded_kind), string_len });
                    return error.DbusProtocol;
                };
                var bounded: Bounded(255) = .{ .buffer = undefined, .len = string_len_u8 };
                {
                    const slice = try reader.take(string_len);
                    it.bytes_read += string_len;
                    // name_ref.* = .{ .buffer = undefined, .len = @intCast(string_len) };
                    @memcpy(bounded.buffer[0..string_len], slice);
                    bounded.buffer[string_len] = 0;
                }
                const nullterm = try reader.takeByte();
                it.bytes_read += 1;
                if (nullterm != 0) {
                    log_dbus.err("{s} name missing null-terminator", .{@tagName(kind)});
                    return error.DbusProtocol;
                }
                return switch (bounded_kind) {
                    .interface => .{ .interface = bounded },
                    .member => .{ .member = bounded },
                    .error_name => .{ .error_name = bounded },
                    .destination => .{ .destination = bounded },
                    .sender => .{ .sender = bounded },
                    .signature => .{ .signature = bounded },
                };
            },
            .reply_serial => {
                // we should already be aligned on a 4-byte boundary
                std.debug.assert(pad4Len(@truncate(it.bytes_read)) == 0);
                const value = try reader.takeInt(u32, it.endian);
                it.bytes_read += 4;
                return .{ .reply_serial = value };
            },
            .unix_fds => {
                @panic("todo");
            },
            .unknown => {
                @panic("todo");
            },
        }
    }
};

pub fn consumeStringNullTerm(reader: *Reader) (DbusProtocolError || Reader.Error)!void {
    const nullterm = try reader.takeByte();
    if (nullterm != 0) {
        log_dbus.err("string missing 0-terminator", .{});
        return error.DbusProtocol;
    }
}

pub const BodyIterator = struct {
    endian: std.builtin.Endian,
    body_len: u32,
    signature: []const u8,

    bytes_read: u32 = 0,
    sig_offset: u32 = 0,

    pending: ?Pending = null,
    // pending_string: ?u32 = null,
    const Pending = union(enum) {
        string: u32,
        array: u32,
    };

    pub const Value = union(enum) {
        string: struct { len: u32 },
        array: struct { size: u32 },
        boolean: bool,
    };

    pub fn notifyConsumed(it: *BodyIterator, kind: enum { string, array }) void {
        it.bytes_read += switch (kind) {
            .string => it.pending.?.string + 1,
            .array => @panic("todo"),
        };
        it.pending = null;
    }

    pub fn next(it: *BodyIterator, reader: *Reader) (DbusProtocolError || Reader.Error)!?Value {
        if (it.pending != null) {
            @panic("notifyConsumed was not called");
        }

        if (it.bytes_read >= it.body_len) {
            std.debug.assert(it.bytes_read == it.body_len);
            if (it.sig_offset != it.signature.len) {
                log_dbus.err("body truncated to {} but still expecting the following types '{s}'", .{ it.body_len, it.signature[it.sig_offset..] });
                return error.DbusProtocol;
            }
            return null;
        }

        if (it.sig_offset >= it.signature.len) {
            log_dbus.err("body has {} bytes left but signature has no types left", .{it.body_len - it.bytes_read});
            return error.DbusProtocol;
        }
        switch (it.signature[it.sig_offset]) {
            'a' => { // array
                const pad_len = pad4Len(@truncate(it.bytes_read));
                if (it.bytes_read + pad_len + 4 > it.body_len) {
                    log_dbus.err("body truncated", .{});
                    return error.DbusProtocol;
                }
                try reader.discardAll(pad_len);
                it.bytes_read += pad_len;
                const array_size = try reader.takeInt(u32, it.endian);
                it.bytes_read += 4;
                std.debug.assert(it.pending == null);
                if (it.bytes_read + array_size > it.body_len) {
                    log_dbus.err("body truncated", .{});
                    return error.DbusProtocol;
                }
                it.pending = .{ .array = array_size };
                it.sig_offset += 1;
                return .{ .array = .{ .size = array_size } };
            },
            's' => { // string
                const pad_len = pad4Len(@truncate(it.bytes_read));
                if (it.bytes_read + pad_len + 4 > it.body_len) {
                    log_dbus.err("body truncated", .{});
                    return error.DbusProtocol;
                }
                try reader.discardAll(pad_len);
                it.bytes_read += pad_len;
                const string_len = try reader.takeInt(u32, it.endian);
                it.bytes_read += 4;
                std.debug.assert(it.pending == null);
                if (it.bytes_read + string_len > it.body_len) {
                    log_dbus.err("body truncated", .{});
                    return error.DbusProtocol;
                }
                it.pending = .{ .string = string_len };
                it.sig_offset += 1;
                return .{ .string = .{ .len = string_len } };
            },
            'b' => { // bool
                const pad_len = pad4Len(@truncate(it.bytes_read));
                if (it.bytes_read + pad_len + 4 > it.body_len) {
                    log_dbus.err("body truncated", .{});
                    return error.DbusProtocol;
                }
                try reader.discardAll(pad_len);
                it.bytes_read += pad_len;
                const bool_value = try reader.takeInt(u32, it.endian);
                it.bytes_read += 4;
                it.sig_offset += 1;
                return .{ .boolean = switch (bool_value) {
                    0 => false,
                    1 => true,
                    else => |value| {
                        log_dbus.err("invalid bool value '{d}'", .{value});
                        return error.DbusProtocol;
                    },
                } };
            },
            else => |ch| std.debug.panic("todo: unknown or unsupported type sig '{c}'", .{ch}),
        }
    }
};

/// The first fixed part of every message
pub const Fixed = struct {
    endian: std.builtin.Endian,
    type: MessageType,
    flags: MessageFlags,
    body_len: u32,
    serial: u32,
    header_array_len: u32,

    pub fn discardHeaders(fixed: *const Fixed, reader: *Reader) Reader.Error!void {
        try reader.discardAll(fixed.header_array_len + pad8Len(@truncate(fixed.header_array_len)));
    }
    pub fn discardBody(fixed: *const Fixed, reader: *Reader) Reader.Error!void {
        try reader.discardAll(fixed.body_len);
    }

    pub fn stream(fixed: *const Fixed, reader: *Reader, writer: *Writer) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!void {
        const headers = try fixed.streamHeaders(reader, writer);
        std.log.info("  --- body ({} bytes) ---", .{fixed.body_len});
        try streamBody(reader, writer, fixed.endian, headers.signatureSlice(), fixed.body_len);
    }

    pub fn streamHeaders(fixed: *const Fixed, reader: *Reader, writer: *Writer) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!DynamicHeaders(null) {
        var path_buf: [1000]u8 = undefined;
        const headers = try fixed.readHeaders(reader, &path_buf);
        try writer.print("DBUS {s}:\n", .{@tagName(fixed.type)});
        if (headers.path) |*path| {
            if (path.len > path_buf.len) {
                try writer.print("  path '{s}' (truncated from {} bytes to {})\n", .{ path_buf[0..path.len], path.len, path_buf.len });
            } else {
                try writer.print("  path '{s}'\n", .{path_buf[0..path.len]});
            }
        } else {
            try writer.writeAll("  path (none)\n");
        }
        if (headers.interface) |interface| {
            try writer.print("  interface '{f}'\n", .{interface});
        } else {
            try writer.writeAll("  interface (none)\n");
        }
        if (headers.member) |member| {
            try writer.print("  member '{f}'\n", .{member});
        } else {
            try writer.writeAll("  member (none)\n");
        }
        if (headers.error_name) |error_name| {
            try writer.print("  error_name '{f}'\n", .{error_name});
        } else {
            try writer.writeAll("  error_name (none)\n");
        }
        if (headers.reply_serial) |reply_serial| {
            try writer.print("  reply_serial '{d}'\n", .{reply_serial});
        } else {
            try writer.writeAll("  reply_serial (none)\n");
        }
        if (headers.destination) |destination| {
            try writer.print("  destination '{f}'\n", .{destination});
        } else {
            try writer.writeAll("  destination (none)\n");
        }
        if (headers.sender) |sender| {
            try writer.print("  sender '{f}'\n", .{sender});
        } else {
            try writer.writeAll("  sender (none)\n");
        }
        if (headers.signature) |signature| {
            try writer.print("  signature '{f}'\n", .{signature});
        } else {
            try writer.writeAll("  signature (none)\n");
        }
        return headers;
    }

    pub fn readMethodReturnHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) (DbusProtocolError || Reader.Error)!DynamicHeaders(.method_return) {
        std.debug.assert(fixed.type == .method_return);
        const headers = try fixed.readHeaders(reader, path_buf);
        return .{
            .unknown_header_count = headers.unknown_header_count,
            .path = headers.path,
            .interface = headers.interface,
            .member = headers.member,
            .error_name = headers.error_name,
            .reply_serial = headers.reply_serial orelse {
                log_dbus.err("method return missing reply_serial", .{});
                return error.DbusProtocol;
            },
            .destination = headers.destination,
            .sender = headers.sender,
            .signature = headers.signature,
            .unix_fds = headers.unix_fds,
        };
    }

    pub fn readErrorHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) (DbusProtocolError || Reader.Error)!DynamicHeaders(.error_reply) {
        std.debug.assert(fixed.type == .error_reply);
        const headers = try fixed.readHeaders(reader, path_buf);
        return .{
            .unknown_header_count = headers.unknown_header_count,
            .path = headers.path,
            .interface = headers.interface,
            .member = headers.member,
            .error_name = headers.error_name orelse {
                log_dbus.err("error reply missing error_name", .{});
                return error.DbusProtocol;
            },
            .reply_serial = headers.reply_serial orelse {
                log_dbus.err("error reply missing reply_serial", .{});
                return error.DbusProtocol;
            },
            .destination = headers.destination,
            .sender = headers.sender,
            .signature = headers.signature,
            .unix_fds = headers.unix_fds,
        };
    }

    pub fn readSignalHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) (DbusProtocolError || Reader.Error)!DynamicHeaders(.signal) {
        std.debug.assert(fixed.type == .signal);
        const headers = try fixed.readHeaders(reader, path_buf);
        return .{
            .unknown_header_count = headers.unknown_header_count,
            .path = headers.path orelse {
                log_dbus.err("signal missing path", .{});
                return error.DbusProtocol;
            },
            .interface = headers.interface orelse {
                log_dbus.err("signal missing interface", .{});
                return error.DbusProtocol;
            },
            .member = headers.member orelse {
                log_dbus.err("signal missing member", .{});
                return error.DbusProtocol;
            },
            .error_name = headers.error_name,
            .reply_serial = headers.reply_serial,
            .destination = headers.destination,
            .sender = headers.sender,
            .signature = headers.signature,
            .unix_fds = headers.unix_fds,
        };
    }

    pub fn readHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) (DbusProtocolError || Reader.Error)!DynamicHeaders(null) {
        var headers: DynamicHeaders(null) = .{
            .path = null,
            .interface = null,
            .member = null,
            .error_name = null,
            .reply_serial = null,
        };

        var it: HeaderFieldIterator = .{
            .endian = fixed.endian,
            .header_array_len = fixed.header_array_len,
        };
        while (try it.next(reader)) |field| switch (field) {
            .path => |path| {
                std.debug.assert(headers.path == null);
                headers.path = .{ .len = path.len };
                const read_len = @min(path_buf.len, path.len);
                try reader.readSliceAll(path_buf[0..read_len]);
                try reader.discardAll(path.len - read_len);
                it.notifyPathConsumed();
            },
            .interface => |str| {
                std.debug.assert(headers.interface == null);
                headers.interface = str;
            },
            .member => |str| {
                std.debug.assert(headers.member == null);
                headers.member = str;
            },
            .error_name => |str| {
                std.debug.assert(headers.error_name == null);
                headers.error_name = str;
            },
            .reply_serial => |serial| {
                std.debug.assert(headers.reply_serial == null);
                headers.reply_serial = serial;
            },
            .destination => |str| {
                std.debug.assert(headers.destination == null);
                headers.destination = str;
            },
            .sender => |str| {
                std.debug.assert(headers.sender == null);
                headers.sender = str;
            },
            .signature => |str| {
                std.debug.assert(headers.signature == null);
                headers.signature = str;
            },
        };

        return headers;
    }
};

pub fn readFixed(reader: *Reader) (DbusProtocolError || Reader.Error)!Fixed {
    const bytes = try reader.takeArray(16);
    const endian: std.builtin.Endian = switch (bytes[0]) {
        'l' => .little,
        'B' => .big,
        else => {
            if (zig_atleast_15)
                log_dbus.err("expected endian 'l' or 'B' but got '{f}'", .{std.zig.fmtString(bytes[0..1])})
            else
                log_dbus.err("expected endian 'l' or 'B' but got '{}'", .{std.zig.fmtEscapes(bytes[0..1])});
            return error.DbusProtocol;
        },
    };

    if (bytes[3] != 1) {
        log_dbus.err("unsupported protocol version {}", .{bytes[3]});
        return error.DbusProtocol;
    }
    return Fixed{
        .endian = endian,
        .type = switch (bytes[1]) {
            @intFromEnum(MessageType.method_call) => .method_call,
            @intFromEnum(MessageType.method_return) => .method_return,
            @intFromEnum(MessageType.error_reply) => .error_reply,
            @intFromEnum(MessageType.signal) => .signal,
            else => |t| {
                log_dbus.err("unknown message type {}", .{t});
                return error.DbusProtocol;
            },
        },
        .flags = @bitCast(bytes[2]),
        .body_len = std.mem.readInt(u32, bytes[4..8], endian),
        .serial = std.mem.readInt(u32, bytes[8..12], endian),
        .header_array_len = std.mem.readInt(u32, bytes[12..16], endian),
    };
}

fn sum(comptime T: type, values: []const T) T {
    var total: T = 0;
    for (values) |value| {
        total += @as(T, value);
    }
    return total;
}

/// Returns the end index of a single type starting at `offset`.
/// A complete type is one of:
/// - A basic type: y, b, n, q, i, u, x, t, d, s, o, g, h
/// - A variant: v
/// - An array: a followed by a single complete type or dict entry
///      - a dict entry {kv} where k is a basic type and v is a complete type (only valid as an array element)
/// - A struct: (...) containing zero or more complete types
fn scanType(sig: []const u8, offset: usize) ?usize {
    if (offset >= sig.len) return null;
    return switch (sig[offset]) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h', 'v' => offset + 1,
        'a' => { // array
            if (offset + 1 >= sig.len) return null;
            if (sig[offset + 1] == '{') {
                if (offset + 2 >= sig.len) return null;
                // key must be a basic type (not container nor variant)
                switch (sig[offset + 2]) {
                    'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h' => {},
                    else => return null,
                }
                const after_value = scanType(sig, offset + 3) orelse return null;
                if (after_value >= sig.len) return null;
                if (sig[after_value] != '}') return null;
                return after_value + 1;
            }
            return scanType(sig, offset + 1);
        },
        '(' => { // struct
            var pos = offset + 1;
            if (pos >= sig.len or sig[pos] == ')') return null;
            while (pos < sig.len and sig[pos] != ')') {
                pos = scanType(sig, pos) orelse return null;
            }
            if (pos >= sig.len or sig[pos] != ')') return null;
            return pos + 1;
        },
        else => null,
    };
}

pub fn streamBody(
    reader: *Reader,
    writer: *Writer,
    endian: std.builtin.Endian,
    signature: []const u8,
    body_size: u32,
) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!void {
    const len = try streamBody2(reader, writer, endian, signature, body_size, 0);
    std.debug.assert(len <= body_size);
    if (len != body_size) return error.DbusProtocol;
}
pub fn streamBody2(
    reader: *Reader,
    writer: *Writer,
    endian: std.builtin.Endian,
    signature: []const u8,
    limit: u32,
    start: u32,
) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!u32 {
    var offset = start;
    var sig_index: usize = 0;
    while (true) {
        if (sig_index >= signature.len) {
            std.debug.assert(sig_index == signature.len);
            return offset;
        }
        const type_end = scanType(signature, sig_index) orelse return error.DbusProtocol;
        std.debug.assert(type_end > sig_index);
        std.debug.assert(type_end <= signature.len);
        const type_sig = signature[sig_index..type_end];
        sig_index = type_end;

        switch (type_sig[0]) {
            'u' => {
                const pad_len = pad4Len(@truncate(offset));
                if (sum(u64, &.{ offset, pad_len, 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const value = try reader.takeInt(u32, endian);
                offset += 4;
                try writer.print("<u32>{d}</u32>", .{value});
            },
            's' => {
                const pad_len = pad4Len(@truncate(offset));
                if (sum(u64, &.{ offset, pad_len, 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const string_len = try reader.takeInt(u32, endian);
                offset += 4;
                if (sum(u64, &.{ offset, string_len }) > limit)
                    return error.DbusProtocol;
                try writer.print("<string size=\"{}\">", .{string_len});
                try reader.streamExact(writer, string_len);
                offset += string_len;
                try reader.discardAll(1);
                offset += 1;
                try writer.writeAll("</string>");
            },
            'a' => {
                const pad_len = pad4Len(@truncate(offset));
                if (sum(u64, &.{ offset, pad_len, 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const array_size = try reader.takeInt(u32, endian);
                offset += 4;
                const initial_pad_len = switch (type_sig[1]) {
                    'x', 't', 'd', '(', '{' => pad8Len(@truncate(offset)),
                    else => 0,
                };
                const array_limit_u64 = sum(u64, &.{ offset, initial_pad_len, array_size });
                if (array_limit_u64 > limit) return error.DbusProtocol;
                const array_limit: u32 = @intCast(array_limit_u64);
                try writer.print("<array size=\"{}\">", .{array_size});
                while (offset < array_limit) {
                    offset = try streamBodyArrayElement(
                        reader,
                        writer,
                        endian,
                        type_sig[1..],
                        array_limit,
                        offset,
                    );
                }
                std.debug.assert(offset == array_limit);
                try writer.writeAll("</array>");
            },
            'v' => {
                if (offset + 1 > limit) return error.DbusProtocol;
                const variant_sig_len = try reader.takeByte();
                offset += 1;
                if (sum(u64, &.{ offset, variant_sig_len, 1 }) > limit)
                    return error.DbusProtocol;
                var variant_sig_buf: [255]u8 = undefined;
                const variant_sig = variant_sig_buf[0..variant_sig_len];
                try reader.readSliceAll(variant_sig);
                offset += variant_sig_len;
                const nullterm = try reader.takeByte();
                offset += 1;
                if (nullterm != 0) return error.DbusProtocol;

                if (scanType(variant_sig, 0)) |end| {
                    if (end != variant_sig.len) {
                        std.log.err("invalid variant type sig '{s}', it contains more than 1 type", .{variant_sig});
                        return error.DbusProtocol;
                    }
                } else {
                    std.log.err("variant type sig '{s}' is invalid", .{variant_sig});
                    return error.DbusProtocol;
                }

                try writer.print("<variant sig=\"{s}\">", .{variant_sig});
                offset = try streamBody2(reader, writer, endian, variant_sig, limit, offset);
                try writer.writeAll("</variant>");
            },
            '{' => {
                std.log.err("invalid signature, a dictionary may only appear as an array element type", .{});
                return error.DbusProtocol;
            },
            else => |ch| {
                std.log.err("unsupported or unknown type sig char '{c}' in streamBody", .{ch});
                return error.DbusProtocol;
            },
        }
    }
}

fn streamBodyArrayElement(
    reader: *Reader,
    writer: *Writer,
    endian: std.builtin.Endian,
    signature: []const u8,
    limit: u32,
    start: u32,
) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!u32 {
    if (signature.len == 0) return error.DbusProtocol;
    if (signature[0] != '{') return streamBody2(reader, writer, endian, signature, limit, start);

    if (signature.len < 4) return error.DbusProtocol;
    const sig_key_end = scanType(signature, 1) orelse return error.DbusProtocol;
    if (sig_key_end == signature.len) return error.DbusProtocol;
    const sig_value_end = scanType(signature, sig_key_end) orelse return error.DbusProtocol;
    if (sig_value_end == signature.len) return error.DbusProtocol;
    if (signature[sig_value_end] != '}') return error.DbusProtocol;

    const pad_len = pad8Len(@truncate(start));
    try reader.discardAll(pad_len);
    try writer.writeAll("<key>");
    const after_key = try streamBody2(
        reader,
        writer,
        endian,
        signature[1..sig_key_end],
        limit,
        pad_len + start,
    );
    try writer.writeAll("</key><value>");
    const after_value = try streamBody2(
        reader,
        writer,
        endian,
        signature[sig_key_end..sig_value_end],
        limit,
        after_key,
    );
    try writer.writeAll("</value>");
    return after_value;
}

const MaybeMessageType = enum {
    none,
    method_call,
    method_return,
    error_reply,
    signal,
    pub fn opt(message_type: ?MessageType) MaybeMessageType {
        return switch (message_type orelse return .none) {
            .method_call => .method_call,
            .method_return => .method_return,
            .error_reply => .error_reply,
            .signal => .signal,
        };
    }
};

const String = struct {
    len: u32,
};

fn DynamicHeaders(comptime message_type: ?MessageType) type {
    const maybe_message_type: MaybeMessageType = .opt(message_type);
    return struct {
        unknown_header_count: u32 = 0,
        path: switch (maybe_message_type) {
            .method_call, .signal => String,
            else => ?String,
        },
        interface: switch (maybe_message_type) {
            .signal => Bounded(max_name),
            else => ?Bounded(max_name),
        },
        member: switch (maybe_message_type) {
            .method_call, .signal => Bounded(max_name),
            else => ?Bounded(max_name),
        },
        error_name: switch (maybe_message_type) {
            .error_reply => Bounded(max_name),
            else => ?Bounded(max_name),
        },
        reply_serial: switch (maybe_message_type) {
            .error_reply, .method_return => u32,
            else => ?u32,
        },
        destination: ?Bounded(max_name) = null,
        sender: ?Bounded(max_name) = null,
        signature: ?Bounded(max_sig) = null,
        unix_fds: ?u32 = null,

        const Self = @This();
        pub fn signatureSlice(self: *const Self) []const u8 {
            return if (self.signature) |*s| s.sliceConst() else "";
        }
    };
}

const FmtHexAsciiOptions = struct {
    width: usize = 16,
};
fn fmtHexAscii(data: []const u8, options: FmtHexAsciiOptions) struct {
    data: []const u8,
    options: FmtHexAsciiOptions,

    const Self = @This();

    pub const format = if (zig_atleast_15) formatNew else formatLegacy;
    fn formatNew(self: Self, writer: *std.Io.Writer) error{WriteFailed}!void {
        try self.formatCommon(writer);
    }
    fn formatLegacy(
        self: Self,
        comptime fmt: []const u8,
        fmt_options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = fmt_options;
        try self.formatCommon(writer);
    }
    fn formatCommon(self: *const Self, writer: anytype) !void {
        const max_line = 200;
        var offset: usize = 0;
        while (true) {
            const next = offset + self.options.width;
            if (next > self.data.len) break;

            var buf: [max_line]u8 = undefined;
            const len = formatLine(&buf, self.data[offset..next], self.options);
            try writer.writeAll(buf[0..len]);
            try writer.writeByte('\n');
            offset = next;
        }
        if (offset < self.data.len) {
            var buf: [max_line]u8 = undefined;
            const len = formatLine(&buf, self.data[offset..], self.options);
            try writer.writeAll(buf[0..len]);
            try writer.writeByte('\n');
        }
    }
} {
    return .{ .data = data, .options = options };
}

fn formatLine(out_buf: []u8, line: []const u8, options: FmtHexAsciiOptions) usize {
    std.debug.assert(line.len <= options.width);
    _ = if (zig_atleast_15) std.fmt.bufPrint(out_buf, "{x}", .{line}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    } else std.fmt.bufPrint(out_buf, "{}", .{std.fmt.fmtSliceHexLower(line)}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    };
    const hex_end = 2 * options.width;
    @memset(out_buf[2 * (line.len) .. hex_end], ' ');

    out_buf[hex_end + 0] = ' ';
    out_buf[hex_end + 1] = '|';
    for (line, 0..) |c, i| {
        out_buf[hex_end + 2 + i] = if (std.ascii.isPrint(c)) c else ' ';
    }
    out_buf[hex_end + 2 + line.len] = '|';
    return hex_end + 2 + line.len + 1;
}
