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
pub const max_name = std.math.maxInt(u8);
pub const max_sig = 255;

pub fn castNameLen(len: u32) ?u8 {
    return std.math.cast(u8, len);
}

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

        pub fn initAssume(slice: NativeSlice) @This() {
            return .{ .ptr = slice.ptr, .len = @intCast(slice.len) };
        }

        pub fn initStatic(comptime ct_slice: NativeSlice) @This() {
            return .{ .ptr = ct_slice.ptr, .len = @intCast(ct_slice.len) };
        }

        pub fn nativeSlice(self: @This()) NativeSlice {
            if (ptr_info.sentinel_ptr) |sentinel_ptr| {
                return self.ptr[0..self.len :@as(*const ptr_info.child, @ptrCast(sentinel_ptr)).*];
            } else {
                return self.ptr[0..self.len];
            }
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

const HeaderFieldU32Kind = enum(u8) {
    reply_serial = 5,
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
    dict: struct {
        key: *const Type,
        value: *const Type,
    },
    variant, // 'v'

    pub fn eql(self: Type, other: Type) bool {
        if (@tagName(self) != @tagName(other)) return false;
        return switch (self) {
            .u8, .bool, .i16, .u16, .i32, .u32, .i64, .u64, .f64, .unix_fd, .string, .object_path, .signature, .variant => true,
            .array => |element_type| element_type.eql(other.array),
            .dict => |d| d.key.eql(other.dict.key) and d.value.eql(other.dict.value),
        };
    }

    pub fn matchesReadKind(self: Type, kind: ReadKind) bool {
        return switch (kind) {
            .boolean => self == .boolean,
            .u32 => self == .u32,
            .string_size => self == .string,
            .object_path_size => self == .object_path,
            .array_size => self == .array or self == .dict,
        };
    }

    pub fn getSignature(self: Type) Slice(u8, [*:0]const u8) {
        return switch (self) {
            .u8 => .initStatic("y"),
            // bool, // 'b'
            // i16, // 'n'
            // u16, // 'q'
            // i32, // 'i'
            // u32, // 'u'
            // i64, // 'x'
            // u64, // 't'
            // f64, // 'd'
            // unix_fd, // 'h'
            .string => .initStatic("s"),
            // object_path, // a string that is also a "syntactically valid object path"
            // signature, // zero or more "single complete types"
            // // @"struct",
            // array: *const Type, // 'a<TYPE>'
            // dict: struct {
            //     key: *const Type,
            //     value: *const Type,
            // },
            .variant => .initStatic("v"),
            else => @compileError("todo: get signature for " ++ @tagName(self)),
        };
    }

    // TODO: might need NativeConst and NativeMut?
    pub fn Native(self: Type) type {
        return switch (self) {
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
            .string => Slice(u32, [*]const u8),
            .object_path => Slice(u32, [*]const u8),
            .signature => Slice(u8, [*]const u8),
            .array => |e| []const e.Native(),
            .dict => |d| []const DictElement(d.key.Native(), d.value.Native()),
            .variant => Variant,
        };
    }

    fn advance(comptime sig_type: Type, start: u32, value: *const sig_type.Native()) error{Overflow}!u32 {
        switch (sig_type) {
            .u8 => return writeSum(&.{ start, 1 }),
            .i32, .u32 => {
                const pad_len: u32 = pad4Len(@truncate(start));
                return writeSum(&.{ start, pad_len + 4 });
            },
            .signature => return writeSum(&.{ start, 2, value.len }),
            .string, .object_path => {
                const pad_len: u32 = pad4Len(@truncate(start));
                return writeSum(&.{ start, pad_len + 4 + 1, value.len });
            },
            .dict => |d| {
                var offset = try dictDataOffset(start);
                for (value.*) |*elem| {
                    // each dict entry is 8-byte aligned (struct alignment)
                    offset = try writeSum(&.{ offset, pad8Len(@truncate(offset)) });
                    offset = try d.key.advance(offset, &elem.key);
                    offset = try d.value.advance(offset, &elem.value);
                }
                return offset;
            },
            .variant => {
                const variant_sig = value.getSignature();
                const after_sig = try Type.advance(.signature, start, &variant_sig);
                return switch (value.*) {
                    .i32 => |*v| try Type.advance(.i32, after_sig, v),
                    .u32 => |*v| try Type.advance(.u32, after_sig, v),
                    .string => |*v| try Type.advance(.string, after_sig, v),
                };
            },
            else => @compileError("todo: support type: " ++ @tagName(sig_type)),
        }
    }
};

fn dictDataOffset(start: u32) error{Overflow}!u32 {
    const pad_len: u32 = pad4Len(@truncate(start));
    const after_size: u32 = try writeSum(&.{ start, pad_len + 4 });
    return try writeSum(&.{ after_size, pad8Len(@truncate(after_size)) });
}

pub fn DictElement(comptime Key: type, comptime Value: type) type {
    return struct { key: Key, value: Value };
}
pub const Variant = union(enum) {
    i32: i32,
    u32: u32,
    string: Slice(u32, [*]const u8),

    pub fn getSignature(variant: *const Variant) Slice(u8, [*]const u8) {
        return switch (variant.*) {
            .i32 => .initStatic("i"),
            .u32 => .initStatic("u"),
            .string => .initStatic("s"),
        };
    }
};

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

fn calcHeaderU32Len(header_align: *u3) u32 {
    const pad_len = pad8Len(header_align.*);
    const field_len: u32 = @as(u32, pad_len) + 8;
    header_align.* = 0; // always ends with 8-byte alignment
    return field_len;
}

pub fn writeHeaderU32(
    writer: *Writer,
    header_align: *u3,
    kind: HeaderFieldU32Kind,
    value: u32,
) error{WriteFailed}!void {
    const pad_len = pad8Len(header_align.*);
    var buf: [8]u8 = undefined;
    buf[0] = @intFromEnum(kind);
    buf[1] = 1; // type-sig length
    buf[2] = 'u';
    buf[3] = 0; // type-sig null terminator
    std.mem.writeInt(u32, buf[4..8], value, native_endian);
    const pad_buf = [1]u8{0} ** 8;
    var data = [_][]const u8{
        pad_buf[0..pad_len],
        &buf,
    };
    try writer.writeVecAll(&data);
    header_align.* = 0; // always ends with 8-byte alignment
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

pub const MethodCall = struct {
    serial: u32,
    path: Slice(u32, [*]const u8),
    destination: ?Slice(u32, [*]const u8) = null,
    interface: ?Slice(u32, [*]const u8) = null,
    member: ?Slice(u32, [*]const u8) = null,
    pub fn calcHeaderArrayLen(self: *const MethodCall, signature: ?Slice(u8, [*]const u8)) u32 {
        var header_align: u3 = 0;
        const path_len = calcHeaderStringLen(&header_align, self.path);
        const dest_len = if (self.destination) |s| calcHeaderStringLen(&header_align, s) else 0;
        const iface_len = if (self.interface) |s| calcHeaderStringLen(&header_align, s) else 0;
        const member_len = if (self.member) |s| calcHeaderStringLen(&header_align, s) else 0;
        const sig_len = if (signature) |s| calcHeaderSigLen(&header_align, s) else 0;
        return path_len + dest_len + iface_len + member_len + sig_len;
    }
};

pub fn WriteData(comptime signature: []const u8) type {
    const types = typesFromSig(signature);
    var fields: [types.len]std.builtin.Type.StructField = undefined;
    inline for (types, &fields, 0..) |field_type, *field, i| {
        const name = std.fmt.comptimePrint("{d}", .{i});
        field.* = .{
            .name = name,
            .type = field_type.Native(),
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(field_type.Native()),
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

fn advance(start: u32, comptime signature: []const u8, data: WriteData(signature)) error{Overflow}!u32 {
    var index = start;
    const types = comptime typesFromSig(signature);
    inline for (types, 0..) |field_type, i| {
        const name = std.fmt.comptimePrint("{d}", .{i});
        index = try field_type.advance(index, &@field(data, name));
    }
    return index;
}

/// This function assumes that the total size of the data can fit within a u32. This should always
/// be the case if used to write a message body because the body size must be pre-calculated so it can
/// be written in the message header as a u32.
pub fn write(
    writer: *Writer,
    full_write_start: u32,
    comptime signature: []const u8,
    data: WriteData(signature),
) error{WriteFailed}!u32 {
    var index = full_write_start;
    const types = comptime typesFromSig(signature);
    inline for (types, 0..) |field_type, i| {
        const name = std.fmt.comptimePrint("{d}", .{i});
        const after_field = field_type.advance(index, &@field(data, name)) catch unreachable;
        switch (field_type) {
            .u8 => {
                try writer.writeByte(@field(data, name));
                index += 1;
            },
            .u32 => {
                const pad_len = pad4Len(@truncate(index));
                try writer.splatByteAll(0, pad_len);
                index += pad_len;
                try writer.writeInt(u32, @field(data, name), native_endian);
                index += 4;
            },
            .signature => {
                try writer.writeByte(@field(data, name).len);
                index += 1;
                try writer.writeAll(@field(data, name).nativeSlice());
                index += @field(data, name).len;
                try writer.writeByte(0);
                index += 1;
            },
            .string, .object_path => {
                const pad_len = pad4Len(@truncate(index));
                try writer.splatByteAll(0, pad_len);
                index += pad_len;
                try writer.writeInt(u32, @field(data, name).len, native_endian);
                index += 4;
                try writer.writeAll(@field(data, name).nativeSlice());
                index += @field(data, name).len;
                try writer.writeByte(0);
                index += 1;
            },
            .dict => |d| {
                const data_start = dictDataOffset(index) catch unreachable;
                const start_pad_len: u32 = pad4Len(@truncate(index));
                try writer.splatByteAll(0, start_pad_len);
                index += start_pad_len;
                try writer.writeInt(u32, after_field - data_start, native_endian);
                index += 4;
                const data_pad_len = pad8Len(@truncate(index));
                try writer.splatByteAll(0, data_pad_len);
                index += data_pad_len;
                std.debug.assert(index == data_start);
                for (@field(data, name)) |*elem| {
                    const pad_len = pad8Len(@truncate(index));
                    try writer.splatByteAll(0, pad_len);
                    index += pad_len;
                    index = try write(writer, index, d.key.getSignature().nativeSlice(), .{elem.key});
                    index = try write(writer, index, d.value.getSignature().nativeSlice(), .{elem.value});
                }
            },
            .variant => {
                index = try write(writer, index, "g", .{@field(data, name).getSignature()});
                index = switch (@field(data, name)) {
                    .i32 => @panic("todo"),
                    .u32 => @panic("todo"),
                    .string => |v| try write(writer, index, "s", .{v}),
                };
            },
            else => @compileError(std.fmt.comptimePrint("todo: write field type {}", .{field_type})),
        }
        std.debug.assert(index == after_field);
    }
    std.debug.assert(index == advance(full_write_start, signature, data) catch unreachable);
    return index;
}

pub fn writeMethodCall(
    writer: *Writer,
    comptime body_sig: []const u8,
    call: MethodCall,
    body_data: WriteData(body_sig),
) error{ BodyTooBig, WriteFailed }!void {
    const body_len = advance(0, body_sig, body_data) catch return error.BodyTooBig;
    const array_data_len = call.calcHeaderArrayLen(if (body_sig.len > 0) .initStatic(body_sig) else null);
    // NOTE: full header signature "yyyyuua(yv)"
    const after_serial = try write(writer, 0, "yyyyuu", .{
        endian_header_value,
        @intFromEnum(MessageType.method_call), // 1
        0, // flags,
        1, // protocol version
        body_len,
        call.serial,
    });
    _ = after_serial;
    // TODO: write via signature "a(yv)"
    try writer.writeInt(u32, array_data_len, native_endian);
    var header_align: u3 = 0;
    try writeHeaderString(writer, &header_align, .path, call.path);
    if (call.destination) |arg| {
        try writeHeaderString(writer, &header_align, .destination, arg);
    }
    if (call.interface) |arg| {
        try writeHeaderString(writer, &header_align, .interface, arg);
    }
    if (call.member) |arg| {
        try writeHeaderString(writer, &header_align, .member, arg);
    }
    if (body_sig.len > 0) {
        try writeHeaderSig(writer, &header_align, .initAssume(body_sig));
    }
    try writer.splatByteAll(0, pad8Len(header_align));

    if (body_sig.len > 0) {
        const body_written = try write(writer, 0, body_sig, body_data);
        std.debug.assert(body_written == body_len);
    }
}

pub const MethodReturn = struct {
    serial: u32,
    reply_serial: u32,
    destination: ?Slice(u32, [*]const u8) = null,

    pub fn calcHeaderArrayLen(self: *const MethodReturn, signature: ?Slice(u8, [*]const u8)) u32 {
        var header_align: u3 = 0;
        const reply_serial_len = calcHeaderU32Len(&header_align);
        const dest_len = if (self.destination) |s| calcHeaderStringLen(&header_align, s) else 0;
        const sig_len = if (signature) |s| calcHeaderSigLen(&header_align, s) else 0;
        return reply_serial_len + dest_len + sig_len;
    }
};

pub fn writeMethodReturn(
    writer: *Writer,
    comptime body_sig: []const u8,
    args: MethodReturn,
    body_data: WriteData(body_sig),
) error{ BodyTooBig, WriteFailed }!void {
    const body_len = advance(0, body_sig, body_data) catch return error.BodyTooBig;
    const array_data_len = args.calcHeaderArrayLen(if (body_sig.len > 0) .initStatic(body_sig) else null);
    const after_serial = try write(writer, 0, "yyyyuu", .{
        endian_header_value,
        @intFromEnum(MessageType.method_return), // 2
        0, // flags,
        1, // protocol version
        body_len,
        args.serial,
    });
    _ = after_serial;
    try writer.writeInt(u32, array_data_len, native_endian);
    var header_align: u3 = 0;
    try writeHeaderU32(writer, &header_align, .reply_serial, args.reply_serial);
    if (args.destination) |arg| {
        try writeHeaderString(writer, &header_align, .destination, arg);
    }
    if (body_sig.len > 0) {
        try writeHeaderSig(writer, &header_align, .initStatic(body_sig));
    }
    try writer.splatByteAll(0, pad8Len(header_align));

    if (body_sig.len > 0) {
        const body_written = try write(writer, 0, body_sig, body_data);
        std.debug.assert(body_written == body_len);
    }
}

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

    pub fn next(it: *HeaderFieldIterator, reader: *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!?Field {
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

const ReadKind = enum {
    boolean,
    u32,
    string_size,
    object_path_size,
    array_size,
    pub fn Type(kind: ReadKind) type {
        return switch (kind) {
            .boolean => bool,
            .u32 => u32,
            .string_size => u32,
            .object_path_size => u32,
            .array_size => u32,
        };
    }
    pub fn valueName(kind: ReadKind) [:0]const u8 {
        return switch (kind) {
            .boolean => "boolean",
            .u32 => "u32",
            .string_size => "string",
            .object_path_size => "object path",
            .array_size => "array",
        };
    }
};

pub const BodyIterator = struct {
    endian: std.builtin.Endian,
    body_len: u32,
    signature: []const u8,

    bytes_read: u32 = 0,
    sig_offset: u32 = 0,

    pending: ?Pending = null,
    const Pending = union(enum) {
        string: u32,
        object_path: u32,
        array: u32,
    };

    pub const Node = union(ReadKind) {
        boolean: bool,
        u32: u32,
        string_size: u32,
        object_path_size: u32,
        array_size: u32,
        pub fn valueName(node: *const Node) [:0]const u8 {
            return switch (node.*) {
                .boolean => "boolean",
                .u32 => "u32",
                .string_size => "string",
                .object_path_size => "object path",
                .array_size => "array",
            };
        }
    };

    pub fn notifyConsumed(it: *BodyIterator, kind: enum { string, object_path, array }) void {
        it.bytes_read += switch (kind) {
            .string => it.pending.?.string + 1,
            .object_path => it.pending.?.object_path + 1,
            .array => @panic("todo"),
        };
        it.pending = null;
    }

    pub fn next(it: *BodyIterator, reader: *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!?Node {
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
            'u' => {
                const pad_len: u32 = pad4Len(@truncate(it.bytes_read));
                if (try readSum(&.{ it.bytes_read, pad_len + 4 }) > it.body_len)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                it.bytes_read += pad_len;
                const value = try reader.takeInt(u32, it.endian);
                it.bytes_read += 4;
                it.sig_offset += 1;
                return .{ .u32 = value };
            },
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

                if (it.sig_offset >= it.signature.len) return error.DbusProtocol;
                const initial_pad_len = switch (it.signature[it.sig_offset]) {
                    'x', 't', 'd', '(', '{' => pad8Len(@truncate(it.bytes_read)),
                    else => 0,
                };
                try reader.discardAll(initial_pad_len);
                it.bytes_read = try readSum(&.{ it.bytes_read, initial_pad_len });

                it.pending = .{ .array = array_size };
                it.sig_offset += 1;
                return .{ .array_size = array_size };
            },
            's', 'o' => |ch| { // string or object-path
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
                it.sig_offset += 1;
                switch (ch) {
                    's' => {
                        it.pending = .{ .string = string_len };
                        return .{ .string_size = string_len };
                    },
                    'o' => {
                        it.pending = .{ .object_path = string_len };
                        return .{ .object_path_size = string_len };
                    },
                    else => unreachable,
                }
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

    /// Confirms the entire body has been read, otherwise, returns errror.DbusProtocol
    pub fn finish(it: *BodyIterator, comptime sig: []const u8, comptime sig_index: usize) error{DbusProtocol}!void {
        if (sig_index < sig.len) @compileError("signature hasn't been fully read, still have: " ++ sig[sig_index..]);
        std.debug.assert(sig.len == sig_index);
        if (it.pending != null) {
            @panic("notifyConsumed was not called");
        }
        if (it.bytes_read < it.body_len) {
            log_dbus.err("only {} bytes out of {} of the body were read", .{ it.bytes_read, it.body_len });
            return error.DbusProtocol;
        }
        std.debug.assert(it.bytes_read == it.body_len);
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
        try writer.print("DBUS {s}:\n", .{@tagName(fixed.type)});
        var path_buf: [1000]u8 = undefined;
        const headers = try fixed.readHeaders(reader, &path_buf);
        try writeHeaders(writer, &path_buf, headers);
        std.log.info("  --- body ({} bytes) ---", .{fixed.body_len});
        try streamBody(reader, writer, fixed.endian, headers.signatureSlice(), fixed.body_len);
    }

    pub fn readMethodReturnHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.method_return) {
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

    pub fn readMethodCallHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.method_call) {
        std.debug.assert(fixed.type == .method_call);
        const headers = try fixed.readHeaders(reader, path_buf);
        return .{
            .unknown_header_count = headers.unknown_header_count,
            .path = headers.path orelse {
                log_dbus.err("method call missing path", .{});
                return error.DbusProtocol;
            },
            .interface = headers.interface,
            .member = headers.member orelse {
                log_dbus.err("method call missing member", .{});
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

    pub fn readErrorHeaders(
        fixed: *const Fixed,
        reader: *Reader,
        path_buf: []u8,
    ) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.error_reply) {
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
    ) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.signal) {
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
    ) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(null) {
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

pub fn writeHeaders(
    writer: *Writer,
    path_buf: []const u8,
    headers: DynamicHeaders(null),
) error{WriteFailed}!void {
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
}

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

fn writeSum(values: []const u32) error{Overflow}!u32 {
    var total: u32 = 0;
    for (values) |value| {
        total, const overflow = @addWithOverflow(total, value);
        if (overflow == 1) return error.Overflow;
    }
    return total;
}
fn readSum(values: []const u32) error{DbusProtocol}!u32 {
    var total: u32 = 0;
    for (values) |value| {
        total, const overflow = @addWithOverflow(total, value);
        if (overflow == 1) return error.DbusProtocol;
    }
    return total;
}

fn countTypes(comptime signature: []const u8) u8 {
    var total: u8 = 0;
    var sig_index: usize = 0;
    while (sig_index < signature.len) {
        const next_sig_index = scanType(signature, sig_index) orelse @compileError("invalid type signature '" ++ signature ++ "'");
        std.debug.assert(next_sig_index > sig_index);
        total, const overflow = @addWithOverflow(total, 1);
        if (overflow == 1) @compileError("invalid type signature '" ++ signature ++ "' (too long)");
        sig_index = next_sig_index;
    }
    std.debug.assert(sig_index == signature.len);
    return total;
}

fn typesFromSig(comptime sig: []const u8) [countTypes(sig)]Type {
    comptime {
        var types: [countTypes(sig)]Type = undefined;
        var type_index: u8 = 0;
        var sig_index: u8 = 0;
        while (sig_index < sig.len) : (type_index += 1) {
            types[type_index], const char_count = nextType(sig[sig_index..]);
            std.debug.assert(char_count > 0);
            sig_index += char_count;
        }
        std.debug.assert(sig_index == sig.len);
        return types;
    }
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

fn typeAddr(comptime t: Type) *const Type {
    return &t;
}

fn nextType(comptime sig: []const u8) struct { Type, u8 } {
    std.debug.assert(sig.len > 0);
    return switch (sig[0]) {
        // basic types
        'y' => .{ .u8, 1 },
        'b' => .{ .bool, 1 },
        'n' => .{ .i16, 1 },
        'q' => .{ .u16, 1 },
        'i' => .{ .i32, 1 },
        'u' => .{ .u32, 1 },
        'x' => .{ .i64, 1 },
        't' => .{ .u64, 1 },
        'd' => .{ .f64, 1 },
        // 'h' => .{ u32, 1 },

        // string types
        's' => .{ .string, 1 },
        'o' => .{ .object_path, 1 },
        'g' => .{ .signature, 1 },

        'v' => .{ .variant, 1 },

        'a' => blk: {
            std.debug.assert(sig.len >= 2);
            if (sig[1] == '{') {
                const key_type, const key_char_count = nextType(sig[2..]);
                const value_type, const value_char_count = nextType(sig[2 + key_char_count ..]);
                std.debug.assert(sig[2 + key_char_count + value_char_count] == '}');
                return .{
                    .{ .dict = .{ .key = typeAddr(key_type), .value = typeAddr(value_type) } },
                    2 + key_char_count + value_char_count + 1,
                };
            }
            const Element, const element_sig_len = nextType(sig[1..]);
            break :blk .{ []const Element, 1 + element_sig_len };
        },
        // '(' => blk: {
        //     const inner = parseStructFields(sig[1..]);
        //     break :blk .{ inner[0], 1 + inner[1] + 1 }; // +1 for '(' and +1 for ')'
        // },
        // '{' => blk: {
        //     const key = nextType(sig[1..]);
        //     const value = nextType(sig[1 + key[1] ..]);
        //     break :blk .{ struct { key: key[0], value: value[0] }, 1 + key[1] + value[1] + 1 };
        // },
        else => @compileError("todo: handle sig: " ++ sig),
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
                const pad_len: u32 = pad4Len(@truncate(offset));
                if (try readSum(&.{ offset, pad_len + 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const value = try reader.takeInt(u32, endian);
                offset += 4;
                try writer.print("<u32>{d}</u32>", .{value});
            },
            's' => {
                const pad_len: u32 = pad4Len(@truncate(offset));
                if (try readSum(&.{ offset, pad_len + 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const string_len = try reader.takeInt(u32, endian);
                offset += 4;
                if (try readSum(&.{ offset, string_len }) > limit)
                    return error.DbusProtocol;
                try writer.print("<string size=\"{}\">", .{string_len});
                try reader.streamExact(writer, string_len);
                offset += string_len;
                try reader.discardAll(1);
                offset += 1;
                try writer.writeAll("</string>");
            },
            'a' => {
                const pad_len: u32 = pad4Len(@truncate(offset));
                if (try readSum(&.{ offset, pad_len + 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const array_size = try reader.takeInt(u32, endian);
                offset += 4;
                const initial_pad_len = switch (type_sig[1]) {
                    'x', 't', 'd', '(', '{' => pad8Len(@truncate(offset)),
                    else => 0,
                };
                const array_limit = try readSum(&.{ offset, initial_pad_len, array_size });
                if (array_limit > limit) return error.DbusProtocol;
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
                const variant_sig_len: u32 = try reader.takeByte();
                offset += 1;
                if (try readSum(&.{ offset, variant_sig_len + 1 }) > limit)
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

pub fn DynamicHeaders(comptime message_type: ?MessageType) type {
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

        pub fn expectReplySerial(self: *const Self, expected: u32) error{DbusProtocol}!void {
            if (self.reply_serial != expected) {
                log_dbus.err("expected serial {} but got {}", .{ expected, self.reply_serial });
                return error.DbusProtocol;
            }
        }
        pub fn expectSignature(self: *const Self, expected: []const u8) error{DbusProtocol}!void {
            if (!std.mem.eql(u8, expected, self.signatureSlice())) {
                log_dbus.err("expected signature '{s}' but got '{s}'", .{ expected, self.signatureSlice() });
                return error.DbusProtocol;
            }
        }

        pub fn asGeneric(self: *const Self) DynamicHeaders(null) {
            return .{
                .unknown_header_count = self.unknown_header_count,
                .path = self.path,
                .interface = self.interface,
                .member = self.member,
                .error_name = self.error_name,
                .reply_serial = self.reply_serial,
                .destination = self.destination,
                .sender = self.sender,
                .signature = self.signature,
                .unix_fds = self.unix_fds,
            };
        }
    };
}

pub fn read(
    comptime sig: []const u8,
    comptime sig_index: *usize,
    comptime kind: ReadKind,
) fn (*BodyIterator, *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.Type() {
    const dbus_type, const char_count = nextType(sig[sig_index.*..]);
    sig_index.* += char_count;
    if (!dbus_type.matchesReadKind(kind)) @compileError("signature indicates type " ++ @tagName(dbus_type) ++ " but code is reading " ++ @tagName(kind));
    return readFn(kind);
}
fn readFn(comptime kind: ReadKind) fn (*BodyIterator, *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.Type() {
    return (struct {
        fn func(it: *BodyIterator, reader: *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.Type() {
            const node = (try it.next(reader)) orelse {
                log_dbus.err("expected {s} but body has ended", .{kind.valueName()});
                return error.DbusProtocol;
            };
            if (kind != node) {
                std.log.err("expected {s} but got {s}", .{ kind.valueName(), node.valueName() });
                return error.DbusProtocol;
            }
            return @field(node, @tagName(kind));
        }
    }).func;
}
