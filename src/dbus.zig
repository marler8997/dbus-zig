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

pub fn socketWriter(s: std.net.Stream, buffer: []u8) Stream15.Writer {
    if (zig_atleast_15) return s.writer(buffer);
    return .init(s, buffer);
}
pub fn socketReader(s: std.net.Stream, buffer: []u8) Stream15.Reader {
    if (zig_atleast_15) return s.reader(buffer);
    return .init(s, buffer);
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
    @"struct": []const u8, // the signature
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

    pub fn getSigFirstChar(self: Type) u8 {
        return switch (self) {
            .u8 => 'y',
            .bool => 'b',
            .i16 => 'n',
            .u16 => 'q',
            .i32 => 'i',
            .u32 => 'u',
            .i64 => 'x',
            .u64 => 't',
            .f64 => 'd',
            .unix_fd => 'x',
            .string => 's',
            .object_path => 'o',
            .signature => 'g',
            .@"struct" => '(',
            .array => 'a',
            .dict => 'a',
            .variant => 'v',
        };
    }

    pub fn getSignature(self: Type) Slice(u8, [*]const u8) {
        return switch (self) {
            .u8 => .initStatic("y"),
            .bool => .initStatic("b"),
            .i16 => .initStatic("n"),
            .u16 => .initStatic("q"),
            .i32 => .initStatic("i"),
            .u32 => .initStatic("u"),
            .i64 => .initStatic("x"),
            .u64 => .initStatic("t"),
            .f64 => .initStatic("d"),
            .unix_fd => .initStatic("x"),
            .string => .initStatic("s"),
            .object_path => .initStatic("o"),
            .signature => .initStatic("g"),
            .@"struct" => |sig| .initStatic(sig),
            // .array =>
            // array: *const Type, // 'a<TYPE>'
            // dict: struct {
            //     key: *const Type,
            //     value: *const Type,
            // },
            .variant => .initStatic("v"),
            else => @compileError("todo: get signature for " ++ @tagName(self)),
            // inline else => |_, t| @compileError("todo: get signature for " ++ @tagName(t)),
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
            .@"struct" => |sig| Tuple(sig[1 .. sig.len - 1]),
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
            .@"struct" => |sig| {
                var offset = try writeSum(&.{ start, pad8Len(@truncate(start)) });
                inline for (comptime typesFromSig(sig[1 .. sig.len - 1]), 0..) |field_type, field_index| {
                    offset = try field_type.advance(offset, &value[field_index]);
                }
                return offset;
            },
            .array => |element| {
                var offset = try arrayDataOffset(start, .fromSig(element.getSigFirstChar()));
                for (value.*) |*e| {
                    offset = try element.advance(offset, e);
                }
                return offset;
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

fn arrayDataOffset(start: u32, element_align8: Align8) error{Overflow}!u32 {
    const pad_len: u32 = pad4Len(@truncate(start));
    const after_size: u32 = try writeSum(&.{ start, pad_len + 4 });
    return try writeSum(&.{ after_size, element_align8.padLen(@truncate(after_size)) });
}
fn dictDataOffset(start: u32) error{Overflow}!u32 {
    // all dict elements are structs which require 8-byte alignment
    return arrayDataOffset(start, .yes);
}

fn arraySigAdvance(sig: []const u8, start: u8, end: u8, next: u8) u8 {
    std.debug.assert(start < end);
    std.debug.assert(start <= next);
    std.debug.assert(next <= end);
    var i = next;
    while (true) {
        if (i == end) return start;
        if (i + 1 == end and sig[i] == '}') return start;
        switch (sig[i]) {
            'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h', 'v', 'a' => return i,
            ')' => i = i + 1,
            else => std.debug.panic(
                "todo: arraySigAdvance to {} ('{s}') correct? sig='{s}' start={} end={}",
                .{ next, sig[next .. next + 1], sig, start, end },
            ),
        }
    }
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

pub fn Tuple(comptime signature: []const u8) type {
    const types = typesFromSig(signature);
    var fields: [types.len]std.builtin.Type.StructField = undefined;
    @setEvalBranchQuota(signature.len * 2000);
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

fn advance(start: u32, comptime signature: []const u8, data: Tuple(signature)) error{Overflow}!u32 {
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
    data: Tuple(signature),
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
                index = try writeStringSize(writer, index, @field(data, name).len);
                try writer.writeAll(@field(data, name).nativeSlice());
                index += @field(data, name).len;
                try writer.writeByte(0);
                index += 1;
            },
            .@"struct" => |struct_sig| {
                {
                    const pad_len = pad8Len(@truncate(index));
                    try writer.splatByteAll(0, pad_len);
                    index += pad_len;
                }
                inline for (comptime typesFromSig(struct_sig[1 .. struct_sig.len - 1]), 0..) |struct_field_type, struct_index| {
                    index = try write(
                        writer,
                        index,
                        struct_field_type.getSignature().nativeSlice(),
                        .{data[i][struct_index]},
                    );
                }
            },
            .array => |element| {
                const element_align8: Align8 = .fromSig(element.getSigFirstChar());
                const array_size = after_field - (arrayDataOffset(index, element_align8) catch unreachable);
                index = try writeArraySize(writer, element_align8, index, array_size);
                for (@field(data, name)) |*e| {
                    index = try write(writer, index, element.getSignature().nativeSlice(), .{e.*});
                }
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
                    .u32 => |v| try write(writer, index, "u", .{v}),
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

pub const Align8 = enum {
    no,
    yes,
    pub fn fromSig(ch: u8) Align8 {
        return switch (ch) {
            'x', 't', 'd', '(', '{' => .yes,
            else => .no,
        };
    }
    pub fn padLen(a: Align8, offset_align: u3) u3 {
        return switch (a) {
            .no => 0,
            .yes => pad8Len(offset_align),
        };
    }
};

pub fn writeStringSize(writer: *Writer, body_start: u32, string_size: u32) error{WriteFailed}!u32 {
    const pad_len = pad4Len(@truncate(body_start));
    try writer.splatByteAll(0, pad_len);
    try writer.writeInt(u32, string_size, native_endian);
    return body_start + @as(u32, pad_len) + 4;
}
pub fn writeArraySize(
    writer: *Writer,
    element_align8: Align8,
    body_start: u32,
    array_size: u32,
) error{WriteFailed}!u32 {
    const data_start = arrayDataOffset(body_start, element_align8) catch unreachable;
    var body_offset: u32 = body_start;
    {
        const pad_len: u32 = pad4Len(@truncate(body_offset));
        try writer.splatByteAll(0, pad_len);
        body_offset += pad_len;
    }
    try writer.writeInt(u32, array_size, native_endian);
    body_offset += 4;
    {
        const pad_len = element_align8.padLen(@truncate(body_offset));
        try writer.splatByteAll(0, pad_len);
        body_offset += pad_len;
    }
    std.debug.assert(body_offset == data_start);
    return data_start;
}

pub fn writeMethodCall(
    writer: *Writer,
    comptime body_sig: []const u8,
    call: MethodCall,
    body_data: Tuple(body_sig),
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
    body_data: Tuple(body_sig),
) error{ BodyTooBig, WriteFailed }!void {
    const body_len = advance(0, body_sig, body_data) catch return error.BodyTooBig;
    const array_data_len = args.calcHeaderArrayLen(if (body_sig.len > 0) .initStatic(body_sig) else null);
    const after_serial = try write(writer, 0, "yyyyuu", .{
        endian_header_value,
        @intFromEnum(MessageType.method_return), // 2
        0, // flags
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

pub const SourceState = union(enum) {
    err,
    auth,
    msg_start,
    headers: struct {
        endian: std.builtin.Endian,
        msg_type: MessageType,
        body_size: u32,
        header_array_size: u32,
    },
    body: BodyIterator,
};

const BodyIterator = struct {
    endian: std.builtin.Endian,
    body_size: u32,
    body_offset: u32,
    body_signature: Bounded(255),

    current_signature: *const Bounded(255),
    state: State,

    pub const State = union(enum) {
        value: u8, // sig offset
        string: struct {
            end: End,
            body_limit: u32,
            sig_offset: u8,
        },
        variant: *SourceVariant,
        array: *SourceArray,

        // NOTE: don't call this in the expression if you're re-assigning state
        pub fn copyEnd(state: *const State) End {
            return switch (state.*) {
                .value => .value,
                .string => unreachable,
                .variant => |variant| .{ .variant = variant },
                .array => |array| .{ .parent_array = array },
            };
        }
    };

    pub const End = union(enum) {
        value,
        variant: *SourceVariant,
        parent_array: *SourceArray,
    };
};

pub const SourceArray = struct {
    end: BodyIterator.End,
    body_limit: u32,
    sig_end: u8,
    element_sig_offset: u8,
    next_sig_offset: u8,
};

pub const SourceVariant = struct {
    end: BodyIterator.End,

    restore: struct {
        signature: *const Bounded(255),
        sig_offset: u8,
    },

    signature: Bounded(255),
    sig_offset: u8,
};

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
pub const Source = struct {
    reader: *Reader,
    state: *SourceState,

    pub fn hasBufferedData(source: Source) bool {
        return source.reader.seek != source.reader.end;
    }

    pub fn readAuth(source: Source) error{ DbusProtocol, ReadFailed, EndOfStream, DbusAuthRejected }!void {
        std.debug.assert(source.state.* == .auth);
        std.debug.assert(source.reader.buffer.len >= min_read_buf);
        errdefer source.state.* = .err;

        const reply = source.reader.takeDelimiterExclusive('\n') catch |err| switch (err) {
            error.ReadFailed, error.EndOfStream => |e| return e,
            error.StreamTooLong => {
                log_dbus.err("DBUS Protocol: AUTH reply exceeded {} bytes", .{source.reader.buffer.len});
                return error.DbusProtocol;
            },
        };
        // 0.15.2 doesn't toss the delimiter
        if (zig_atleast_15_2) source.reader.toss(1);

        if (zig_atleast_15)
            log_dbus.info("AUTH reply: '{f}'", .{std.zig.fmtString(reply)})
        else
            log_dbus.info("AUTH reply: '{}'", .{std.zig.fmtEscapes(reply)});
        if (std.mem.startsWith(u8, reply, "OK ")) {
            // should include a guid, maybe we don't need it though?
            source.state.* = .msg_start;
            return;
        }
        if (std.mem.startsWith(u8, reply, "REJECTED ")) {
            // TODO: maybe fallback to other auth mechanisms?
            return error.DbusAuthRejected;
        }
        log_dbus.info("DBUS Protocol: unhandled reply from server '{s}'", .{reply});
        source.state.* = .err;
        return error.DbusProtocol;
    }

    pub fn readMsgStart(source: Source) error{ DbusProtocol, ReadFailed, EndOfStream }!MsgStart {
        std.debug.assert(source.state.* == .msg_start);
        errdefer source.state.* = .err;

        const bytes = try source.reader.takeArray(16);
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
        const msg_type: MessageType = switch (bytes[1]) {
            @intFromEnum(MessageType.method_call) => .method_call,
            @intFromEnum(MessageType.method_return) => .method_return,
            @intFromEnum(MessageType.error_reply) => .error_reply,
            @intFromEnum(MessageType.signal) => .signal,
            else => |t| {
                log_dbus.err("unknown message type {}", .{t});
                return error.DbusProtocol;
            },
        };
        const header_array_size = std.mem.readInt(u32, bytes[12..16], endian);
        const body_size = std.mem.readInt(u32, bytes[4..8], endian);
        source.state.* = .{ .headers = .{
            .endian = endian,
            .msg_type = msg_type,
            .body_size = body_size,
            .header_array_size = header_array_size,
        } };
        return MsgStart{
            .endian = endian,
            .type = msg_type,
            .flags = @bitCast(bytes[2]),
            .body_len = body_size,
            .serial = std.mem.readInt(u32, bytes[8..12], endian),
            .header_array_len = header_array_size,
        };
    }

    // call after calling readHeaders*
    pub fn bodySignature(source: Source) ?*const Bounded(255) {
        return switch (source.state.*) {
            .err, .auth, .headers => unreachable,
            .msg_start => null,
            .body => |*it| &it.body_signature,
        };
    }
    pub fn bodySignatureCopy(source: Source) Bounded(255) {
        return if (source.bodySignature()) |sig| sig.* else .empty();
    }
    pub fn bodySignatureSlice(source: Source) []const u8 {
        return if (source.bodySignature()) |sig| sig.slice() else "";
    }

    pub fn discardRemaining(source: Source) error{ DbusProtocol, ReadFailed, EndOfStream }!void {
        const headers_read = switch (source.state.*) {
            .err, .auth, .msg_start => unreachable,
            .headers => false,
            .body => true,
        };
        errdefer source.state.* = .err;
        if (!headers_read) {
            // TODO: implement/call discardHeaders instead
            // try source.discardHeaders();
            const headers = try source.readHeadersGeneric(&.{});
            _ = headers;
        }
        try source.discardBody();
    }

    pub fn streamRemaining(source: Source, writer: *Writer) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!void {
        const headers_read = blk: switch (source.state.*) {
            .err, .auth, .msg_start => unreachable,
            .headers => |*h| {
                try writer.print("message_type={s} body_size={} headers:\n", .{ @tagName(h.msg_type), h.body_size });
                break :blk false;
            },
            .body => true,
        };
        errdefer source.state.* = .err;
        if (!headers_read) {
            var path_buf: [1000]u8 = undefined;
            const headers = try source.readHeadersGeneric(&path_buf);
            try writeHeaders(writer, &path_buf, source.bodySignature(), headers);
        }
        try writer.writeAll("  body: ");
        try source.streamBody(writer);
        try writer.writeAll("\n");
    }

    pub fn readHeadersMethodReturn(source: Source, path_buf: []u8) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.method_return) {
        std.debug.assert(source.state.headers.msg_type == .method_return);
        const headers = try source.readHeadersGeneric(path_buf);
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
            // .signature = headers.signature,
            .unix_fds = headers.unix_fds,
        };
    }

    pub fn readHeadersMethodCall(source: Source, path_buf: []u8) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.method_call) {
        std.debug.assert(source.state.headers.msg_type == .method_call);
        const headers = try source.readHeadersGeneric(path_buf);
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
            .unix_fds = headers.unix_fds,
        };
    }

    // pub fn readHeadersError(
    //     msg_start: *const MsgStart,
    //     path_buf: []u8,
    // ) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.error_reply) {
    //     std.debug.assert(msg_start.type == .error_reply);
    //     const headers = try msg_start.readHeadersGeneric(reader, path_buf);
    //     return .{
    //         .unknown_header_count = headers.unknown_header_count,
    //         .path = headers.path,
    //         .interface = headers.interface,
    //         .member = headers.member,
    //         .error_name = headers.error_name orelse {
    //             log_dbus.err("error reply missing error_name", .{});
    //             return error.DbusProtocol;
    //         },
    //         .reply_serial = headers.reply_serial orelse {
    //             log_dbus.err("error reply missing reply_serial", .{});
    //             return error.DbusProtocol;
    //         },
    //         .destination = headers.destination,
    //         .sender = headers.sender,
    //         .signature = headers.signature,
    //         .unix_fds = headers.unix_fds,
    //     };
    // }

    pub fn readHeadersSignal(source: Source, path_buf: []u8) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(.signal) {
        std.debug.assert(source.state.headers.msg_type == .signal);
        const headers = try source.readHeadersGeneric(path_buf);
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
            .unix_fds = headers.unix_fds,
        };
    }

    pub fn readHeadersGeneric(source: Source, path_buf: []u8) error{ DbusProtocol, ReadFailed, EndOfStream }!DynamicHeaders(null) {
        std.debug.assert(source.state.* == .headers);
        errdefer source.state.* = .err;

        var headers: DynamicHeaders(null) = .{
            .path = null,
            .interface = null,
            .member = null,
            .error_name = null,
            .reply_serial = null,
        };
        var signature: ?Bounded(255) = null;

        var it: HeaderFieldIterator = .{
            .endian = source.state.headers.endian,
            .header_array_len = source.state.headers.header_array_size,
        };
        while (try it.next(source.reader)) |field| switch (field) {
            .path => |path| {
                if (headers.path != null) {
                    log_dbus.err("duplicate path header", .{});
                    return error.DbusProtocol;
                }
                headers.path = .{ .len = path.len };
                const read_len = @min(path_buf.len, path.len);
                try source.reader.readSliceAll(path_buf[0..read_len]);
                try source.reader.discardAll(path.len - read_len);
                it.notifyPathConsumed();
            },
            .interface => |str| {
                if (headers.interface != null) {
                    log_dbus.err("duplicate interface header", .{});
                    return error.DbusProtocol;
                }
                headers.interface = str;
            },
            .member => |str| {
                if (headers.member != null) {
                    log_dbus.err("duplicate member header", .{});
                    return error.DbusProtocol;
                }
                headers.member = str;
            },
            .error_name => |str| {
                if (headers.error_name != null) {
                    log_dbus.err("duplicate error name header", .{});
                    return error.DbusProtocol;
                }
                headers.error_name = str;
            },
            .reply_serial => |serial| {
                if (headers.reply_serial != null) {
                    log_dbus.err("duplicate reply serial header", .{});
                    return error.DbusProtocol;
                }
                headers.reply_serial = serial;
            },
            .destination => |str| {
                if (headers.destination != null) {
                    log_dbus.err("duplicate desintation header", .{});
                    return error.DbusProtocol;
                }
                headers.destination = str;
            },
            .sender => |str| {
                if (headers.sender != null) {
                    log_dbus.err("duplicate sender header", .{});
                    return error.DbusProtocol;
                }
                headers.sender = str;
            },
            .signature => |str| {
                if (signature != null) {
                    log_dbus.err("duplicate signature header", .{});
                    return error.DbusProtocol;
                }
                signature = str;
            },
        };

        // need to copy these values out of state so we can use them when re-assigning state
        const endian = source.state.headers.endian;
        const body_size = source.state.headers.body_size;
        source.state.* = .{ .body = .{
            .endian = endian,
            .body_size = body_size,
            .body_offset = 0,
            .body_signature = if (signature) |s| s else .empty(),

            .current_signature = undefined,
            .state = .{ .value = 0 },
        } };
        source.state.body.current_signature = &source.state.body.body_signature;
        return headers;
    }

    pub fn expectSignature(source: Source, expected: []const u8) error{DbusProtocol}!void {
        switch (source.state.*) {
            .auth, .headers, .err => unreachable,
            .msg_start => if (expected.len != 0) {
                log_dbus.err("expected signature '{s}' but there is none", .{expected});
                return error.DbusProtocol;
            },
            .body => |*it| if (!std.mem.eql(u8, expected, it.body_signature.slice())) {
                log_dbus.err("expected signature '{s}' but got '{s}'", .{ expected, it.body_signature.slice() });
                return error.DbusProtocol;
            },
        }
    }

    fn onBodyConsumed(source: Source, consume_sig: []const u8) void {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        std.debug.assert(it.body_offset <= it.body_size);
        switch (it.state) {
            .value => |sig_offset| {
                std.debug.assert(sig_offset + consume_sig.len <= it.current_signature.len);
                std.debug.assert(std.mem.eql(
                    u8,
                    it.current_signature.slice()[sig_offset..][0..consume_sig.len],
                    consume_sig,
                ));
                it.state = .{ .value = @intCast(sig_offset + consume_sig.len) };
            },
            .variant => |variant| {
                std.debug.assert(it.current_signature == &variant.signature);
                std.debug.assert(variant.sig_offset < variant.signature.len);
                // TODO: one or more of these checks might need to be a DbusProtocol error rather
                //       than runtime assert
                std.debug.assert(variant.sig_offset + consume_sig.len == variant.signature.len);
                std.debug.assert(std.mem.eql(
                    u8,
                    variant.signature.slice()[0..consume_sig.len],
                    consume_sig,
                ));
                it.current_signature = variant.restore.signature;
                it.state = switch (variant.end) {
                    .value => .{ .value = variant.restore.sig_offset },
                    .variant => @panic("todo"),
                    .parent_array => |array| .{ .array = array },
                };
                switch (variant.end) {
                    .value => {},
                    .variant => @panic("todo"),
                    .parent_array => source.onDataConsumed("v"),
                }
            },
            .string => unreachable,
            .array => source.onDataConsumed(consume_sig),
        }
    }

    // only call if we're in a "body data" state, updates the current state if all the
    // data has been consumed
    fn onDataConsumed(source: Source, maybe_first_sig: ?[]const u8) void {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        var maybe_consumed_sig = maybe_first_sig;
        while (true) {
            switch (it.state) {
                .value => unreachable,
                .string => std.debug.assert(maybe_consumed_sig == null),
                .variant => unreachable,
                .array => {},
            }

            const body_limit = switch (it.state) {
                .value => unreachable,
                .string => |*s| s.body_limit,
                .variant => unreachable,
                .array => |a| a.body_limit,
            };
            std.debug.assert(it.body_offset <= body_limit);
            if (it.body_offset < body_limit) return switch (it.state) {
                .value => unreachable,
                .string => {},
                .variant => unreachable,
                .array => |array| if (maybe_consumed_sig) |sig| {
                    std.debug.assert(std.mem.eql(u8, it.current_signature.buffer[array.next_sig_offset..][0..sig.len], sig));
                    array.next_sig_offset = arraySigAdvance(
                        it.current_signature.slice(),
                        array.element_sig_offset,
                        array.sig_end,
                        @intCast(array.next_sig_offset + sig.len),
                    );
                },
            };
            const consumed_sig: []const u8 = switch (it.state) {
                .value => unreachable,
                .string => "s",
                .variant => "v",
                .array => |array| it.current_signature.slice()[array.element_sig_offset - 1 .. array.sig_end],
            };
            maybe_consumed_sig = consumed_sig;
            switch (switch (it.state) {
                .value => unreachable,
                .string => |*s| s.end,
                .variant => |variant| variant.end,
                .array => |array| array.end,
            }) {
                .value => {
                    const next_sig_offset = switch (it.state) {
                        .value => unreachable,
                        .string => |*s| s.sig_offset + 1,
                        .variant => @panic("todo"),
                        .array => |array| array.sig_end,
                    };
                    it.state = .{ .value = next_sig_offset };
                    return;
                },
                .variant => |variant| {
                    it.current_signature = &variant.signature;
                    it.state = .{ .variant = variant };
                    return source.onBodyConsumed(consumed_sig);
                },
                .parent_array => |parent_array| {
                    const parent_copy = parent_array;
                    it.state = .{ .array = parent_copy };
                },
            }
        }
    }

    fn discardBody(source: Source) error{ DbusProtocol, ReadFailed, EndOfStream }!void {
        const it = switch (source.state.*) {
            .err, .auth, .headers, .msg_start => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        std.debug.assert(it.body_offset <= it.body_size);
        try source.reader.discardAll(it.body_size - it.body_offset);
        source.state.* = .msg_start;
    }

    pub fn bodyEnd(source: Source) error{DbusProtocol}!void {
        const it = switch (source.state.*) {
            .err, .auth, .headers, .msg_start => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        std.debug.assert(it.body_offset <= it.body_size);
        if (it.body_offset != it.body_size) {
            log_dbus.err(
                "read {} bytes of body but total is {} (signature is '{s}')",
                .{ it.body_offset, it.body_size, it.body_signature.slice() },
            );
            return error.DbusProtocol;
        }
        source.state.* = .msg_start;
    }

    pub fn streamBody(source: Source, writer: *Writer) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!void {
        const it = switch (source.state.*) {
            .err, .auth, .headers, .msg_start => unreachable,
            .body => |*it| it,
        };
        const sig_offset = switch (it.state) {
            .value => |sig_offset| sig_offset,
            .string, .variant, .array => unreachable,
        };
        errdefer source.state.* = .err;
        const new_offset = try stream(
            source.reader,
            writer,
            it.endian,
            it.body_signature.slice()[sig_offset..],
            it.body_size,
            it.body_offset,
        );
        std.debug.assert(new_offset <= it.body_size);
        if (new_offset != it.body_size) {
            log_dbus.err("body has {} bytes leftover", .{it.body_size - new_offset});
            return error.DbusProtocol;
        }
        source.state.* = .msg_start;
    }

    pub fn readBody(
        source: Source,
        comptime kind: ReadKind,
        read_context: kind.ReadContext(),
    ) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.ReadType() {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        std.debug.assert(it.body_offset < it.body_size);
        const initial_sig_offset = blk: switch (it.state) {
            .value => |sig_offset| sig_offset,
            .string => unreachable,
            .variant => |variant| variant.sig_offset,
            .array => |array| {
                std.debug.assert(it.body_offset < array.body_limit);
                if (it.current_signature.buffer[array.next_sig_offset] == '{') {
                    const pad_len: u32 = pad8Len(@truncate(it.body_offset));
                    try source.reader.discardAll(pad_len);
                    it.body_offset = try incBodyLimited(it.body_size, &.{ it.body_offset, pad_len });
                    array.next_sig_offset += 1;
                }
                break :blk array.next_sig_offset;
            },
        };
        const value_sig_offset = blk: {
            var sig_offset = initial_sig_offset;
            while (true) {
                std.debug.assert(sig_offset < it.current_signature.len);
                if (it.current_signature.buffer[sig_offset] != '(')
                    break :blk sig_offset;
                const pad_len: u32 = pad8Len(@truncate(it.body_offset));
                if (try incBody(&.{ it.body_offset, pad_len }) > it.body_size)
                    return error.DbusProtocol;
                try source.reader.discardAll(pad_len);
                sig_offset += 1;
                switch (it.state) {
                    .value => it.state = .{ .value = sig_offset },
                    .string => unreachable,
                    .variant => |variant| variant.sig_offset = sig_offset,
                    .array => |array| array.next_sig_offset = sig_offset,
                }
            }
        };
        std.debug.assert(kind.sigChar() == it.current_signature.slice()[value_sig_offset]);

        switch (kind) {
            .u32 => {
                const pad_len: u32 = pad4Len(@truncate(it.body_offset));
                if (try incBody(&.{ it.body_offset, pad_len + 4 }) > it.body_size)
                    return error.DbusProtocol;
                try source.reader.discardAll(pad_len);
                it.body_offset += pad_len;
                const value = try source.reader.takeInt(u32, it.endian);
                it.body_offset += 4;
                source.onBodyConsumed("u");
                return value;
            },
            .string_size, .object_path_size => {
                const pad_len: u32 = pad4Len(@truncate(it.body_offset));
                if (try incBody(&.{ it.body_offset, pad_len + 4 }) > it.body_size)
                    return error.DbusProtocol;
                try source.reader.discardAll(pad_len);
                it.body_offset += pad_len;
                const string_size = try source.reader.takeInt(u32, it.endian);
                it.body_offset += 4;
                const string_limit = try incBody(&.{ it.body_offset, string_size, 1 });
                if (string_limit > it.body_size) return error.DbusProtocol;
                const end_copy = it.state.copyEnd(); // copy this outside the assign to it.state below
                it.state = .{ .string = .{
                    .end = end_copy,
                    .sig_offset = value_sig_offset,
                    .body_limit = string_limit,
                } };
                return string_size;
            },
            .variant_sig => {
                const sig_len = try source.reader.takeByte();
                it.body_offset += 1;
                read_context.* = .{
                    .end = it.state.copyEnd(),
                    .restore = .{
                        .signature = it.current_signature,
                        .sig_offset = value_sig_offset + 1,
                    },
                    .signature = .{ .len = sig_len, .buffer = undefined },
                    .sig_offset = 0,
                };
                try source.reader.readSliceAll(read_context.signature.buffer[0..sig_len]);
                it.body_offset = try incBodyLimited(it.body_size, &.{ it.body_offset, sig_len });
                {
                    const nullterm = try source.reader.takeByte();
                    it.body_offset = try incBodyLimited(it.body_size, &.{ it.body_offset, 1 });
                    if (nullterm != 0) {
                        log_dbus.err("variant signature missing 0-term", .{});
                        return error.DbusProtocol;
                    }
                }
                it.current_signature = &read_context.signature;
                it.state = .{ .variant = read_context };
                return;
            },
            .array_size => {
                {
                    const pad_len: u32 = pad4Len(@truncate(it.body_offset));
                    if (try incBody(&.{ it.body_offset, pad_len + 4 }) > it.body_size)
                        return error.DbusProtocol;
                    try source.reader.discardAll(pad_len);
                    it.body_offset += pad_len;
                }
                const array_size = try source.reader.takeInt(u32, it.endian);
                it.body_offset += 4;
                {
                    const pad_len: u32 = arrayPadLen(it.current_signature.buffer[value_sig_offset + 1], @truncate(it.body_offset));
                    try source.reader.discardAll(pad_len);
                    it.body_offset += pad_len;
                }
                const element_sig_offset: u8 = value_sig_offset + 1;
                read_context.* = .{
                    .end = it.state.copyEnd(),
                    .body_limit = try incBodyLimited(it.body_size, &.{ it.body_offset, array_size }),
                    .sig_end = scanArrayElementSig(it.current_signature.slice(), element_sig_offset),
                    .element_sig_offset = element_sig_offset,
                    .next_sig_offset = element_sig_offset,
                };
                it.state = .{ .array = read_context };
                source.onDataConsumed(null);
                return;
            },
            else => @compileError("todo: implement read kind " ++ @tagName(kind)),
        }
    }

    pub fn currentSignature(source: Source) *const Bounded(255) {
        return switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it.current_signature,
        };
    }

    pub fn bodyOffset(source: Source) u32 {
        return switch (source.state.*) {
            .err, .auth, .headers => unreachable,
            .msg_start => 0,
            .body => |*it| it.body_offset,
        };
    }

    pub fn dataRemaining(source: Source) u32 {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        const body_limit = switch (it.state) {
            .value => unreachable,
            .string => |*s| s.body_limit,
            .variant => unreachable,
            .array => |a| a.body_limit,
        };
        std.debug.assert(it.body_offset < body_limit);
        return body_limit - it.body_offset;
    }

    pub fn dataTake(source: Source, size: u32) error{ ReadFailed, EndOfStream }![]u8 {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        const body_limit = switch (it.state) {
            .value => unreachable,
            .string => |*s| s.body_limit,
            .variant => unreachable,
            .array => |a| a.body_limit,
        };
        std.debug.assert(it.body_offset + size <= body_limit);
        const result = try source.reader.take(size);
        it.body_offset += @intCast(size);
        source.onDataConsumed(null);
        return result;
    }

    // pub fn dataTakeInt(source: Source, comptime T: type) error{ ReadFailed, EndOfStream }![]u8 {
    //     const it = switch (source.state) {
    //         .err, .auth, .msg_start, .headers => unreachable,
    //         .body => |*it| b,
    //     };
    //     errdefer source.state = .err;
    //     const data = switch (it.state) {
    //         .value => unreachable,
    //         .data => |*d| d,
    //     };
    //     std.debug.assert(data.consumed + @sizeOf(T) <= data.size);
    //     const int = try source.reader.takeInt(T, it.endian);
    //     data.consumed += @sizeOf(T);
    //     source.onDataConsumed();
    //     return int;
    // }

    pub fn dataReadSliceAll(source: Source, slice: []u8) error{ ReadFailed, EndOfStream }!void {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        const body_limit = switch (it.state) {
            .value => unreachable,
            .string => |*s| s.body_limit,
            .variant => unreachable,
            .array => |a| a.body_limit,
        };
        std.debug.assert(it.body_offset + slice.len <= body_limit);
        try source.reader.readSliceAll(slice);
        it.body_offset += @intCast(slice.len);
        source.onDataConsumed(null);
    }
    pub fn dataReadNullTerm(source: Source) error{ DbusProtocol, ReadFailed, EndOfStream }!void {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        const body_limit = switch (it.state) {
            .value => unreachable,
            .string => |*s| s.body_limit,
            .variant => unreachable,
            .array => |a| a.body_limit,
        };
        std.debug.assert(it.body_offset + 1 == body_limit);
        const nullterm = try source.reader.takeByte();
        it.body_offset += 1;
        if (nullterm != 0) {
            log_dbus.err("expected 0 terminator but got {}", .{nullterm});
            return error.DbusProtocol;
        }
        source.onDataConsumed(null);
    }

    pub fn dataStreamExact(source: Source, writer: *Writer, n: u32) error{ ReadFailed, EndOfStream, WriteFailed }!void {
        const it = switch (source.state.*) {
            .err, .auth, .msg_start, .headers => unreachable,
            .body => |*it| it,
        };
        errdefer source.state.* = .err;
        const body_limit = switch (it.state) {
            .value => unreachable,
            .string => |*s| s.body_limit,
            .variant => unreachable,
            .array => |a| a.body_limit,
        };
        std.debug.assert(it.body_offset + n <= body_limit);
        try source.reader.streamExact(writer, n);
        it.body_offset += n;
        source.onDataConsumed(null);
    }
};

pub fn Bounded(comptime max: comptime_int) type {
    return struct {
        buffer: [max:0]u8,
        len: Len,

        const Len = std.math.IntFittingRange(0, max);

        const Self = @This();
        pub fn empty() Self {
            return .{ .buffer = undefined, .len = 0 };
        }
        pub fn sliceMut(self: *Self) []u8 {
            return self.buffer[0..self.len];
        }
        pub fn slice(self: *const Self) []const u8 {
            return self.buffer[0..self.len];
        }

        pub fn sliceDbus(self: *const Self) Slice(Len, [*]const u8) {
            return .{ .ptr = &self.buffer, .len = self.len };
        }

        pub const format = if (zig_atleast_15) formatNew else formatLegacy;
        pub fn formatNew(self: Self, writer: *std.Io.Writer) error{WriteFailed}!void {
            try writer.print("{s}", .{self.slice()});
        }
        pub fn formatLegacy(
            self: @This(),
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try writer.print("{s}", .{self.slice()});
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
            // log_dbus.info("discarding {} bytes of header padding...", .{pad_len});
            try reader.discardAll(pad_len);
            return null;
        }

        // every header field is aligned to 8 bytes
        {
            const pad_len = pad8Len(@truncate(it.bytes_read));
            // log_dbus.info("discarding {} bytes of field padding...", .{pad_len});
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

pub fn consumeStringNullTerm(reader: *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!void {
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
    variant_sig,
    array_size,
    pub fn ReadType(kind: ReadKind) type {
        return switch (kind) {
            .boolean => bool,
            .u32 => u32,
            .string_size => u32,
            .object_path_size => u32,
            .variant_sig => void,
            .array_size => void,
        };
    }
    pub fn ReadContext(kind: ReadKind) type {
        return switch (kind) {
            .boolean,
            .u32,
            .string_size,
            .object_path_size,
            => void,
            .variant_sig => *SourceVariant,
            .array_size => *SourceArray,
        };
    }
    pub fn valueName(kind: ReadKind) [:0]const u8 {
        return switch (kind) {
            .boolean => "boolean",
            .u32 => "u32",
            .string_size => "string",
            .object_path_size => "object path",
            .variant_sig => "variant",
            .array_size => "array",
        };
    }

    pub fn sigChar(kind: ReadKind) u8 {
        return switch (kind) {
            .boolean => 'b',
            .u32 => 'u',
            .string_size => 's',
            .object_path_size => 'o',
            .variant_sig => 'v',
            .array_size => 'a',
        };
    }
};

/// Returns the initial padding size between the array size and its first element.
/// This padding is always present event if the array is empty (has a size of 0).
pub fn arrayPadLen(next_sig_char: u8, current_align: u3) u3 {
    return switch (next_sig_char) {
        'x', 't', 'd', '(', '{' => pad8Len(current_align),
        else => 0,
    };
}

pub const MsgStart = struct {
    endian: std.builtin.Endian,
    type: MessageType,
    flags: MessageFlags,
    body_len: u32,
    serial: u32,
    header_array_len: u32,
};

pub fn writeHeaders(
    writer: *Writer,
    path_buf: []const u8,
    signature: ?*const Bounded(255),
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
    if (signature) |*s| {
        try writer.print("  signature '{f}'\n", .{s.*});
    } else {
        try writer.writeAll("  signature (none)\n");
    }
}

fn writeSum(values: []const u32) error{Overflow}!u32 {
    var total: u32 = 0;
    for (values) |value| {
        total, const overflow = @addWithOverflow(total, value);
        if (overflow == 1) return error.Overflow;
    }
    return total;
}

fn incBody(values: []const u32) error{DbusProtocol}!u32 {
    var total: u32 = 0;
    for (values) |value| {
        total, const overflow = @addWithOverflow(total, value);
        if (overflow == 1) return error.DbusProtocol;
    }
    return total;
}
fn incBodyLimited(limit: u32, values: []const u32) error{DbusProtocol}!u32 {
    const offset = try incBody(values);
    if (offset > limit) return error.DbusProtocol;
    return offset;
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
            types[type_index], sig_index = nextType(sig, sig_index);
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
fn scanType(sig: []const u8, start: usize) ?usize {
    if (start >= sig.len) return null;
    return switch (sig[start]) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h', 'v' => start + 1,
        'a' => { // array
            if (start + 1 >= sig.len) return null;
            if (sig[start + 1] == '{') {
                if (start + 2 >= sig.len) return null;
                // key must be a basic type (not container nor variant)
                switch (sig[start + 2]) {
                    'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 's', 'o', 'g', 'h' => {},
                    else => return null,
                }
                const after_value = scanType(sig, start + 3) orelse return null;
                if (after_value >= sig.len) return null;
                if (sig[after_value] != '}') return null;
                return after_value + 1;
            }
            return scanType(sig, start + 1);
        },
        '(' => { // struct
            var pos = start + 1;
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

fn scanSig(sig: []const u8, offset: u8) u8 {
    return switch (sig[offset]) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 'h', 's', 'v' => offset + 1,
        'a' => @panic("todo"),
        '(' => @panic("todo"),
        else => unreachable,
    };
}
pub fn scanStructSig(sig: []const u8, start: u8) u8 {
    var offset: u8 = start;
    while (sig[offset] != ')') {
        offset = @intCast(scanType(sig, offset).?);
    }
    return offset + 1;
}
fn scanArrayElementSig(sig: []const u8, offset: u8) u8 {
    std.debug.assert(sig[offset - 1] == 'a');
    return switch (sig[offset]) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 'h', 's', 'v' => offset + 1,
        'a' => @panic("todo"),
        '(' => scanStructSig(sig, offset + 1),
        '{' => {
            const after_key = scanSig(sig, offset + 1);
            const after_value = scanSig(sig, after_key);
            std.debug.assert(sig[after_value] == '}');
            return after_value + 1;
        },
        else => unreachable,
    };
}

fn nextType(comptime sig: []const u8, start: u8) struct { Type, u8 } {
    return switch (sig[start]) {
        // basic types
        'y' => .{ .u8, start + 1 },
        'b' => .{ .bool, start + 1 },
        'n' => .{ .i16, start + 1 },
        'q' => .{ .u16, start + 1 },
        'i' => .{ .i32, start + 1 },
        'u' => .{ .u32, start + 1 },
        'x' => .{ .i64, start + 1 },
        't' => .{ .u64, start + 1 },
        'd' => .{ .f64, start + 1 },
        // 'h' => .{ u32, start+ 1 },

        // string types
        's' => .{ .string, start + 1 },
        'o' => .{ .object_path, start + 1 },
        'g' => .{ .signature, start + 1 },

        'v' => .{ .variant, start + 1 },

        'a' => {
            if (sig[start + 1] == '{') {
                const key_type, var offset = nextType(sig, start + 2);
                const value_type, offset = nextType(sig, offset);
                std.debug.assert(sig[offset] == '}');
                return .{ .{ .dict = .{
                    .key = typeAddr(key_type),
                    .value = typeAddr(value_type),
                } }, offset + 1 };
            }
            const element_type, const offset = nextType(sig, start + 1);
            return .{ .{ .array = typeAddr(element_type) }, offset };
        },
        '(' => {
            var sig_index: usize = start + 1;
            while (true) {
                if (sig_index >= sig.len) @compileError("invalid type signature '" ++ sig ++ "' (missing close paren)");
                if (sig[sig_index] == ')') {
                    sig_index += 1;
                    break;
                }
                sig_index = scanType(sig, sig_index) orelse @compileError("invalid type signature '" ++ sig ++ "'");
            }
            return .{ .{ .@"struct" = sig[start..sig_index] }, sig_index };
        },
        // '{' => {
        //     const key = nextType(sig[1..]);
        //     const value = nextType(sig[1 + key[1] ..]);
        //     break :blk .{ struct { key: key[0], value: value[0] }, 1 + key[1] + value[1] + 1 };
        // },
        else => @compileError("todo: handle sig: " ++ sig),
    };
}

pub fn stream(
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
                if (try incBody(&.{ offset, pad_len + 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const value = try reader.takeInt(u32, endian);
                offset += 4;
                try writer.print("<u32>{d}</u32>", .{value});
            },
            's' => {
                const pad_len: u32 = pad4Len(@truncate(offset));
                if (try incBody(&.{ offset, pad_len + 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const string_len = try reader.takeInt(u32, endian);
                offset += 4;
                if (try incBody(&.{ offset, string_len }) > limit)
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
                if (try incBody(&.{ offset, pad_len + 4 }) > limit)
                    return error.DbusProtocol;
                try reader.discardAll(pad_len);
                offset += pad_len;
                const array_size = try reader.takeInt(u32, endian);
                offset += 4;
                const initial_pad_len = arrayPadLen(type_sig[1], @truncate(offset));
                const array_limit = try incBody(&.{ offset, initial_pad_len, array_size });
                if (array_limit > limit) return error.DbusProtocol;
                try writer.print("<array size=\"{}\">", .{array_size});
                while (offset < array_limit) {
                    offset = try streamArrayElement(
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
                if (try incBody(&.{ offset, variant_sig_len + 1 }) > limit)
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
                        log_dbus.err("invalid variant type sig '{s}', it contains more than 1 type", .{variant_sig});
                        return error.DbusProtocol;
                    }
                } else {
                    log_dbus.err("variant type sig '{s}' is invalid", .{variant_sig});
                    return error.DbusProtocol;
                }

                try writer.print("<variant sig=\"{s}\">", .{variant_sig});
                offset = try stream(reader, writer, endian, variant_sig, limit, offset);
                try writer.writeAll("</variant>");
            },
            '{' => {
                log_dbus.err("invalid signature, a dictionary may only appear as an array element type", .{});
                return error.DbusProtocol;
            },
            else => |ch| {
                log_dbus.err("unsupported or unknown type sig char '{c}' in streamBody", .{ch});
                return error.DbusProtocol;
            },
        }
    }
}

fn streamArrayElement(
    reader: *Reader,
    writer: *Writer,
    endian: std.builtin.Endian,
    signature: []const u8,
    limit: u32,
    start: u32,
) error{ DbusProtocol, ReadFailed, EndOfStream, WriteFailed }!u32 {
    if (signature.len == 0) return error.DbusProtocol;
    if (signature[0] != '{') return stream(reader, writer, endian, signature, limit, start);

    if (signature.len < 4) return error.DbusProtocol;
    const sig_key_end = scanType(signature, 1) orelse return error.DbusProtocol;
    if (sig_key_end == signature.len) return error.DbusProtocol;
    const sig_value_end = scanType(signature, sig_key_end) orelse return error.DbusProtocol;
    if (sig_value_end == signature.len) return error.DbusProtocol;
    if (signature[sig_value_end] != '}') return error.DbusProtocol;

    const pad_len = pad8Len(@truncate(start));
    try reader.discardAll(pad_len);
    try writer.writeAll("<key>");
    const after_key = try stream(
        reader,
        writer,
        endian,
        signature[1..sig_key_end],
        limit,
        pad_len + start,
    );
    try writer.writeAll("</key><value>");
    const after_value = try stream(
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
        // signature: ?Bounded(max_sig) = null,
        unix_fds: ?u32 = null,

        const Self = @This();
        // pub fn signatureSlice(self: *const Self) []const u8 {
        //     return if (self.signature) |*s| s.slice() else "";
        // }

        pub fn expectReplySerial(self: *const Self, expected: u32) error{DbusProtocol}!void {
            if (self.reply_serial != expected) {
                log_dbus.err("expected serial {} but got {}", .{ expected, self.reply_serial });
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
                .unix_fds = self.unix_fds,
            };
        }
    };
}

// pub fn read(
//     comptime sig: []const u8,
//     comptime sig_index: *usize,
//     comptime kind: ReadKind,
// ) fn (*BodyIterator, *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.Type() {
//     const dbus_type, const char_count = nextType(sig[sig_index.*..]);
//     sig_index.* += char_count;
//     if (!dbus_type.matchesReadKind(kind)) @compileError("signature indicates type " ++ @tagName(dbus_type) ++ " but code is reading " ++ @tagName(kind));
//     return readFn(kind);
// }
// fn readFn(comptime kind: ReadKind) fn (*BodyIterator, *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.Type() {
//     return (struct {
//         fn func(it: *BodyIterator, reader: *Reader) error{ DbusProtocol, ReadFailed, EndOfStream }!kind.Type() {
//             const node = (try it.next(reader)) orelse {
//                 log_dbus.err("expected {s} but body has ended", .{kind.valueName()});
//                 return error.DbusProtocol;
//             };
//             if (kind != node) {
//                 log_dbus.err("expected {s} but got {s}", .{ kind.valueName(), node.valueName() });
//                 return error.DbusProtocol;
//             }
//             return @field(node, @tagName(kind));
//         }
//     }).func;
// }
