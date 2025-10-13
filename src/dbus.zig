const builtin = @import("builtin");
const std = @import("std");

pub const Connection = @import("dbus/Connection.zig");
pub const address = @import("dbus/address.zig");
pub const Address = address.Address;

const default_system_bus_path = "/var/run/dbus/system_bus_socket";
pub const default_system_bus_address_str = "unix:path=" ++ default_system_bus_path;
//pub const default_system_bus_address = comptime blk: {
//    .unix = .{ .path =
//};

// This maximum length applies to bus names, interfaces and members
pub const max_name = 255;

pub const BusAddressString = struct {
    origin: enum { hardcoded_default, environment_variable },
    str: []const u8,
};

pub fn getSystemBusAddress() Address {
    @panic("todo");
    //return std.os.getenv("DBUS_SYSTEM_BUS_ADDRESS") orelse default_system_bus_address;
}
pub fn getSessionBusAddressString() BusAddressString {
    if (std.posix.getenv("DBUS_SESSION_BUS_ADDRESS")) |s|
        return BusAddressString{ .origin = .environment_variable, .str = s };
    return BusAddressString{ .origin = .hardcoded_default, .str = default_system_bus_address_str };
}

pub const MessageType = enum(u8) {
    method_call = 1,
    method_return = 2,
    error_reply = 3,
    signal = 4,
};

const native_endian = builtin.cpu.arch.endian();
const endian_header_value = switch (native_endian) {
    .big => 'B',
    .little => 'l',
};

pub fn writeIntNative(comptime T: type, buf: [*]u8, value: T) void {
    @as(*align(1) T, @ptrCast(buf)).* = value;
}

pub fn readInt(comptime T: type, endian: std.builtin.Endian, comptime buf_align: u29, buf: [*]align(buf_align) const u8) T {
    const value = @as(*align(buf_align) const T, @ptrCast(buf)).*;
    return if (native_endian == endian) value else @byteSwap(value);
}

pub fn strSlice(comptime Len: type, comptime s: []const u8) Slice(Len, [*]const u8) {
    return Slice(Len, [*]const u8){
        .ptr = s.ptr,
        .len = @as(Len, @intCast(s.len)),
    };
}
pub fn sliceLen(ptr: anytype, len: anytype) Slice(@TypeOf(len), @TypeOf(ptr)) {
    return Slice(@TypeOf(len), @TypeOf(ptr)){ .ptr = ptr, .len = len };
}
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

        pub fn nativeSlice(self: @This()) NativeSlice {
            return self.ptr[0..self.len];
        }

        pub fn initComptime(comptime ct_slice: NativeSlice) @This() {
            return .{ .ptr = ct_slice.ptr, .len = @as(LenType, @intCast(ct_slice.len)) };
        }

        pub fn lenCast(self: @This(), comptime NewLenType: type) Slice(NewLenType, Ptr) {
            return .{ .ptr = self.ptr, .len = @as(NewLenType, @intCast(self.len)) };
        }

        pub usingnamespace switch (@typeInfo(Ptr).pointer.child) {
            u8 => struct {
                pub fn format(
                    self: Self,
                    comptime fmt: []const u8,
                    options: std.fmt.FormatOptions,
                    writer: anytype,
                ) !void {
                    _ = fmt;
                    _ = options;
                    try writer.writeAll(self.ptr[0..self.len]);
                }
            },
            else => struct {},
        };
    };
}

const header_fixed_part_len =
    4 // endian/type/flags/version
    + 4 // body_length
    + 4 // serial
;
fn stringEncodeLen(string_len: u32, align_to: u29) u32 {
    return @as(u32, @intCast(4 + std.mem.alignForward(u32, string_len + 1, align_to)));
}

fn serializeString(buf: [*]u8, str: Slice(u32, [*]const u8), align_to: u29) usize {
    writeIntNative(u32, buf, str.len);
    @memcpy(buf[4..][0..str.len], str);
    const pad_offset = 4 + str.len;
    const final_len = std.mem.alignForward(u32, pad_offset + 1, align_to);
    @memset(buf[pad_offset..final_len], 0);
    return final_len;
}

const DbusDataType = enum {
    byte,
    boolean,
    int16,
    uint16,
    int32,
    uint32,
    int64,
    uint64,
    double,
    string,
    //object_path, // same as string
    signature,
    array,
    @"struct",
    variant,
    //dict_entry, // same as struct
    //unix_fd, // same as uint32
};

const string_align = 4; // 4 for the uint32 length
const struct_align = 4; // 4 for the uint32 length
fn alignment(data_type: DbusDataType) u4 {
    return switch (data_type) {
        .byte => 1,
        .boolean => 4,
        .int16 => 2,
        .uint16 => 2,
        .int32 => 4,
        .uint32 => 4,
        .int64 => 8,
        .uint64 => 8,
        .string => string_align,
        .signature => 1,
        .array => 4, // for the length
        .@"struct" => struct_align, // each field is on an 8-byte boundary
        .variant => 1, // alignment of signature
    };
}

const HeaderFieldStringKind = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
    destination = 6,
    sender = 7,
    pub fn typeSig(kind: HeaderFieldStringKind) u8 {
        return switch (kind) {
            .path => 'o',
            .interface,
            .member,
            .error_name,
            .destination,
            .sender,
            => 's',
        };
    }
};
const HeaderFieldUint32Kind = enum(u8) {
    reply_serial = 5,
    unix_fds = 9,
};
const HeaderFieldKind = enum(u8) {
    path = @intFromEnum(HeaderFieldStringKind.path),
    interface = @intFromEnum(HeaderFieldStringKind.interface),
    member = @intFromEnum(HeaderFieldStringKind.member),
    error_name = @intFromEnum(HeaderFieldStringKind.error_name),
    reply_serial = @intFromEnum(HeaderFieldUint32Kind.reply_serial),
    destination = @intFromEnum(HeaderFieldStringKind.destination),
    sender = @intFromEnum(HeaderFieldStringKind.sender),
    signature = 8,
    unix_fds = @intFromEnum(HeaderFieldUint32Kind.unix_fds),
};

fn toAlign(len: usize) u4 {
    return @as(u4, @intCast(((len - 1) & 0x7) + 1));
}
fn alignAdd(in_align: u4, addend: usize) u4 {
    return toAlign(@as(usize, @intCast(in_align)) + addend);
}

fn Pad(comptime align_to: comptime_int) type {
    return switch (align_to) {
        4 => u2,
        8 => u3,
        else => @compileError("unsupported alignment"),
    };
}
/// Returns the padding needed to align the given len.
fn padLen(comptime align_to: comptime_int, len: Pad(align_to)) Pad(align_to) {
    return (0 -% len) & (align_to - 1);
}

// Returns the padding needed to align the given content len to 4-bytes.
// Note that it returns 0 for values already 4-byte aligned.
fn pad4Len(len: u2) u2 {
    return padLen(4, len);
}

// Returns the padding needed to align the given content len to 8-bytes.
// Note that it returns 0 for values already 8-byte aligned.
fn pad8Len(len: u3) u3 {
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

const header_field_string = struct {
    fn getLen(string_len: u32) u27 {
        return @as(u27, @intCast(4 + // 1 for kind, 3 for type sig
            4 + // string length uint32 (already aligned to 4)
            string_len + 1 // add 1 for null-terminator
        ));
    }
    fn serialize(msg: [*]u8, kind: HeaderFieldStringKind, str: Slice(u32, [*]const u8)) u27 {
        msg[0] = @intFromEnum(kind);
        msg[1] = 1; // type-sig length
        msg[2] = kind.typeSig();
        msg[3] = 0; // null-terminator
        const str_off = 4;
        // no padding
        comptime std.debug.assert(0 == pad.getLen(str_off, string_align));
        writeIntNative(u32, msg + str_off, str.len);
        @memcpy(msg[str_off + 4 ..][0..str.len], str.ptr);
        const end = str_off + 4 + str.len;
        msg[end] = 0;
        std.debug.assert(getLen(str.len) == end + 1);
        return @as(u27, @intCast(end + 1));
    }
};
const pad = struct {
    pub fn getLen(in_align: u4, out_align: u4) u4 {
        return @as(u4, @intCast(std.mem.alignForward(u4, in_align, out_align) - in_align));
    }
    pub fn serialize(msg: [*]u8, in_align: u4, out_align: u4) u4 {
        const len = getLen(in_align, out_align);
        @memset(msg[0..len], 0);
        return len;
    }
};

// NOTE: strings may not contain the codepoint 0
//       strings are ALWAYS null-terminated
//       they also must not contain OVERLONG sequences or exceed the value 0x10ffff
pub const max_codepoint = 0x10ffff;

pub const Type = enum {
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
    // pub fn sig(self: FixedType) u8 {
    //     return switch (self) {
    //         .u8 => 'y',
    //         .bool => 'b',
    //         .i16 => 'n',
    //         .u16 => 'q',
    //         .i32 => 'i',
    //         .u32 => 'u',
    //         .i64 => 'x',
    //         .u64 => 't',
    //         .f64 => 'd',
    //         .unix_fd => 'h',
    //     };
    // }
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

const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

const Iovlen = if (!zig_atleast_15 and builtin.cpu.arch == .x86_64)
    u32
else
    @FieldType(std.posix.msghdr_const, "iovlen");

const socketwriter = @import("socketwriter.zig");
pub const SocketWriter = socketwriter.SocketWriter;
pub fn socketWriter(sock: std.posix.socket_t, buffer: []u8) SocketWriter {
    if (zig_atleast_15) return (std.net.Stream{ .handle = sock }).writer(buffer);
    return .init(.{ .handle = sock }, buffer);
}
pub const Writer = @import("writer.zig").Writer;

fn calcHeaderStringLen(header_align: *u3, str: Slice(u32, [*]const u8)) u32 {
    const pad_len = pad8Len(header_align.*);
    const string_len: u32 = @as(u32, pad_len) + 8 + str.len + 1;
    header_align.* +%= @truncate(string_len);
    return string_len;
}
fn writeHeaderString(
    writer: *Writer,
    header_align: *u3,
    kind: HeaderFieldStringKind,
    str: Slice(u32, [*]const u8),
) Writer.Error!void {
    const pad_len = pad8Len(header_align.*);
    var buf: [8]u8 = undefined;
    buf[0] = @intFromEnum(kind);
    buf[1] = 1; // type-sig length
    buf[2] = kind.typeSig();
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

pub fn writeMethodCall(
    writer: *Writer,
    comptime signature: []const Type,
    args: MethodCall,
    body: Body(signature),
) (error{BodyTooBig} || Writer.Error)!void {
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

    {
        const pad_buf = [_]u8{0} ** 8;
        try writer.writeAll(pad_buf[0..pad8Len(header_align)]);
    }

    try writer.flush();
}

pub const MethodCall = struct {
    serial: u32,
    path: Slice(u32, [*]const u8),
    destination: ?Slice(u32, [*]const u8) = null,
    interface: ?Slice(u32, [*]const u8) = null,
    member: ?Slice(u32, [*]const u8) = null,
    pub fn calcHeaderArrayLen(self: *const MethodCall) u32 {
        var header_align: u3 = 0;
        const path_len = calcHeaderStringLen(&header_align, self.path);
        const dest_len = if (self.destination) |s| calcHeaderStringLen(&header_align, s) else 0;
        const iface_len = if (self.interface) |s| calcHeaderStringLen(&header_align, s) else 0;
        const member_len = if (self.member) |s| calcHeaderStringLen(&header_align, s) else 0;
        return path_len + dest_len + iface_len + member_len;
    }
};

//pub const signal_msg = struct {
//    pub const Args = struct {
//        serial: u32,
//        path: Slice(u32, [*]const u8),
//        interface: Slice(u32, [*]const u8),
//        member: Slice(u32, [*]const u8),
//    };
//    pub fn getHeaderLen(args: Args) u32 {
//        const len =
//            header_fixed_part_len
//            + stringEncodeLen(args.path.len, 4)
//            + stringEncodeLen(args.interface.len, 4)
//            + stringEncodeLen(args.member.len, 4)
//        ;
//        return @intCast(u32, std.mem.alignForward(len, 8));
//    }
//    pub fn serialize(msg: [*]u8, args: Args) void {
//        msg[0] = endian_header_value;
//        msg[1] = @enumToInt(MessageType.signal);
//        msg[2] = 0; // flags
//        msg[3] = 1; // protocol version
//        const body_length = 0;
//        writeIntNative(u32, msg + 4, body_length);
//        writeIntNative(u32, msg + 8, args.serial);
//
//        if (true) @panic("TODO: serialize the optional header field array length");
//
//        var offset: usize = 12;
//        offset += serializeString(msg + offset, args.path, 4);
//        offset += serializeString(msg + offset, args.interface, 4);
//        offset += serializeString(msg + offset, args.member, 4);
//        std.debug.assert(std.mem.alignForward(offset, 8) == getHeaderLen(args));
//    }
//};
//

fn getEndian(first_msg_byte: u8) ?std.builtin.Endian {
    return switch (first_msg_byte) {
        'l' => std.builtin.Endian.little,
        'B' => std.builtin.Endian.big,
        else => null,
    };
}

pub const GetMsgLenError = error{ InvalidEndianValue, TooBig };
/// Returned len is guaranteed to be 8-byte aligned
pub fn getMsgLen(msg: []align(8) const u8) GetMsgLenError!?u27 {
    if (msg.len < 16) return null;
    return try getMsgLenAssumeAtLeast16(msg);
}
/// Returned len is guaranteed to be 8-byte aligned
pub fn getMsgLenAssumeAtLeast16(msg: []align(8) const u8) GetMsgLenError!u27 {
    const endian = getEndian(msg[0]) orelse return error.InvalidEndianValue;
    const body_len = readInt(u32, endian, comptime toAlign(4), msg.ptr + 4);
    const header_array_len = readInt(u32, endian, comptime toAlign(12), msg.ptr + 12);
    const header_end = 16 + std.mem.alignForward(u32, header_array_len, 8);
    return std.math.cast(u27, header_end + body_len) orelse error.TooBig;
}

pub fn parseMsgType(msg_ptr: [*]align(8) const u8) ?MessageType {
    return switch (msg_ptr[1]) {
        @intFromEnum(MessageType.method_call) => MessageType.method_call,
        @intFromEnum(MessageType.method_return) => MessageType.method_return,
        @intFromEnum(MessageType.error_reply) => MessageType.error_reply,
        @intFromEnum(MessageType.signal) => MessageType.signal,
        else => null,
    };
}
pub const ParsedMsg = struct {
    endian: std.builtin.Endian,
    header_end: u27,
    unknown_header_count: u32,
    headers: Headers,
    pub const Headers = union(enum) {
        method_return: struct {
            reply_serial: u32,
            // TODO: are all these really option for method_return?
            destination: ?[]const u8,
            sender: ?[]const u8,
            signature: ?[]const u8,
            unix_fds: ?u32,
        },
        signal: struct {
            path: []const u8,
            interface: []const u8,
            member: []const u8,
            // TODO: are all these really option for signal?
            destination: ?[]const u8,
            sender: ?[]const u8,
            signature: ?[]const u8,
            unix_fds: ?u32,
        },
        err: struct {
            reply_serial: u32,
            name: []const u8,
            path: ?[]const u8,
            interface: ?[]const u8,
            member: ?[]const u8,
            destination: ?[]const u8,
            sender: ?[]const u8,
            signature: ?[]const u8,
            unix_fds: ?u32,
        },
    };

    pub fn serial(self: ParsedMsg, msg_ptr: [*]align(8) const u8) u32 {
        return readInt(u32, self.endian, 8, msg_ptr + 8);
    }

    pub const HeaderField = union(enum) {
        unknown: struct {
            id: u8,
        },
        string: struct {
            kind: HeaderFieldStringKind,
            str: [:0]align(4) const u8,
        },
        uint32: struct {
            kind: HeaderFieldUint32Kind,
            val: u32,
        },
        sig: [:0]const u8,
    };
    pub const HeaderArrayIterator = struct {
        endian: std.builtin.Endian,
        header_end: u27,
        offset: u27 = 16,

        pub const NextError = error{
            FieldTooBig,
            UnexpectedTypeSig,
            NoNullTerm,
        };
        pub fn next(self: *HeaderArrayIterator, msg_ptr: [*]align(8) const u8) NextError!?HeaderField {
            const start = self.offset;
            if (start == self.header_end) return null;
            const parse_type: union(enum) {
                string: HeaderFieldStringKind,
                uint32: HeaderFieldUint32Kind,
                signature: void,
                unknown: u8,
            } = switch (msg_ptr[start]) {
                @intFromEnum(HeaderFieldKind.path) => .{ .string = .path },
                @intFromEnum(HeaderFieldKind.interface) => .{ .string = .interface },
                @intFromEnum(HeaderFieldKind.member) => .{ .string = .member },
                @intFromEnum(HeaderFieldKind.error_name) => .{ .string = .error_name },
                @intFromEnum(HeaderFieldKind.reply_serial) => .{ .uint32 = .reply_serial },
                @intFromEnum(HeaderFieldKind.destination) => .{ .string = .destination },
                @intFromEnum(HeaderFieldKind.sender) => .{ .string = .sender },
                @intFromEnum(HeaderFieldKind.signature) => .signature,
                @intFromEnum(HeaderFieldKind.unix_fds) => .{ .uint32 = .unix_fds },
                else => |id| .{ .unknown = id },
            };
            switch (parse_type) {
                .string => |kind| {
                    const string_start = start + 8;
                    if (string_start > self.header_end) return error.FieldTooBig;
                    if (msg_ptr[start + 1] != 1) return error.UnexpectedTypeSig;
                    if (msg_ptr[start + 2] != kind.typeSig()) return error.UnexpectedTypeSig;
                    if (msg_ptr[start + 3] != 0) return error.UnexpectedTypeSig;
                    const string_len = readInt(u32, self.endian, 4, @as([*]align(4) const u8, @alignCast(msg_ptr + start + 4)));
                    // string_len + 1 for null terminator
                    const field_end = string_start + std.mem.alignForward(u32, string_len + 1, 8);
                    if (field_end > self.header_end) return error.FieldTooBig;
                    const str = msg_ptr[string_start .. string_start + string_len];
                    if (str.ptr[string_len] != 0) return error.NoNullTerm;
                    self.offset = @as(u27, @intCast(field_end));
                    return HeaderField{ .string = .{
                        .kind = kind,
                        .str = @ptrCast(@alignCast(str)),
                    } };
                },
                .uint32 => |kind| {
                    const field_end = start + 8;
                    if (field_end > self.header_end) return error.FieldTooBig;
                    if (msg_ptr[start + 1] != 1) return error.UnexpectedTypeSig;
                    if (msg_ptr[start + 2] != 'u') return error.UnexpectedTypeSig;
                    const val = readInt(u32, self.endian, 4, @as([*]align(4) const u8, @alignCast(msg_ptr + start + 4)));
                    self.offset = @as(u27, @intCast(field_end));
                    return HeaderField{ .uint32 = .{ .kind = kind, .val = val } };
                },
                .signature => {
                    const sig_content_start = start + 5;
                    if (sig_content_start > self.header_end) return error.FieldTooBig;
                    if (msg_ptr[start + 1] != 1) return error.UnexpectedTypeSig;
                    if (msg_ptr[start + 2] != 'g') return error.UnexpectedTypeSig;
                    if (msg_ptr[start + 3] != 0) return error.UnexpectedTypeSig;
                    const sig_len = msg_ptr[start + 4];
                    // sign_len + 1 for null terminator
                    const field_end = std.mem.alignForward(u32, sig_content_start + sig_len + 1, 8);
                    if (field_end > self.header_end) return error.FieldTooBig;
                    const sig = msg_ptr[sig_content_start .. sig_content_start + sig_len];
                    if (sig.ptr[sig_len] != 0) return error.NoNullTerm;
                    self.offset = @as(u27, @intCast(field_end));
                    return HeaderField{ .sig = @ptrCast(sig) };
                },
                .unknown => |id| {
                    std.log.warn("TODO: got unknown header field id '{}', use the type signature to skip it", .{id});
                    self.offset = self.header_end;
                    return HeaderField{ .unknown = .{ .id = id } };
                },
            }
        }
    };
    pub fn headerArrayIterator(self: ParsedMsg) HeaderArrayIterator {
        return .{ .endian = self.endian, .header_end = self.header_end };
    }
};

pub fn parseMsg(msg: []align(8) const u8) ParsedMsgError!ParsedMsg {
    const msg_len = getMsgLenAssumeAtLeast16(msg) catch unreachable;
    std.debug.assert(msg.len == msg_len);
    return parseMsgAssumeGetMsgLen(.{ .ptr = msg.ptr, .len = msg_len });
}

pub const ParsedMsgError = error{
    InvalidMsgType,
    DuplicateHeader,
} || ParsedMsg.HeaderArrayIterator.NextError || HeaderParser.ToParsedHeadersError;

/// parse a complete message (msg is exactly 1 complete message)
pub fn parseMsgAssumeGetMsgLen(msg: Slice(u27, [*]align(8) const u8)) ParsedMsgError!ParsedMsg {
    std.debug.assert((getMsgLenAssumeAtLeast16(msg.nativeSlice()) catch unreachable) == msg.len);
    // an invalid endian value should be impossible because this would have been caught in getMsgLen
    const endian = getEndian(msg.ptr[0]) orelse unreachable;
    const header_array_len = readInt(u32, endian, comptime toAlign(4), msg.ptr + 12);
    const header_end = @as(u27, @intCast(16 + std.mem.alignForward(u32, header_array_len, 8)));
    const msg_type = parseMsgType(msg.ptr) orelse return error.InvalidMsgType;
    var header_parser = HeaderParser{};
    {
        var it = ParsedMsg.HeaderArrayIterator{
            .endian = endian,
            .header_end = header_end,
        };
        while (try it.next(msg.ptr)) |header_field| {
            switch (header_field) {
                .unknown => header_parser.unknown_header_count += 1,
                .string => |str| {
                    const str_ptr = header_parser.getStringHeaderPtr(str.kind);
                    if (str_ptr.*) |_| return error.DuplicateHeader;
                    str_ptr.* = str.str;
                },
                .uint32 => |u| {
                    const uint_ptr = header_parser.getUint32HeaderPtr(u.kind);
                    if (uint_ptr.*) |_| return error.DuplicateHeader;
                    uint_ptr.* = u.val;
                },
                .sig => |s| {
                    if (header_parser.signature) |_| return error.DuplicateHeader;
                    header_parser.signature = s;
                },
            }
        }
    }

    return ParsedMsg{
        .endian = endian,
        .header_end = header_end,
        .unknown_header_count = header_parser.unknown_header_count,
        .headers = try header_parser.toParsedHeaders(msg_type),
    };
}

const HeaderParser = struct {
    unknown_header_count: u32 = 0,
    path: ?[:0]const u8 = null,
    interface: ?[:0]const u8 = null,
    member: ?[:0]const u8 = null,
    error_name: ?[:0]const u8 = null,
    reply_serial: ?u32 = null,
    destination: ?[:0]const u8 = null,
    sender: ?[:0]const u8 = null,
    signature: ?[:0]const u8 = null,
    unix_fds: ?u32 = null,
    pub fn getStringHeaderPtr(
        self: *HeaderParser,
        kind: HeaderFieldStringKind,
    ) *?[:0]const u8 {
        return switch (kind) {
            .path => &self.path,
            .interface => &self.interface,
            .member => &self.member,
            .error_name => &self.error_name,
            .destination => &self.destination,
            .sender => &self.sender,
        };
    }
    pub fn getUint32HeaderPtr(
        self: *HeaderParser,
        kind: HeaderFieldUint32Kind,
    ) *?u32 {
        return switch (kind) {
            .reply_serial => &self.reply_serial,
            .unix_fds => &self.unix_fds,
        };
    }
    pub const ToParsedHeadersError = error{
        MissingPathHeader,
        MissingInterfaceHeader,
        MissingMemberHeader,
        MissingSerialHeader,
        MissingErrorName,
        UnexpectedPathHeader,
        UnexpectedInterfaceHeader,
        UnexpectedMemberHeader,
        UnexpectedErrorHeader,
        UnexpectedSerialHeader,
    };
    pub fn toParsedHeaders(
        self: HeaderParser,
        msg_type: MessageType,
    ) ToParsedHeadersError!ParsedMsg.Headers {
        switch (msg_type) {
            .method_call => {
                const path = self.path orelse return error.MissingPathHeader;
                _ = path;
                @panic("todo");
            },
            .method_return => {
                if (self.path) |_| return error.UnexpectedPathHeader;
                if (self.interface) |_| return error.UnexpectedInterfaceHeader;
                if (self.member) |_| return error.UnexpectedMemberHeader;
                if (self.error_name) |_| return error.UnexpectedErrorHeader;
                return ParsedMsg.Headers{
                    .method_return = .{
                        .reply_serial = self.reply_serial orelse return error.MissingSerialHeader,
                        .destination = self.destination,
                        .sender = self.sender,
                        .signature = self.signature,
                        .unix_fds = self.unix_fds,
                    },
                };
            },
            .error_reply => {
                return ParsedMsg.Headers{ .err = .{
                    .reply_serial = self.reply_serial orelse return error.MissingSerialHeader,
                    .name = self.error_name orelse return error.MissingErrorName,
                    .path = self.path,
                    .interface = self.interface,
                    .member = self.member,
                    .destination = self.destination,
                    .sender = self.sender,
                    .signature = self.signature,
                    .unix_fds = self.unix_fds,
                } };
            },
            .signal => {
                if (self.error_name) |_| return error.UnexpectedErrorHeader;
                if (self.reply_serial) |_| return error.UnexpectedSerialHeader;
                return ParsedMsg.Headers{
                    .signal = .{
                        .path = self.path orelse return error.MissingPathHeader,
                        .interface = self.interface orelse return error.MissingInterfaceHeader,
                        .member = self.member orelse return error.MissingMemberHeader,
                        .destination = self.destination,
                        .sender = self.sender,
                        .signature = self.signature,
                        .unix_fds = self.unix_fds,
                    },
                };
            },
        }
    }
};

// TODO: not sure if this is the right function and/or place for this
pub fn parseString(endian: std.builtin.Endian, buf: []const u8, offset: usize) ?struct {
    string: [:0]const u8,
    end: usize,
} {
    if (offset + 4 > buf.len) return null;
    const len = std.mem.readInt(u32, buf[offset..][0..4], endian);
    const null_index = offset + 4 + len;
    if (null_index >= buf.len) return null;
    if (buf[null_index] != 0) return null;
    return .{ .string = buf[offset + 4 .. null_index :0], .end = null_index + 1 };
}

fn readFull(reader: anytype, buf: []u8) (@TypeOf(reader).Error || error{EndOfStream})!void {
    std.debug.assert(buf.len > 0);
    var total_received: usize = 0;
    while (true) {
        const last_received = try reader.read(buf[total_received..]);
        if (last_received == 0)
            return error.EndOfStream;
        total_received += last_received;
        if (total_received == buf.len)
            break;
    }
}

pub const ReadOneMsg = union(enum) {
    partial: u27,
    complete: u27,
};
/// The caller must check whether the length returned is larger than the provided `buf`.
/// If it is, then only the first 16-bytes have been read.  The caller can allocate a new
/// buffer large enough to accomodate and finish reading the message by copying the first
/// 16 bytes to the new buffer then calling `readOneMsgFinish`.
pub fn readOneMsg(reader: anytype, buf: []align(8) u8) !ReadOneMsg {
    std.debug.assert(buf.len >= 16);
    try readFull(reader, buf[0..16]);
    const msg_len = getMsgLenAssumeAtLeast16(buf) catch |err| switch (err) {
        error.InvalidEndianValue => return error.DbusMsgInvalidEndianValue,
        error.TooBig => return error.DbusMsgTooBig,
    };
    if (msg_len > buf.len) return ReadOneMsg{ .partial = msg_len };

    try readOneMsgFinish(reader, buf[0..msg_len]);
    return ReadOneMsg{ .complete = msg_len };
}

pub fn readOneMsgFinish(reader: anytype, buf: []align(8) u8) !void {
    if (builtin.mode == .Debug) {
        const msg_len = getMsgLenAssumeAtLeast16(buf) catch unreachable;
        std.debug.assert(buf.len == msg_len);
    }
    try readFull(reader, buf[16..]);
}

pub fn readOneMsgArrayList(reader: anytype, al: *std.ArrayListAligned(u8, 8)) !void {
    std.debug.assert(std.mem.isAligned(al.items.len, 8));

    try al.ensureUnusedCapacity(16);
    const header: []align(8) u8 = @alignCast(al.unusedCapacitySlice()[0..16]);
    try readFull(reader, header);
    al.items.len += 16;
    const msg_len = getMsgLenAssumeAtLeast16(header) catch |err| switch (err) {
        error.InvalidEndianValue => return error.DbusMsgInvalidEndianValue,
        error.TooBig => return error.DbusMsgTooBig,
    };
    const remaining = msg_len - 16;
    try al.ensureUnusedCapacity(remaining);
    try readFull(reader, al.unusedCapacitySlice()[0..remaining]);
    al.items.len += remaining;
}
