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

pub const BusAddressString = struct {
    origin: enum { hardcoded_default, environment_variable },
    str: []const u8,
};

pub fn getSystemBusAddress() Address {
    @panic("todo");
    //return std.os.getenv("DBUS_SYSTEM_BUS_ADDRESS") orelse default_system_bus_address;
}
pub fn getSessionBusAddressString() BusAddressString {
    if (std.os.getenv("DBUS_SESSION_BUS_ADDRESS")) |s|
        return BusAddressString{ .origin = .environment_variable, .str = s };
    return BusAddressString{ .origin = .hardcoded_default, .str = default_system_bus_address_str };
}

pub const MessageType = enum(u8) {
    method_call = 1,
    method_return = 2,
    error_reply = 3,
    signal = 4,
};

const endian_header_value = switch (builtin.cpu.arch.endian()) {
    .Big => 'B',
    .Little => 'l',
};

pub fn writeIntNative(comptime T: type, buf: [*]u8, value: T) void {
    @ptrCast(*align(1) T, buf).* = value;
}

pub fn readInt(comptime buf_align: u29, comptime T: type, endian: std.builtin.Endian, buf: [*]align(buf_align) const u8) T {
    const value = @ptrCast(*const align(buf_align) T, buf).*;
    return if (builtin.cpu.arch.endian() == endian) value else @byteSwap(T, value);
}

pub fn strSlice(comptime Len: type, comptime s: []const u8) Slice(Len, [*]const u8) {
    return Slice(Len, [*]const u8){
        .ptr = s.ptr,
        .len = @intCast(Len, s.len),
    };
}
pub fn Slice(comptime LenType: type, comptime Ptr: type) type { return struct {
    const Self = @This();
    const ptr_info = @typeInfo(Ptr).Pointer;
    pub const NativeSlice = @Type(std.builtin.TypeInfo {
        .Pointer = .{
            .size = .Slice,
            .is_const = ptr_info.is_const,
            .is_volatile = ptr_info.is_volatile,
            .alignment = ptr_info.alignment,
            .address_space = ptr_info.address_space,
            .child = ptr_info.child,
            .is_allowzero = ptr_info.is_allowzero,
            .sentinel = ptr_info.sentinel,
        },
    });

    ptr: Ptr,
    len: LenType,

    pub fn nativeSlice(self: @This()) NativeSlice {
        return self.ptr[0 .. self.len];
    }

    pub fn initComptime(comptime ct_slice: NativeSlice) @This() {
        return .{ .ptr = ct_slice.ptr, .len = @intCast(LenType, ct_slice.len) };
    }

    pub fn lenCast(self: @This(), comptime NewLenType: type) Slice(NewLenType, Ptr) {
        return .{ .ptr = self.ptr, .len = @intCast(NewLenType, self.len) };
    }

    pub usingnamespace switch (@typeInfo(Ptr).Pointer.child) {
        u8 => struct {
            pub fn format(
                self: Self,
                comptime fmt: []const u8,
                options: std.fmt.FormatOptions,
                writer: anytype,
            ) !void {
                _ = fmt; _ = options;
                try writer.writeAll(self.ptr[0 .. self.len]);
            }
        },
        else => struct {},
    };
};}

const header_fixed_part_len =
      4 // endian/type/flags/version
    + 4 // body_length
    + 4 // serial
;
fn stringEncodeLen(string_len: u32, align_to: u29) u32 {
    return @intCast(u32, 4 + std.mem.alignForward(string_len + 1, align_to));
}

fn serializeString(buf: [*]u8, str: Slice(u32, [*]const u8), align_to: u29) usize {
    writeIntNative(u32, buf, str.len);
    @memcpy(buf + 4, str.ptr, str.len);
    const pad_offset = 4 + str.len;
    const final_len = std.mem.alignForward(pad_offset + 1, align_to);
    @memset(buf + pad_offset, 0, final_len - pad_offset);
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
const HeaderFieldKind = enum(u8) {
    path = @enumToInt(HeaderFieldStringKind.path),
    interface = @enumToInt(HeaderFieldStringKind.interface),
    member = @enumToInt(HeaderFieldStringKind.member),
    error_name = @enumToInt(HeaderFieldStringKind.error_name),
    reply_serial = 5,
    destination = @enumToInt(HeaderFieldStringKind.destination),
    sender = @enumToInt(HeaderFieldStringKind.sender),
    signature = 8,
    unix_fds = 9,
};

fn toAlign(len: usize) u4 {
    return @intCast(u4, ((len - 1) & 0x7) + 1);
}
fn alignAdd(in_align: u4, addend: usize) u4 {
    return toAlign(@intCast(usize, in_align) + addend);
}

const header_field = struct {
    fn getLen(in_align: u4, string_len: u32) u27 {
        return @intCast(u27,
            3 + // kind, typesig
            pad.getLen(alignAdd(in_align, 3), string_align) +
            4 + // string length uint32
            string_len + 1 // add 1 for null-terminator
        );
    }
    fn serialize(msg: [*]u8, in_align: u4, kind: HeaderFieldStringKind, str: Slice(u32, [*]const u8)) u27 {
        msg[0] = @enumToInt(kind);
        msg[1] = 1; // type-sig length
        msg[2] = kind.typeSig();
        const pad_len = pad.getLen(alignAdd(in_align, 3), string_align);
        std.mem.set(u8, msg[3..3 + pad_len], 0);
        const str_off = 3 + pad_len;
        writeIntNative(u32, msg + str_off, str.len);
        @memcpy(msg + str_off + 4, str.ptr, str.len);
        const end = str_off + 4 + str.len;
        msg[end] = 0;
        std.debug.assert(getLen(in_align, str.len) == end + 1);
        return @intCast(u27, end + 1);
    }
};
const pad = struct {
    pub fn getLen(in_align: u4, out_align: u4) u4 {
        return @intCast(u4, std.mem.alignForward(in_align, out_align) - in_align);
    }
    pub fn serialize(msg: [*]u8, in_align: u4, out_align: u4) u4 {
        const len = getLen(in_align, out_align);
        std.mem.set(u8, msg[0 .. len], 0);
        return len;
    }
};

const LenEncoder = struct {
    len: u27 = 0,
    pub fn set(self: *LenEncoder, comptime T: type, offset: u27, value: T) void {
        _ = value;
        switch (T) {
            u8 => self.len = std.math.max(self.len, offset + 1),
            u32 => self.len = std.math.max(self.len, offset + 4),
            else => @compileError("LenEncoder.set does not support: " ++ @typeName(T)),
        }
    }
    pub fn setBytes(self: *LenEncoder, start: u27, end: u27, val: u8) void {
        _ = start;
        _ = val;
        self.len = std.math.max(self.len, end);
    }
    pub fn setHeaderFieldString(
        self: *LenEncoder,
        offset: u27,
        kind: HeaderFieldStringKind,
        str: Slice(u32, [*]const u8),
    ) u27 {
        _ = kind;
        var len: u27 = pad.getLen(toAlign(offset), struct_align);
        len += header_field.getLen(toAlign(offset + len), str.len);
        self.len = std.math.max(self.len, offset + len);
        return len;
    }
};

const MsgEncoder = struct {
    msg: [*]u8,
    pub fn set(self: *MsgEncoder, comptime T: type, offset: u27, value: T) void {
        switch (T) {
            u8 => self.msg[offset] = value,
            u32 => writeIntNative(u32, self.msg + offset, value),
            else => @compileError("MsgEncoder.set does not support: " ++ @typeName(T)),
        }
    }
    pub fn setBytes(self: *MsgEncoder, start: u27, end: u27, val: u8) void {
        std.mem.set(u8, self.msg[start..end], val);
    }
    pub fn setHeaderFieldString(
        self: *MsgEncoder,
        offset: u27,
        kind: HeaderFieldStringKind,
        str: Slice(u32, [*]const u8),
    ) u27 {
        const pad_len = pad.serialize(self.msg + offset, toAlign(offset), struct_align);
        const str_offset = offset + pad_len;
        return pad_len + header_field.serialize(self.msg + str_offset, toAlign(str_offset), kind, str);
    }
};

pub const method_call_msg = struct {
    pub const Args = struct {
        serial: u32,
        path: Slice(u32, [*]const u8),
        destination: ?Slice(u32, [*]const u8) = null,
        interface: ?Slice(u32, [*]const u8) = null,
        member: ?Slice(u32, [*]const u8) = null,
        signature: ?Slice(u32, [*]const u8) = null,
    };

    pub fn encode(comptime Encoder: type, encoder: Encoder, args: Args) void {
        encoder.set(u8, 0, endian_header_value);
        encoder.set(u8, 1, @enumToInt(MessageType.method_call));
        encoder.set(u8, 2, 0); // flags
        encoder.set(u8, 3, 1); // protocol version
        const body_length = 0;
        encoder.set(u32, 4, body_length);
        encoder.set(u32, 8, args.serial);
        // offset 12 is the array data length, will serialize below
        // note: offset(16) is already 8-byte aligned here
        var field_array_len = encoder.setHeaderFieldString(16, .path, args.path);
        if (args.destination) |arg| {
            field_array_len += encoder.setHeaderFieldString(16 + field_array_len, .destination, arg);
        }
        if (args.interface) |arg| {
            field_array_len += encoder.setHeaderFieldString(16 + field_array_len, .interface, arg);
        }
        if (args.member) |arg| {
            field_array_len += encoder.setHeaderFieldString(16 + field_array_len, .member, arg);
        }

        // TODO: is the array length the padded or non-padded length?
        encoder.set(u32, 12, @intCast(u32, field_array_len));

        const end = @intCast(u27, std.mem.alignForward(16 + field_array_len, 8));
        encoder.setBytes(16 + field_array_len, end, 0);
    }
    pub fn getHeaderLen(args: Args) u27 {
        var encoder = LenEncoder { };
        encode(*LenEncoder, &encoder, args);
        return encoder.len;
    }
    pub fn serialize(msg: [*]u8, args: Args) void {
        var encoder = MsgEncoder { .msg = msg };
        encode(*MsgEncoder, &encoder, args);
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

pub const GetMsgLenError = error { InvalidEndianValue, TooBig };
pub fn getMsgLen(msg: []const align(8) u8) GetMsgLenError!?u27 {
    // first thing we check is if we have the whole message
    if (msg.len < 16) return null;
    return try getMsgLenAssumeAtLeast16(msg);
}
pub fn getMsgLenAssumeAtLeast16(msg: []const align(8) u8) GetMsgLenError!u27 {
    const endian = switch (msg[0]) {
        'l' => std.builtin.Endian.Little,
        'B' => std.builtin.Endian.Big,
        else => return error.InvalidEndianValue,
    };
    const body_len = readInt(4, u32, endian, msg.ptr + 4);
    const field_array_len = readInt(4, u32, endian, msg.ptr + 12);
    const header_end = 16 + std.mem.alignForward(field_array_len, 8);
    return std.math.cast(u27, header_end + body_len) catch error.TooBig;
}

pub const MsgTaggedUnion = union(enum) {
    method_return: *align(8) Msg.MethodReturn,
};
//pub fn msgAsTaggedUnion(msg: [*]align(8) u8) ?MsgTaggedUnion {
//    return switch (msg[1]) {
//        MessageType.method_return => .{ .method_return = @ptrCast(*align(8) Msg.MethodReturn, msg) },
//        else => null,
//    }
//}

pub const Msg = extern union {
//    generic: Generic,
//    method_call: void,
    method_return: MethodReturn,
//    error_reply: void,
//    signal: void,
//
//    pub const Generic = extern struct {
//        endian: u8,
//        message_type: u8,
//        flags: u8,
//        protocol_version: u8,
//        body_length: u32,
//        serial: u32,
//    };
    pub const MethodReturn = extern struct {
    };
};

fn readFull(reader: anytype, buf: []u8) (@TypeOf(reader).Error || error{EndOfStream})!void {
    std.debug.assert(buf.len > 0);
    var total_received : usize = 0;
    while (true) {
        const last_received = try reader.read(buf[total_received..]);
        if (last_received == 0)
            return error.EndOfStream;
        total_received += last_received;
        if (total_received == buf.len)
            break;
    }
}

/// The caller must check whether the length returned is larger than the provided `buf`.
/// If it is, then only the first 16-bytes have been read.  The caller can allocate a new
/// buffer large enough to accomodate and finish reading the message by copying the first
/// 16 bytes to the new buffer then calling `readOneMsgFinish`.
pub fn readOneMsg(reader: anytype, buf: []align(8) u8) !u27 {
    std.debug.assert(buf.len >= 16);
    try readFull(reader, buf[0 .. 16]);
    const msg_len = getMsgLenAssumeAtLeast16(buf) catch |err| switch (err) {
        error.InvalidEndianValue => return error.DbusMsgInvalidEndianValue,
        error.TooBig => return error.DbusMsgTooBig,
    };
    if (msg_len <= buf.len) {
        try readOneMsgFinish(reader, buf[0 .. msg_len]);
    }
    return msg_len;
}

pub fn readOneMsgFinish(reader: anytype, buf: []align(8) u8) !void {
    if (builtin.mode == .Debug) {
        const msg_len = getMsgLenAssumeAtLeast16(buf) catch unreachable;
        std.debug.assert(buf.len == msg_len);
    }
    try readFull(reader, buf[16..]);
}
