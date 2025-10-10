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

const endian_header_value = switch (builtin.cpu.arch.endian()) {
    .big => 'B',
    .little => 'l',
};

pub fn writeIntNative(comptime T: type, buf: [*]u8, value: T) void {
    @as(*align(1) T, @ptrCast(buf)).* = value;
}

pub fn readInt(comptime T: type, endian: std.builtin.Endian, comptime buf_align: u29, buf: [*]align(buf_align) const u8) T {
    const value = @as(*align(buf_align) const T, @ptrCast(buf)).*;
    return if (builtin.cpu.arch.endian() == endian) value else @byteSwap(value);
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

const LenEncoder = struct {
    len: u27 = 0,
    pub fn set(self: *LenEncoder, comptime T: type, offset: u27, value: T) void {
        _ = value;
        switch (T) {
            u8 => self.len = @max(self.len, offset + 1),
            u32 => self.len = @max(self.len, offset + 4),
            else => @compileError("LenEncoder.set does not support: " ++ @typeName(T)),
        }
    }
    pub fn setBytes(self: *LenEncoder, start: u27, end: u27, val: u8) void {
        _ = start;
        _ = val;
        self.len = @max(self.len, end);
    }
    pub fn setHeaderFieldString(
        self: *LenEncoder,
        offset: u27,
        kind: HeaderFieldStringKind,
        str: Slice(u32, [*]const u8),
    ) u27 {
        _ = kind;
        var len: u27 = pad.getLen(toAlign(offset), struct_align);
        len += header_field_string.getLen(str.len);
        self.len = @max(self.len, offset + len);
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
        @memset(self.msg[start..end], val);
    }
    pub fn setHeaderFieldString(
        self: *MsgEncoder,
        offset: u27,
        kind: HeaderFieldStringKind,
        str: Slice(u32, [*]const u8),
    ) u27 {
        const pad_len = pad.serialize(self.msg + offset, toAlign(offset), struct_align);
        const str_offset = offset + pad_len;
        return pad_len + header_field_string.serialize(self.msg + str_offset, kind, str);
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
        encoder.set(u8, 1, @intFromEnum(MessageType.method_call));
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
        encoder.set(u32, 12, @as(u32, @intCast(field_array_len)));

        const end = @as(u27, @intCast(std.mem.alignForward(u32, 16 + field_array_len, 8)));
        encoder.setBytes(16 + field_array_len, end, 0);
    }
    pub fn getHeaderLen(args: Args) u27 {
        var encoder = LenEncoder{};
        encode(*LenEncoder, &encoder, args);
        return encoder.len;
    }
    pub fn serialize(msg: [*]u8, args: Args) void {
        var encoder = MsgEncoder{ .msg = msg };
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

fn getEndian(first_msg_byte: u8) ?std.builtin.Endian {
    return switch (first_msg_byte) {
        'l' => std.builtin.Endian.little,
        'B' => std.builtin.Endian.big,
        else => null,
    };
}

pub const GetMsgLenError = error{ InvalidEndianValue, TooBig };
pub fn getMsgLen(msg: []align(8) const u8) GetMsgLenError!?u27 {
    if (msg.len < 16) return null;
    return try getMsgLenAssumeAtLeast16(msg);
}
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
            .method_call => @panic("todo"),
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
            .error_reply => @panic("todo"),
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
