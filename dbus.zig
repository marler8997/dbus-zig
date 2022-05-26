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
pub fn readIntNative(comptime T: type, buf: [*]const u8) T {
    return @ptrCast(*const align(1) T, buf).*;
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

pub const method_call_msg = struct {
    pub const Args = struct {
        serial: u32,
        path: Slice(u32, [*]const u8),
        interface: ?Slice(u32, [*]const u8) = null,
        member: ?Slice(u32, [*]const u8) = null,
        signature: ?Slice(u32, [*]const u8) = null,
    };
    pub fn getHeaderLen(args: Args) u32 {
        const len =
            header_fixed_part_len
            + stringEncodeLen(args.path.len, 4)
            + stringEncodeLen(args.interface.len, 4)
            + stringEncodeLen(args.member.len, 4)
        ;
        return @intCast(u32, std.mem.alignForward(len, 8));
    }
    pub fn serialize(buf: [*]u8, args: Args) void {
        buf[0] = endian_header_value;
        buf[1] = @enumToInt(MessageType.method_call);
        buf[2] = 0; // flasg
        buf[3] = 1; // protocol version
        const body_length = 0;
        writeIntNative(u32, buf + 4, body_length);
        writeIntNative(u32, buf + 8, args.serial);

        var offset: usize = 12;
        offset += serializeString(buf + offset, args.path, 4);
        std.debug.assert(offset == getHeaderLen(args));
    }
};

pub const signal_msg = struct {
    pub const Args = struct {
        serial: u32,
        path: Slice(u32, [*]const u8),
        interface: Slice(u32, [*]const u8),
        member: Slice(u32, [*]const u8),
    };
    pub fn getHeaderLen(args: Args) u32 {
        const len =
            header_fixed_part_len
            + stringEncodeLen(args.path.len, 4)
            + stringEncodeLen(args.interface.len, 4)
            + stringEncodeLen(args.member.len, 4)
        ;
        return @intCast(u32, std.mem.alignForward(len, 8));
    }
    pub fn serialize(buf: [*]u8, args: Args) void {
        buf[0] = endian_header_value;
        buf[1] = @enumToInt(MessageType.signal);
        buf[2] = 0; // flasg
        buf[3] = 1; // protocol version
        const body_length = 0;
        writeIntNative(u32, buf + 4, body_length);
        writeIntNative(u32, buf + 8, args.serial);

        var offset: usize = 12;
        offset += serializeString(buf + offset, args.path, 4);
        offset += serializeString(buf + offset, args.interface, 4);
        offset += serializeString(buf + offset, args.member, 4);
        std.debug.assert(std.mem.alignForward(offset, 8) == getHeaderLen(args));
    }
};
