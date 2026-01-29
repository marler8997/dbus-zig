pub const Header = extern struct {
    /// Size of the current entry. Includes the header and data but not padding.
    size: usize,
    /// Originating protocol (i.e. std.os.linux.SOL.SOCKET)
    level: c_int,
    /// Protocol-specific type (i.e. SCM.RIGHTS)
    type: c_int,
};

/// Pointer to array of entries.
pub const Array = struct {
    size: usize,
    ptr: *const Header,
};

pub fn Entry(comptime T: type) type {
    const unpadded_size = @sizeOf(Header) + @sizeOf(T);
    const padded_size = std.mem.alignForward(usize, unpadded_size, @alignOf(Header));

    return extern struct {
        size: usize = unpadded_size,
        level: c_int,
        type: c_int,
        data: T,
        padding: [padded_size - unpadded_size]u8 = undefined,

        const Self = @This();
        comptime {
            std.debug.assert(@offsetOf(Header, "size") == @offsetOf(Self, "size"));
            std.debug.assert(@offsetOf(Header, "level") == @offsetOf(Self, "level"));
            std.debug.assert(@offsetOf(Header, "type") == @offsetOf(Self, "type"));
            std.debug.assert(@sizeOf(Self) == padded_size);
        }
        pub fn singleEntryArray(self: *const Self) Array {
            return .{ .ptr = @ptrCast(self), .size = @sizeOf(Self) };
        }
    };
}

const std = @import("std");
