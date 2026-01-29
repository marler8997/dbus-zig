pub const Header = extern struct {
    /// Size of the current entry. Includes the header and data but not padding.
    size: usize, // data byte count, including header
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

pub fn RecvBuffer(comptime T: type) type {
    return struct {
        recv_len: usize = 0,
        entry: Entry(T) = undefined,
        const Self = @This();
        pub fn ref(self: *Self) RecvBufferRef {
            return .{
                .header = @ptrCast(&self.entry),
                .len = @sizeOf(@TypeOf(self.entry)),
                .recv_len_ref = &self.recv_len,
            };
        }
        pub fn dataLen(self: *const Self) usize {
            if (self.recv_len == 0) return 0;
            std.debug.assert(self.recv_len >= @sizeOf(Header));
            const recv_data_len = self.recv_len - @sizeOf(Header);
            return @min(@sizeOf(T), recv_data_len);
        }
    };
}

pub const RecvBufferRef = struct {
    len: usize,
    header: *Header,
    recv_len_ref: *usize,

    pub const empty: RecvBufferRef = .{ .len = 0, .header = undefined, .recv_len_ref = undefined };

    pub fn reset(ref: *RecvBufferRef) void {
        if (ref.len == 0) return;
        if (ref.recv_len_ref.* == 0) return;
        // if (ref.entry.result_len == 0) return;
        @panic("todo");
    }
    pub fn received(ref: *RecvBufferRef, len: usize) void {
        if (ref.len == 0) return;
        std.debug.assert(ref.recv_len_ref.* == 0);
        ref.recv_len_ref.* = len;
    }
};

const std = @import("std");
