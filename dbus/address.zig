const std = @import("std");
const testing = std.testing;

const Transport = enum {
    unix,
};

const transport_name_map = std.ComptimeStringMap(Transport, .{
    .{ "unix", .unix },
});

pub const Address = union(Transport) {
    unix: struct {
        unescaped_path: []const u8,
    },

    pub const FromStringError = error {
        UnknownTransport,
        UnknownUnixOption,
        MultipleUnixPaths,
        UnixMissingPath,
    }
    || AddrParser.InitError
    || AddrParser.KeysIterator.NextError
    || ResolveEscapesError
    ;
    pub fn fromString(str: []const u8) FromStringError!Address {
        var parser = try AddrParser.init(str);
        const transport_str = parser.transport();
        const transport = transport_name_map.get(transport_str) orelse
            return error.UnknownTransport;
        var it = parser.keysIterator();
        switch (transport) {
            .unix => {
                var path: ?[]const u8 = null;
                while (try it.next()) |kv| {
                    if (std.mem.eql(u8, kv.key, "path")) {
                        if (path) |_| return error.MultipleUnixPaths;
                        //const len_without_null = try resolveEscapes(resolved.ptr, kv.unescaped_value);
                        //std.debug.assert(len_without_null <= kv.unescaped_value.len);
                        //const new_len = len_without_null + 1;
                        //resolved[len_without_null] = 0;
                        //_ = allocator.shrink(resolved, new_len);
                        //path = std.meta.assumeSentinel(resolved.ptr, 0);
                        //std.debug.assert(std.mem.len(path) == new_len);
                        path = kv.unescaped_value;
                    } else {
                        return error.UnknownUnixOption;
                    }
                }
                return Address{
                    .unix = .{
                        .unescaped_path = path orelse return error.UnixMissingPath,
                    },
                };
            },
        }
    }
};

pub const AllocatedAddress = struct {
    addr: Address,
    pub fn deinit(self: AllocatedAddress, allocator: *std.mem.Allocator) void {
        switch (self) {
            .unix => |unix_addr| {
                allocator.free(u8, unix_addr.path[0 .. std.mem.len(unix_addr.path) + 1]);
            },
        }
    }
};

pub fn hasEscapes(unescaped_value: []const u8) bool {
    for (unescaped_value) |c| {
        if (c == '%') return true;
    }
    return false;
}

const ResolveEscapesError = error {
    DestTooSmall,
    BadEscapeSequence,
};
// ensuring that dest can hold at least unescaped_value.len is good enough
pub fn resolveEscapes(dest: []u8, unescaped_value: []const u8) ResolveEscapesError!usize {
    var dest_index: usize = 0;
    var value_index: usize = 0;
    while (value_index < unescaped_value.len) : (value_index += 1) {
        if (dest_index >= dest.len) return error.DestTooSmall;
        var value = unescaped_value[value_index];
        if (value == '%') {
            if (value_index + 2 >= unescaped_value.len)
                return error.BadEscapeSequence;
            value = hexDigitVal(unescaped_value[value_index+2]) orelse
                return error.BadEscapeSequence;
            value |= (hexDigitVal(unescaped_value[value_index+1]) orelse
                return error.BadEscapeSequence) << 4;
            value_index += 2;
        }
        dest[dest_index] = value;
        dest_index += 1;
    }
    return dest_index;
}

pub const AddrParser = struct {
    addr: []const u8,
    colon_index: usize,

    pub const InitError = error { MissingColonToTerminateTransport };
    pub fn init(addr: []const u8) InitError!AddrParser {
        const colon_index = std.mem.indexOfScalar(u8, addr, ':') orelse
            return InitError.MissingColonToTerminateTransport;
        return AddrParser{ .addr = addr, .colon_index = colon_index };
    }

    pub fn transport(self: AddrParser) []const u8 {
        return self.addr[0 .. self.colon_index];
    }

    pub const KeysIterator = struct {
        str: []const u8,
        index: usize,

        pub const KeyValue = struct {
            key: []const u8,
            unescaped_value: []const u8,
        };

        pub const NextError = error {
            KeyValueMissignAssignChar,
        };
        
        pub fn next(self: *KeysIterator) !?KeyValue {
            if (self.index >= self.str.len) return null;
            const assign_index = std.mem.indexOfScalarPos(u8, self.str, self.index, '=') orelse
                return NextError.KeyValueMissignAssignChar;
            const index = self.index;
            const end = blk: {
                if (std.mem.indexOfScalarPos(u8, self.str, assign_index + 1, ',')) |comma_index| {
                    self.index = comma_index + 1;
                    break :blk comma_index;
                }
                self.index = self.str.len;
                break :blk self.str.len;
            };
            return KeyValue{
                .key = self.str[index..assign_index],
                .unescaped_value = self.str[assign_index+1..end],
            };
        }
    };
    
    pub fn keysIterator(self: AddrParser) KeysIterator {
        return .{ .str = self.addr[self.colon_index + 1..], .index = 0 };
    }
};

test {
    {
        var parser = try AddrParser.init("unix:");
        try testing.expectEqualSlices(u8, "unix", parser.transport());
        var it = parser.keysIterator();
        try testing.expect(null == try it.next());
    }
    {
        var parser = try AddrParser.init("unix:path=/tmp/dbus-test,foo=bar");
        try testing.expectEqualSlices(u8, "unix", parser.transport());
        var it = parser.keysIterator();
        {
            const kv = (try it.next()).?;
            try testing.expectEqualSlices(u8, "path", kv.key);
            try testing.expectEqualSlices(u8, "/tmp/dbus-test", kv.unescaped_value);
        }
        {
            const kv = (try it.next()).?;
            try testing.expectEqualSlices(u8, "foo", kv.key);
            try testing.expectEqualSlices(u8, "bar", kv.unescaped_value);
        }
        try testing.expect(null == try it.next());
    }
    {
        var parser = try AddrParser.init("unix:path=/a-fun-path/%68%65%6c%6C%6f-weird-chars%3a%00%01%2c");
        try testing.expectEqualSlices(u8, "unix", parser.transport());
        var it = parser.keysIterator();
        {
            const kv = (try it.next()).?;
            try testing.expectEqualSlices(u8, "path", kv.key);
            try testing.expectEqualSlices(u8, "/a-fun-path/%68%65%6c%6C%6f-weird-chars%3a%00%01%2c", kv.unescaped_value);
            var buffer: [100]u8 = undefined;
            const value = buffer[0 .. try resolveEscapes(&buffer, kv.unescaped_value)];
            try testing.expectEqualSlices(u8, "/a-fun-path/hello-weird-chars:\x00\x01,", value);
        }
        try testing.expect(null == try it.next());
    }
}

// TODO: replace with something in std
fn hexDigitVal(hex_digit: u8) ?u8 {
    return switch (hex_digit) {
        '0'...'9' => hex_digit - '0',
        'A'...'F' => hex_digit + 10 - 'A',
        'a'...'f' => hex_digit + 10 - 'a',
        else => null,
    };
}

// TODO: this is currently unused
fn isOptionallyEscapedByte(b: u8) bool {
    return switch (b) {
        '*',
        '-'...'9', // includes '.' and '/'
        'A'...'Z',
        '\\',
        '_',
        'a'...'z',
        => true,
        else => false,
    };
}

test "isOptionallyEscapedByte" {
    try testing.expect(!isOptionallyEscapedByte(0));
    try testing.expect(!isOptionallyEscapedByte('*' - 1));
    try testing.expect( isOptionallyEscapedByte('*'    ));
    try testing.expect(!isOptionallyEscapedByte('*' + 1));
    try testing.expect(!isOptionallyEscapedByte('-' - 1));
    try testing.expect( isOptionallyEscapedByte('-'    ));
    try testing.expect( isOptionallyEscapedByte('.'    ));
    try testing.expect( isOptionallyEscapedByte('/'    ));
    try testing.expect( isOptionallyEscapedByte('0'    ));
    try testing.expect( isOptionallyEscapedByte('9'    ));
    try testing.expect(!isOptionallyEscapedByte('9' + 1));
    try testing.expect(!isOptionallyEscapedByte('A' - 1));
    try testing.expect( isOptionallyEscapedByte('A'    ));
    try testing.expect( isOptionallyEscapedByte('Z'    ));
    try testing.expect(!isOptionallyEscapedByte('Z' + 1));
    try testing.expect(!isOptionallyEscapedByte('_' - 1));
    try testing.expect( isOptionallyEscapedByte('_'    ));
    try testing.expect(!isOptionallyEscapedByte('_' + 1));
    try testing.expect(!isOptionallyEscapedByte('a' - 1));
    try testing.expect( isOptionallyEscapedByte('a'    ));
    try testing.expect( isOptionallyEscapedByte('a'    ));
    try testing.expect(!isOptionallyEscapedByte('z' + 1));
}
