const std = @import("std");

pub const HexdumpOptions = struct {
    width: usize = 16,
};

pub fn hexdump(out_line: fn(line: []const u8) void, data: []const u8, options: HexdumpOptions) void {
    const max_line = 200;
    
    var offset: usize = 0;
    while (true) {
        const next = offset + options.width;
        if (next > data.len) break;

        var buf: [max_line]u8 = undefined;
        const len = formatLine(&buf, data[offset..next], options);
        out_line(buf[0 .. len]);
        offset = next;
    }
    if (offset < data.len) {
        var buf: [max_line]u8 = undefined;
        const len = formatLine(&buf, data[offset..], options);
        out_line(buf[0 .. len]);
    }
}

fn formatLine(out_buf: []u8, line: []const u8, options: HexdumpOptions) usize {
    std.debug.assert(line.len <= options.width);
    _ = (std.fmt.bufPrint(out_buf, "{}", .{std.fmt.fmtSliceHexLower(line)}) catch |err| switch (err) {
        error.NoSpaceLeft => unreachable,
    }).len;
    const hex_end = 2 * options.width;
    std.mem.set(u8, out_buf[2*(line.len) .. hex_end], ' ');

    out_buf[hex_end + 0] = ' ';
    out_buf[hex_end + 1] = '|';
    for (line) |c, i| {
        out_buf[hex_end + 2 + i] = if (std.ascii.isPrint(c)) c else ' ';
    }
    out_buf[hex_end + 2 + line.len] = '|';
    return hex_end + 2 + line.len + 1;
}
