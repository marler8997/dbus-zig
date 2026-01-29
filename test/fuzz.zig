pub const std_options: std.Options = .{
    .log_level = .info,
};

fn usage() noreturn {
    std.debug.print("Usage: fuzz SEED_FILE TIMEOUT_SECONDS\n", .{});
    std.process.exit(1);
}

pub fn main() !void {
    var args = std.process.args();
    _ = args.next(); // skip program name
    const seed_filename = args.next() orelse usage();
    const time_limit_ns: u64 = blk: {
        const str = args.next() orelse usage();
        break :blk @as(u64, std.time.ns_per_s) * (std.fmt.parseInt(u64, str, 10) catch errExit(
            "invalid TIMEOUT_SECONDS integer '{s}'",
            .{str},
        ));
    };
    if (args.next() != null) errExit("error: too many cmdline args", .{});

    const initial_seed: u64 = blk: {
        if (std.fs.path.dirname(seed_filename)) |d| try std.fs.cwd().makePath(d);
        var file = std.fs.cwd().openFile(seed_filename, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                std.log.info("no seed file '{s}' generating a new one", .{seed_filename});
                try saveSeedFile(seed_filename, 0);
                break :blk 0;
            },
            else => |e| errExit(
                "open seed file '{s}' failed with {s}",
                .{ seed_filename, @errorName(e) },
            ),
        };
        defer file.close();
        const seed = try parseSeedFile(seed_filename, file);
        std.log.info("restored seed {} from file", .{seed});
        break :blk seed;
    };

    const start_ns = std.time.nanoTimestamp();
    var next_seed = initial_seed;
    while (true) {
        std.log.info("testing seed {}", .{next_seed});
        try testSeed(next_seed);
        next_seed += 1;
        try saveSeedFile(seed_filename, next_seed);
        const elapsed: u64 = @intCast(std.time.nanoTimestamp() - start_ns);
        if (elapsed >= time_limit_ns) {
            std.log.info("time limit reached after {} seeds", .{next_seed - initial_seed});
            return;
        }
    }
}

fn readSeedFile(seed_filename: []const u8) !u64 {
    var file = std.fs.cwd().openFile(seed_filename, .{}) catch |e| errExit(
        "open seed file '{s}' failed with {s}",
        .{ seed_filename, @errorName(e) },
    );
    defer file.close();
    return parseSeedFile(seed_filename, file);
}
fn parseSeedFile(seed_filename: []const u8, file: std.fs.File) !u64 {
    var reader = file.reader(&.{});
    var read_buf: [100]u8 = undefined;
    const content_len = try reader.interface.readSliceShort(&read_buf);
    if (content_len == read_buf.len) errExit(
        "seed file '{s}' is too long",
        .{seed_filename},
    );
    const content = std.mem.trimRight(u8, read_buf[0..content_len], "\r\n");
    return std.fmt.parseInt(u64, content, 10) catch errExit(
        "seed file content '{s}' is not an integer",
        .{content},
    );
}

fn saveSeedFile(seed_filename: []const u8, seed: u64) !void {
    // std.log.info("writing seed {}", .{seed});
    {
        var file = try std.fs.cwd().createFile(seed_filename, .{});
        defer file.close();
        var seed_buf: [100]u8 = undefined;
        const seed_str = std.fmt.bufPrint(&seed_buf, "{}\n", .{seed}) catch unreachable;
        try file.writeAll(seed_str);
    }
    std.debug.assert(seed == try readSeedFile(seed_filename));
}

fn testSeed(seed: u64) !void {
    // Pre-fill a buffer from PRNG. When Zig's fuzz tester is ready,
    // this buffer comes from the fuzzer instead.
    var prng = std.Random.DefaultPrng.init(seed);
    var input_buf: [5000]u8 = undefined;
    prng.fill(&input_buf);
    try fuzzRoundTrip(&input_buf);
}

fn fuzzRoundTrip(input: []const u8) !void {
    var smith = Smith.init(input);

    var fds: [2]c_int = .{ -1, -1 };
    switch (std.posix.errno(std.os.linux.socketpair(
        std.os.linux.AF.UNIX,
        std.os.linux.SOCK.STREAM,
        0,
        &fds,
    ))) {
        .SUCCESS => {},
        else => |err| {
            std.debug.print("socketpair failed: {}\n", .{err});
            return error.SocketPairFailed;
        },
    }
    defer {
        std.posix.close(fds[0]);
        std.posix.close(fds[1]);
    }
    const memfd = try std.posix.memfd_createZ("fuzz-test", 0);
    defer std.posix.close(memfd);

    const write_buf_size = smith.nextMinMax(u16, 1, 4096);
    const read_buf_size = smith.nextMinMax(u16, 1, 4096);

    const canary = [_]u8{0xde} ** 16;
    var write_buf_with_canary: [4096 + canary.len]u8 = undefined;
    const write_buf = write_buf_with_canary[0..write_buf_size];
    @memcpy(write_buf_with_canary[write_buf.len..][0..canary.len], &canary);

    var read_buf_with_canary: [4096 + canary.len]u8 = undefined;
    const read_buf = read_buf_with_canary[0..read_buf_size];
    @memcpy(read_buf_with_canary[read_buf.len..][0..canary.len], &canary);

    var msg_writer = dbus.MsgWriter.init(.{ .handle = fds[0] }, write_buf);
    var msg_reader = dbus.MsgReader.init(.{ .handle = fds[1] }, read_buf);
    defer msg_reader.deinit();

    const writer = &msg_writer.interface;
    const reader = msg_reader.interface();

    // We don't use the fuzz input for test data because the actual data
    // doesn't affect the codepath.
    var test_data_rng: std.Random.DefaultPrng = .init(smith.next(u64));
    var test_data: TestData = .{};

    const max_io = 10_000;
    var expect_fd = false;

    while (!smith.isEmpty() or test_data.unverified() > 0) {
        std.debug.assert(msg_writer.control == null);

        const in_socket: u16 = test_data.unverified() - @as(u16, @intCast(writer.buffered().len));
        const Operation = enum { flush, write, read };
        const op: Operation = switch (smith.next(Operation)) {
            .flush => if (in_socket > 0 and writer.buffered().len == 0) .read else .flush,
            .write => if (!smith.isEmpty() and test_data.available() > 0) .write else if (in_socket > 0) .read else .flush,
            .read => if (in_socket > 0) .read else .flush,
        };
        switch (op) {
            .flush => {
                const send_fd = !expect_fd and writer.buffered().len > 0 and smith.next(bool);
                if (send_fd) {
                    var entry: dbus.cmsg.Entry(std.posix.fd_t) = .{
                        .level = std.os.linux.SOL.SOCKET,
                        .type = dbus.SCM.RIGHTS,
                        .data = memfd,
                    };
                    msg_writer.control = entry.singleEntryArray();
                    expect_fd = true;
                }
                try writer.flush();
                std.debug.assert(msg_writer.control == null);
            },
            .write => {
                std.debug.assert(test_data.available() > 0);
                const write_len = smith.nextMinMax(u16, 1, @min(max_io, test_data.available()));
                const WriteKind = enum { data, splat };
                switch (smith.next(WriteKind)) {
                    .data => {
                        var buf: [max_io]u8 = undefined;
                        const data = buf[0..write_len];
                        test_data_rng.fill(data);
                        try writer.writeAll(data);
                        test_data.write(data);
                    },
                    .splat => {
                        const byte = smith.next(u8);
                        try writer.splatByteAll(byte, write_len);
                        var buf: [max_io]u8 = undefined;
                        @memset(buf[0..write_len], byte);
                        test_data.write(buf[0..write_len]);
                    },
                }
            },
            .read => {
                std.debug.assert(in_socket > 0);
                const read_len = smith.nextMinMax(u16, 1, @min(max_io, in_socket));
                var buf: [max_io]u8 = undefined;
                const data = buf[0..read_len];

                const ReadKind = enum { read, discard, stream };
                const read_kind: ReadKind = switch (smith.next(ReadKind)) {
                    .read => .read,
                    // cannot use discard while expect_fd is true
                    .discard => if (expect_fd) switch (smith.next(enum { read, stream })) {
                        .read => .read,
                        .stream => .stream,
                    } else .discard,
                    .stream => .stream,
                };
                switch (read_kind) {
                    .read => {
                        try reader.readSliceAll(data);
                    },
                    .discard => try reader.discardAll(read_len),
                    .stream => {
                        var discard_writer = std.Io.Writer.Discarding.init(&buf);
                        try reader.streamExact(&discard_writer.writer, read_len);
                        std.debug.assert(discard_writer.fullCount() == read_len);
                    },
                }
                switch (read_kind) {
                    .discard => test_data.discard(read_len),
                    .read, .stream => test_data.verify(data),
                }
                if (expect_fd and msg_reader.unix_fds.array[0] != -1) {
                    expect_fd = false;
                    // Test both taking/closing the fd ourselves, and
                    // allowing the underlying reader to close it on deinit.
                    if (smith.next(bool)) {
                        const received_fd = msg_reader.unix_fds.take(0) orelse
                            std.debug.panic("expected to receive fd", .{});
                        std.posix.close(received_fd);
                    }
                }
            },
        }

        std.debug.assert(std.mem.eql(
            u8,
            write_buf_with_canary[write_buf.len..][0..canary.len],
            &canary,
        ));
        std.debug.assert(std.mem.eql(
            u8,
            read_buf_with_canary[read_buf.len..][0..canary.len],
            &canary,
        ));
    }
    std.debug.assert(!expect_fd);
}

const TestData = struct {
    buf: [1 << 16]u8 = undefined,
    head: u16 = 0,
    tail: u16 = 0,

    pub fn available(td: *const TestData) u16 {
        // Reserve one slot to distinguish full from empty.
        return @as(u16, 65535) - (td.head -% td.tail);
    }

    /// Total bytes written but not yet verified/discarded.
    pub fn unverified(td: *const TestData) u16 {
        return td.head -% td.tail;
    }

    pub fn write(td: *TestData, data: []const u8) void {
        std.debug.assert(data.len <= td.available());
        const first = @min(data.len, @as(usize, 65536) - td.head);
        @memcpy(td.buf[td.head..][0..first], data[0..first]);
        if (first < data.len) {
            @memcpy(td.buf[0 .. data.len - first], data[first..]);
        }
        td.head +%= @intCast(data.len);
    }

    pub fn verify(td: *TestData, data: []const u8) void {
        std.debug.assert(data.len <= td.unverified());
        const first = @min(data.len, @as(usize, 65536) - td.tail);
        if (!std.mem.eql(u8, td.buf[td.tail..][0..first], data[0..first])) {
            std.debug.panic("verify mismatch in first segment at tail={}", .{td.tail});
        }
        if (first < data.len) {
            if (!std.mem.eql(u8, td.buf[0 .. data.len - first], data[first..])) {
                std.debug.panic("verify mismatch in wrapped segment", .{});
            }
        }
        td.tail +%= @intCast(data.len);
    }

    pub fn discard(td: *TestData, len: usize) void {
        std.debug.assert(len <= td.unverified());
        td.tail +%= @intCast(len);
    }
};

fn errExit(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const std = @import("std");
const dbus = @import("dbus");
const Smith = @import("Smith.zig");
