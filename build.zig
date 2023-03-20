const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dbus_module = b.addModule("dbus", .{
        .source_file = .{ .path = "dbus.zig" },
    });

    {
        const exe = b.addExecutable(.{
            .name = "example",
            .root_source_file = .{.path = "example.zig"},
            .target = target,
            .optimize = optimize,
        });
        exe.addModule("dbus", dbus_module);
        exe.install();

        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("example", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }
    {
        const exe = b.addExecutable(.{
            .name = "daemon",
            .root_source_file = .{.path = "daemon.zig"},
            .target = target,
            .optimize = optimize,
        });
        exe.single_threaded = true;
        exe.addModule("dbus", dbus_module);
        exe.install();

        const run_cmd = exe.run();
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("daemon", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }
}
