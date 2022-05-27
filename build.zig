const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    {
        const exe = b.addExecutable("example", "example.zig");
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.addPackagePath("dbus", "dbus.zig");
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
        const exe = b.addExecutable("daemon", "daemon.zig");
        exe.single_threaded = true;
        exe.setTarget(target);
        exe.setBuildMode(mode);
        exe.addPackagePath("dbus", "dbus.zig");
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
