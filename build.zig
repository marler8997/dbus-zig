const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const dbus_module = b.addModule("dbus", .{
        .root_source_file = .{ .path = "dbus.zig" },
    });

    {
        const exe = b.addExecutable(.{
            .name = "example",
            .root_source_file = .{ .path = "example.zig" },
            .target = target,
            .optimize = mode,
        });

        exe.root_module.addImport("dbus", dbus_module);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
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
            .root_source_file = .{ .path = "daemon.zig" },
            .single_threaded = true,
            .target = target,
            .optimize = mode,
        });

        exe.root_module.addImport("dbus", dbus_module);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step("daemon", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }
}
