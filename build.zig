const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const dbus_module = b.addModule("dbus", .{
        .root_source_file = b.path("src/dbus.zig"),
    });

    {
        const exe = b.addExecutable(.{
            .name = "example",
            .root_module = b.createModule(.{
                .root_source_file = b.path("example.zig"),
                .target = target,
                .optimize = mode,
                .imports = &.{
                    .{ .name = "dbus", .module = dbus_module },
                },
            }),
        });
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
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/daemon.zig"),
                .target = target,
                .optimize = mode,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "dbus", .module = dbus_module },
                },
            }),
        });
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
