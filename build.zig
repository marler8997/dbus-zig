const std = @import("std");

pub const zig_atleast_15 = @import("builtin").zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const dbus_module = b.addModule("dbus", .{
        .root_source_file = b.path("src/dbus.zig"),
    });
    if (!zig_atleast_15) {
        if (b.lazyDependency("iobackport", .{})) |iobackport_dep| {
            dbus_module.addImport("std15", iobackport_dep.module("std15"));
        }
    }

    const examples = b.step("examples", "build/install all the examples");

    inline for (&.{ "hello", "monitor" }) |example_name| {
        const exe = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/" ++ example_name ++ ".zig"),
                .target = target,
                .optimize = mode,
                .imports = &.{
                    .{ .name = "dbus", .module = dbus_module },
                },
            }),
        });
        const install = b.addInstallArtifact(exe, .{});
        b.getInstallStep().dependOn(&install.step);
        b.step("build-" ++ example_name, "Build the " ++ example_name ++ " example").dependOn(&install.step);
        examples.dependOn(&install.step);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(&install.step);
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step(example_name, "Run the " ++ example_name ++ " example");
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
