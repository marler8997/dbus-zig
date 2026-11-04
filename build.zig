const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardOptimizeOption(.{});

    const dbus_module = b.addModule("dbus", .{
        .root_source_file = b.path("src/dbus.zig"),
    });

    const test_step = b.step("test", "");

    {
        const unit_test = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/dbus.zig"),
                .target = target,
                .optimize = mode,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(unit_test).step);
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
        test_step.dependOn(&exe.step);
        const install = b.addInstallArtifact(exe, .{});
        b.getInstallStep().dependOn(&install.step);
        b.step("build-" ++ example_name, "Build the " ++ example_name ++ " example").dependOn(&install.step);
        examples.dependOn(&install.step);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(&install.step);
        run_cmd.addPassthruArgs();

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
        const install = b.addInstallArtifact(exe, .{});

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(&install.step);
        run_cmd.addPassthruArgs();

        const run_step = b.step("daemon", "Run the app");
        run_step.dependOn(&run_cmd.step);
    }

    const dbusc = blk: {
        const exe = b.addExecutable(.{
            .name = "dbusc",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/dbusc.zig"),
                .target = target,
                .optimize = mode,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "dbus", .module = dbus_module },
                },
            }),
        });
        const install = b.addInstallArtifact(exe, .{});
        b.step("install-dbusc", "").dependOn(&install.step);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(&install.step);
        run_cmd.addPassthruArgs();

        const run_step = b.step("dbusc", "Run the cli tool");
        run_step.dependOn(&run_cmd.step);
        break :blk exe;
    };

    {
        const run = b.addRunArtifact(dbusc);
        run.addArg("call");
        run.addArg("org.freedesktop.DBus");
        run.addArg("/org/freedesktop/DBus");
        run.addArg("org.freedesktop.DBus.ListNames");
        run.addArg("");
        b.step("test-list-names", "").dependOn(&run.step);
        test_step.dependOn(&run.step);
    }
    {
        const run = b.addRunArtifact(dbusc);
        run.addArg("call");
        run.addArg("org.freedesktop.DBus");
        run.addArg("/org/freedesktop/DBus");
        run.addArg("org.freedesktop.DBus.Debug.Stats.GetStats");
        run.addArg("");
        b.step("test-get-stats", "").dependOn(&run.step);
        test_step.dependOn(&run.step);
    }

    {
        const exe = b.addExecutable(.{
            .name = "dbustest",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/dbustest.zig"),
                .target = target,
                .optimize = mode,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "dbus", .module = dbus_module },
                },
            }),
        });
        const install = b.addInstallArtifact(exe, .{});
        b.step("install-dbustest", "").dependOn(&install.step);

        const run = b.addRunArtifact(exe);
        test_step.dependOn(&run.step);
        b.step("dbustest", "").dependOn(&run.step);
    }

    {
        const exe = b.addExecutable(.{
            .name = "fuzz",
            .root_module = b.createModule(.{
                .root_source_file = b.path("test/fuzz.zig"),
                .target = target,
                .optimize = mode,
                .single_threaded = true,
                .imports = &.{
                    .{ .name = "dbus", .module = dbus_module },
                },
            }),
        });
        const install = b.addInstallArtifact(exe, .{});
        b.step("install-fuzz", "").dependOn(&install.step);

        {
            const run_test = b.addRunArtifact(exe);
            // the fuzzer logs every seed to stderr; let it through instead of having the
            // build runner capture it and report it under "failed command:"
            run_test.stdio = .inherit;
            _ = run_test.addOutputFileArg("seed");
            run_test.addArg("2"); // 2 seconds
            b.step("fuzz-test", "").dependOn(&run_test.step);
            test_step.dependOn(&run_test.step);
        }

        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        b.step("fuzz", "Run the fuzz tester").dependOn(&run.step);
    }
}
