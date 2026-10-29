const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("npf", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests = b.addTest(.{ .root_module = mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    // The official vectors live in their own test binary. They are the slow
    // part by a wide margin, almost all of it X448 in a debug build.
    const vectors_mod = b.createModule(.{
        .root_source_file = b.path("src/vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    vectors_mod.addImport("npf", mod);
    vectors_mod.addAnonymousImport("cacophony", .{
        .root_source_file = b.path("tests/vectors/cacophony.txt"),
    });
    vectors_mod.addAnonymousImport("snow", .{
        .root_source_file = b.path("tests/vectors/snow.txt"),
    });
    vectors_mod.addAnonymousImport("noise-c-fallback", .{
        .root_source_file = b.path("tests/vectors/noise-c-fallback.txt"),
    });
    const vector_tests = b.addTest(.{ .root_module = vectors_mod });
    const run_vector_tests = b.addRunArtifact(vector_tests);

    const vectors_step = b.step("test-vectors", "Run the official test vectors");
    vectors_step.dependOn(&run_vector_tests.step);

    const test_step = b.step("test", "Run everything");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_vector_tests.step);

    // Patterns that must be rejected at comptime. Each fixture is compiled
    // on its own and the build fails unless the compiler fails with the
    // expected diagnostic.
    const rejected = [_]struct { file: []const u8, expect: []const u8 }{
        .{
            .file = "pre_message_form.zig",
            .expect = "a pre-message must be empty",
        },
        .{
            .file = "duplicate_dh.zig",
            .expect = "DH performed more than once per handshake",
        },
        .{
            .file = "duplicate_ephemeral.zig",
            .expect = "e sent twice by the same party",
        },
        .{
            .file = "missing_remote_key.zig",
            .expect = "needs a remote ephemeral key that has not been received",
        },
        .{
            .file = "missing_local_key.zig",
            .expect = "needs a local static key that party does not have",
        },
        .{
            .file = "ephemeral_contribution.zig",
            .expect = "encrypted under a key with no local ephemeral contribution",
        },
        .{
            .file = "psk_without_ephemeral.zig",
            .expect = "psk without a sent e",
        },
    };

    const reject_step = b.step("test-rejects", "Check that invalid patterns fail to compile");
    for (rejected) |case| {
        const run = b.addSystemCommand(&.{
            b.graph.zig_exe,
            "build-obj",
            "-fno-emit-bin",
            "--dep",
            "npf",
        });
        run.addPrefixedFileArg("-Mroot=", b.path(b.pathJoin(&.{ "tests/compile_errors", case.file })));
        run.addPrefixedFileArg("-Mnpf=", b.path("src/root.zig"));
        run.addArg("--cache-dir");
        run.addDirectoryArg(std.Build.LazyPath.cache_root);
        run.expectExitCode(1);
        run.addCheck(.{ .expect_stderr_match = case.expect });
        run.setName(b.fmt("reject {s}", .{case.file}));
        reject_step.dependOn(&run.step);
    }
    test_step.dependOn(reject_step);

    const fast_step = b.step("test-fast", "Run everything except the vectors");
    fast_step.dependOn(&run_unit_tests.step);
    fast_step.dependOn(reject_step);
}
