const std = @import("std");
const npf = @import("npf");

const crypto = npf.crypto;
const pattern = npf.pattern;
const handshake = npf.handshake;
const pipe = npf.pipe;

const Pattern = pattern.Pattern;
const Suite = handshake.Suite;

const Message = struct {
    payload: []const u8 = "",
    ciphertext: []const u8 = "",
};

const Vector = struct {
    protocol_name: []const u8,
    /// Absent from snow.txt, present in cacophony.txt.
    handshake_hash: ?[]const u8 = null,
    init_prologue: []const u8 = "",
    init_psks: []const []const u8 = &.{},
    init_static: ?[]const u8 = null,
    init_ephemeral: ?[]const u8 = null,
    init_remote_static: ?[]const u8 = null,
    resp_prologue: []const u8 = "",
    resp_psks: []const []const u8 = &.{},
    resp_static: ?[]const u8 = null,
    resp_ephemeral: ?[]const u8 = null,
    resp_remote_static: ?[]const u8 = null,
    messages: []const Message,
};

const File = struct { vectors: []const Vector };

fn hexKey(comptime len: usize, s: []const u8) ![len]u8 {
    var out: [len]u8 = undefined;
    const got = try std.fmt.hexToBytes(&out, s);
    if (got.len != out.len) return error.BadKeyLength;
    return out;
}

fn hexInto(buf: []u8, s: []const u8) ![]u8 {
    return std.fmt.hexToBytes(buf, s);
}

fn runVector(comptime S: type, comptime p: Pattern, v: Vector) !void {
    const Hs = handshake.HandshakeState(S);

    var prologue_buf: [256]u8 = undefined;
    const prologue = try hexInto(&prologue_buf, v.init_prologue);

    const Dh = Hs.Dh;
    var i_cfg: Hs.Config = .{ .prologue = prologue };
    var r_cfg: Hs.Config = .{ .prologue = prologue };
    if (v.init_static) |h| i_cfg.s = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, h));
    if (v.init_ephemeral) |h| i_cfg.e = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, h));
    if (v.init_remote_static) |h| i_cfg.rs = try hexKey(Dh.dhlen, h);
    if (v.resp_static) |h| r_cfg.s = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, h));
    if (v.resp_ephemeral) |h| r_cfg.e = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, h));
    if (v.resp_remote_static) |h| r_cfg.rs = try hexKey(Dh.dhlen, h);
    // Section 9.2 allows several psk tokens. The vector lists one PSK per
    // token, applied in order.
    var i_psks: [Hs.max_psks][Hs.psk_len]u8 = undefined;
    var r_psks: [Hs.max_psks][Hs.psk_len]u8 = undefined;
    for (v.init_psks, 0..) |h, i| i_psks[i] = try hexKey(Hs.psk_len, h);
    for (v.resp_psks, 0..) |h, i| r_psks[i] = try hexKey(Hs.psk_len, h);
    i_cfg.psks = i_psks[0..v.init_psks.len];
    r_cfg.psks = r_psks[0..v.resp_psks.len];

    var initiator = try Hs.init(p, .initiator, i_cfg);
    var responder = try Hs.init(p, .responder, r_cfg);

    var payload_buf: [4096]u8 = undefined;
    var expected_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var plain_buf: [4096]u8 = undefined;

    for (v.messages[0..p.messages.len], 0..) |m, i| {
        const payload = try hexInto(&payload_buf, m.payload);
        const expected = try hexInto(&expected_buf, m.ciphertext);
        const writer, const reader = if (p.senderIsInitiator(i))
            .{ &initiator, &responder }
        else
            .{ &responder, &initiator };

        const n = try writer.writeMessage(payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        const m_len = try reader.readMessage(out_buf[0..n], &plain_buf);
        try std.testing.expectEqualSlices(u8, payload, plain_buf[0..m_len]);
    }

    try std.testing.expectEqual(initiator.handshakeHash(), responder.handshakeHash());
    if (v.handshake_hash) |hex| {
        var hash_buf: [64]u8 = undefined;
        const expected_hash = try hexInto(&hash_buf, hex);
        try std.testing.expectEqualSlices(u8, expected_hash, &initiator.handshakeHash());
    }

    var i_keys = try initiator.split();
    var r_keys = try responder.split();
    const one_way = p.messages.len == 1;

    for (v.messages[p.messages.len..], p.messages.len..) |m, i| {
        const payload = try hexInto(&payload_buf, m.payload);
        const expected = try hexInto(&expected_buf, m.ciphertext);
        const from_initiator = one_way or p.senderIsInitiator(i);
        const send = if (from_initiator) &i_keys.send else &r_keys.send;
        const recv = if (from_initiator) &r_keys.recv else &i_keys.recv;

        const n = try send.encryptWithAd("", payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        const m_len = try recv.decryptWithAd("", out_buf[0..n], &plain_buf);
        try std.testing.expectEqualSlices(u8, payload, plain_buf[0..m_len]);
    }
}

const pattern_names = [_][]const u8{
    "N",      "K",      "X",
    "NN",     "KN",     "NK",
    "KK",     "NX",     "KX",
    "XN",     "IN",     "XK",
    "IK",     "XX",     "IX",
    "NK1",    "NX1",    "X1N",
    "X1K",    "XK1",    "X1K1",
    "X1X",    "XX1",    "X1X1",
    "K1N",    "K1K",    "KK1",
    "K1K1",   "K1X",    "KX1",
    "K1X1",   "I1N",    "I1K",
    "IK1",    "I1K1",   "I1X",
    "IX1",    "I1X1",   "Npsk0",
    "Kpsk0",  "Xpsk1",  "NNpsk0",
    "NNpsk2", "NKpsk0", "NKpsk2",
    "NXpsk2", "XNpsk3", "XKpsk3",
    "XXpsk3", "KNpsk0", "KNpsk2",
    "KKpsk0", "KKpsk2", "KXpsk2",
    "INpsk1", "INpsk2", "IKpsk1",
    "IKpsk2", "IXpsk2",
};

const suites = .{
    .{ "25519_ChaChaPoly_SHA256", Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Sha256) },
    .{ "25519_ChaChaPoly_SHA512", Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Sha512) },
    .{ "25519_ChaChaPoly_BLAKE2s", Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Blake2s) },
    .{ "25519_ChaChaPoly_BLAKE2b", Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Blake2b) },
    .{ "25519_AESGCM_SHA256", Suite(crypto.X25519, crypto.AesGcm, crypto.Sha256) },
    .{ "25519_AESGCM_SHA512", Suite(crypto.X25519, crypto.AesGcm, crypto.Sha512) },
    .{ "25519_AESGCM_BLAKE2s", Suite(crypto.X25519, crypto.AesGcm, crypto.Blake2s) },
    .{ "25519_AESGCM_BLAKE2b", Suite(crypto.X25519, crypto.AesGcm, crypto.Blake2b) },
    .{ "448_ChaChaPoly_SHA256", Suite(crypto.X448, crypto.ChaChaPoly, crypto.Sha256) },
    .{ "448_ChaChaPoly_SHA512", Suite(crypto.X448, crypto.ChaChaPoly, crypto.Sha512) },
    .{ "448_ChaChaPoly_BLAKE2s", Suite(crypto.X448, crypto.ChaChaPoly, crypto.Blake2s) },
    .{ "448_ChaChaPoly_BLAKE2b", Suite(crypto.X448, crypto.ChaChaPoly, crypto.Blake2b) },
    .{ "448_AESGCM_SHA256", Suite(crypto.X448, crypto.AesGcm, crypto.Sha256) },
    .{ "448_AESGCM_SHA512", Suite(crypto.X448, crypto.AesGcm, crypto.Sha512) },
    .{ "448_AESGCM_BLAKE2s", Suite(crypto.X448, crypto.AesGcm, crypto.Blake2s) },
    .{ "448_AESGCM_BLAKE2b", Suite(crypto.X448, crypto.AesGcm, crypto.Blake2b) },
};

const FallbackVector = struct {
    name: []const u8,
    pattern: []const u8 = "",
    fallback: bool = false,
    init_prologue: []const u8 = "",
    init_static: ?[]const u8 = null,
    init_ephemeral: ?[]const u8 = null,
    init_remote_static: ?[]const u8 = null,
    resp_prologue: []const u8 = "",
    resp_static: ?[]const u8 = null,
    resp_ephemeral: ?[]const u8 = null,
    handshake_hash: []const u8,
    messages: []const Message,
};

const FallbackFile = struct { vectors: []const FallbackVector };

fn runFallbackVector(comptime S: type, v: FallbackVector) !void {
    const Hs = handshake.HandshakeState(S);
    const fallback = pattern.XXfallback;

    var prologue_buf: [256]u8 = undefined;
    const prologue = try hexInto(&prologue_buf, v.init_prologue);

    const Dh = Hs.Dh;
    const alice_s = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.init_static.?));
    const alice_e = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.init_ephemeral.?));
    const bob_s = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.resp_static.?));
    const bob_e = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.resp_ephemeral.?));
    const stale_rs = try hexKey(Dh.dhlen, v.init_remote_static.?);

    var payload_buf: [4096]u8 = undefined;
    var expected_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var plain_buf: [4096]u8 = undefined;

    var alice_ik = try Hs.init(pattern.IK, .initiator, .{
        .prologue = prologue,
        .s = alice_s,
        .e = alice_e,
        .rs = stale_rs,
    });
    var bob_ik = try Hs.init(pattern.IK, .responder, .{ .prologue = prologue, .s = bob_s, .e = bob_e });

    {
        const payload = try hexInto(&payload_buf, v.messages[0].payload);
        const expected = try hexInto(&expected_buf, v.messages[0].ciphertext);
        const n = try alice_ik.writeMessage(payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        try std.testing.expectError(
            handshake.Error.AuthenticationFailed,
            bob_ik.readMessage(out_buf[0..n], &plain_buf),
        );
    }

    var alice = try Hs.init(fallback, .initiator, .{
        .prologue = prologue,
        .s = alice_s,
        .e = alice_e,
    });
    var bob = try Hs.init(fallback, .responder, .{
        .prologue = prologue,
        .s = bob_s,
        .e = bob_e,
        .re = alice_e.public,
    });

    const rest = v.messages[1..];
    for (rest[0..fallback.messages.len], 0..) |m, i| {
        const payload = try hexInto(&payload_buf, m.payload);
        const expected = try hexInto(&expected_buf, m.ciphertext);
        const writer, const reader = if (fallback.senderIsInitiator(i))
            .{ &alice, &bob }
        else
            .{ &bob, &alice };

        const n = try writer.writeMessage(payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        const got = try reader.readMessage(out_buf[0..n], &plain_buf);
        try std.testing.expectEqualSlices(u8, payload, plain_buf[0..got]);
    }

    var hash_buf: [64]u8 = undefined;
    const expected_hash = try hexInto(&hash_buf, v.handshake_hash);
    try std.testing.expectEqualSlices(u8, expected_hash, &alice.handshakeHash());
    try std.testing.expectEqualSlices(u8, expected_hash, &bob.handshakeHash());

    var a_keys = try alice.split();
    var b_keys = try bob.split();

    for (rest[fallback.messages.len..], fallback.messages.len..) |m, i| {
        const payload = try hexInto(&payload_buf, m.payload);
        const expected = try hexInto(&expected_buf, m.ciphertext);
        const from_initiator = fallback.senderIsInitiator(i);
        const send = if (from_initiator) &a_keys.send else &b_keys.send;
        const recv = if (from_initiator) &b_keys.recv else &a_keys.recv;

        const n = try send.encryptWithAd("", payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        const got = try recv.decryptWithAd("", out_buf[0..n], &plain_buf);
        try std.testing.expectEqualSlices(u8, payload, plain_buf[0..got]);
    }
}

/// The same vectors, driven through the Pipe API instead of by hand, so the
/// compound state machine in pipe.zig is checked against real transcripts
/// rather than only against itself.
fn runPipeFallbackVector(comptime S: type, v: FallbackVector) !void {
    const P = pipe.Pipe(S);
    const Dh = P.Hs.Dh;
    const fallback = pattern.XXfallback;

    var prologue_buf: [256]u8 = undefined;
    const prologue = try hexInto(&prologue_buf, v.init_prologue);

    const alice_s = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.init_static.?));
    const alice_e = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.init_ephemeral.?));
    const bob_s = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.resp_static.?));
    const bob_e = Dh.KeyPair.fromSecret(try hexKey(Dh.dhlen, v.resp_ephemeral.?));
    const stale_rs = try hexKey(Dh.dhlen, v.init_remote_static.?);

    var payload_buf: [4096]u8 = undefined;
    var expected_buf: [4096]u8 = undefined;
    var out_buf: [4096]u8 = undefined;
    var plain_buf: [4096]u8 = undefined;

    var alice = try P.initiator(.{
        .prologue = prologue,
        .s = alice_s,
        .e = alice_e,
        .rs = stale_rs,
    });
    var bob = try P.responder(.{
        .prologue = prologue,
        .s = bob_s,
        .e = bob_e,
    }, .ik);
    try std.testing.expectEqual(P.Kind.ik, alice.currentKind());

    {
        const payload = try hexInto(&payload_buf, v.messages[0].payload);
        const expected = try hexInto(&expected_buf, v.messages[0].ciphertext);
        const n = try alice.writeMessage(payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        try std.testing.expectError(
            pipe.Error.FallbackRequired,
            bob.readMessage(out_buf[0..n], &plain_buf),
        );
    }

    try std.testing.expectEqual(P.Kind.fallback, bob.currentKind());
    try alice.switchToFallback();
    try std.testing.expectEqual(P.Kind.fallback, alice.currentKind());

    const rest = v.messages[1..];
    for (rest[0..fallback.messages.len], 0..) |m, i| {
        const payload = try hexInto(&payload_buf, m.payload);
        const expected = try hexInto(&expected_buf, m.ciphertext);
        const writer, const reader = if (fallback.senderIsInitiator(i))
            .{ &alice, &bob }
        else
            .{ &bob, &alice };

        const n = try writer.writeMessage(payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        const got = try reader.readMessage(out_buf[0..n], &plain_buf);
        try std.testing.expectEqualSlices(u8, payload, plain_buf[0..got]);
    }

    var hash_buf: [64]u8 = undefined;
    const expected_hash = try hexInto(&hash_buf, v.handshake_hash);
    try std.testing.expectEqualSlices(u8, expected_hash, &alice.handshakeHash());
    try std.testing.expectEqualSlices(u8, expected_hash, &bob.handshakeHash());

    var a_keys = try alice.split();
    var b_keys = try bob.split();

    for (rest[fallback.messages.len..], fallback.messages.len..) |m, i| {
        const payload = try hexInto(&payload_buf, m.payload);
        const expected = try hexInto(&expected_buf, m.ciphertext);
        const from_initiator = fallback.senderIsInitiator(i);
        const send = if (from_initiator) &a_keys.send else &b_keys.send;
        const recv = if (from_initiator) &b_keys.recv else &a_keys.recv;

        const n = try send.encryptWithAd("", payload, &out_buf);
        try std.testing.expectEqualSlices(u8, expected, out_buf[0..n]);
        const got = try recv.decryptWithAd("", out_buf[0..n], &plain_buf);
        try std.testing.expectEqualSlices(u8, payload, plain_buf[0..got]);
    }
}

test "noise-c fallback vectors through the Pipe api" {
    const data = @embedFile("noise-c-fallback");
    const parsed = try std.json.parseFromSlice(FallbackFile, std.testing.allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var ran: usize = 0;
    inline for (suites) |suite| {
        const want = "Noise_XXfallback_" ++ suite[0];
        for (parsed.value.vectors) |v| {
            if (!std.mem.eql(u8, v.name, want)) continue;
            runPipeFallbackVector(suite[1], v) catch |err| {
                std.debug.print("pipe fallback vector failed: {s}\n", .{want});
                return err;
            };
            ran += 1;
        }
    }
    try std.testing.expectEqual(suites.len, ran);
}

test "noise-c fallback vectors" {
    const data = @embedFile("noise-c-fallback");
    const parsed = try std.json.parseFromSlice(FallbackFile, std.testing.allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var ran: usize = 0;
    inline for (suites) |suite| {
        const want = "Noise_XXfallback_" ++ suite[0];
        for (parsed.value.vectors) |v| {
            if (!std.mem.eql(u8, v.name, want)) continue;
            try std.testing.expect(v.fallback);
            try std.testing.expectEqualStrings("IK", v.pattern);
            runFallbackVector(suite[1], v) catch |err| {
                std.debug.print("fallback vector failed: {s}\n", .{want});
                return err;
            };
            ran += 1;
        }
    }
    try std.testing.expectEqual(suites.len, ran);
}

/// Patterns that appear in snow.txt but not in cacophony.txt. All of them
/// carry more than one psk modifier, which section 9.2 permits and which no
/// other vector file we have exercises.
const multi_psk_names = [_][]const u8{
    "NNpsk0+psk2",           "NXpsk0+psk1+psk2", "XNpsk1+psk3", "XKpsk0+psk3",
    "KNpsk1+psk2",           "KKpsk0+psk2",      "INpsk1+psk2", "IKpsk0+psk2",
    "IXpsk0+psk2",           "XXpsk0+psk1",      "XXpsk0+psk2", "XXpsk0+psk3",
    "XXpsk0+psk1+psk2+psk3",
};

test "snow vectors, including multi-psk patterns" {
    const data = @embedFile("snow");
    const parsed = try std.json.parseFromSlice(File, std.testing.allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var ran: usize = 0;
    inline for (suites) |suite| {
        if (comptime std.mem.startsWith(u8, suite[0], "25519_")) {
            inline for (multi_psk_names) |name| {
                const full = "Noise_" ++ name ++ "_" ++ suite[0];
                const p = comptime pattern.fromName(name);
                for (parsed.value.vectors) |v| {
                    if (!std.mem.eql(u8, v.protocol_name, full)) continue;
                    runVector(suite[1], p, v) catch |err| {
                        std.debug.print("snow vector failed: {s}\n", .{full});
                        return err;
                    };
                    ran += 1;
                }
            }
        }
    }
    try std.testing.expectEqual(multi_psk_names.len * 8, ran);
}

test "cacophony vectors" {
    const data = @embedFile("cacophony");
    const parsed = try std.json.parseFromSlice(File, std.testing.allocator, data, .{
        .ignore_unknown_fields = true,
    });
    defer parsed.deinit();

    var ran: usize = 0;
    inline for (suites) |suite| {
        inline for (pattern_names) |name| {
            const full = "Noise_" ++ name ++ "_" ++ suite[0];
            const p = comptime pattern.fromName(name);
            for (parsed.value.vectors) |v| {
                if (!std.mem.eql(u8, v.protocol_name, full)) continue;
                runVector(suite[1], p, v) catch |err| {
                    std.debug.print("vector failed: {s}\n", .{full});
                    return err;
                };
                ran += 1;
            }
        }
    }
    try std.testing.expectEqual(pattern_names.len * suites.len, ran);
}
