const std = @import("std");
const npf = @import("root.zig");

const XX = npf.Protocol("Noise_XX_25519_ChaChaPoly_SHA256");

fn testRng(seed: *u8) npf.Rng {
    return .{
        .ctx = seed,
        .fillFn = struct {
            fn f(ctx: ?*anyopaque, out: []u8) void {
                const s: *u8 = @ptrCast(@alignCast(ctx.?));
                for (out) |*b| {
                    b.* = s.*;
                    s.* +%= 1;
                }
            }
        }.f,
    };
}

// Covers every line of the snippet in README.md. The peer is local so the
// handshake can run to completion, which is what the "read the reply"
// comment stands in for there.
test "readme example" {
    const static = XX.Dh.KeyPair.fromSecret(@splat(11));
    var seed: u8 = 1;

    var hs = try XX.init(.initiator, .{ .s = static, .rng = testRng(&seed) });

    var buf: [npf.max_message_len]u8 = undefined;
    const n = try hs.writeMessage("hello", &buf);
    // send buf[0..n], read the reply, repeat until hs.isFinished()

    const peer_static = XX.Dh.KeyPair.fromSecret(@splat(22));
    var peer_seed: u8 = 128;
    var peer = try XX.init(.responder, .{
        .s = peer_static,
        .rng = testRng(&peer_seed),
    });

    var plain: [npf.max_message_len]u8 = undefined;
    var len = try peer.readMessage(buf[0..n], &plain);
    try std.testing.expectEqualStrings("hello", plain[0..len]);
    while (!hs.isFinished()) {
        const writer, const reader = if (hs.isMyTurn())
            .{ &hs, &peer }
        else
            .{ &peer, &hs };
        len = try writer.writeMessage("", &buf);
        _ = try reader.readMessage(buf[0..len], &plain);
    }

    var t = try hs.split();
    len = try t.send.encryptWithAd("", "data", &buf);

    var peer_t = try peer.split();
    const got = try peer_t.recv.decryptWithAd("", buf[0..len], &plain);
    try std.testing.expectEqualStrings("data", plain[0..got]);
}

test "Protocol resolves every part of the name" {
    try std.testing.expectEqualStrings("XX", XX.handshake_pattern.name);
    try std.testing.expectEqualStrings("25519", XX.Dh.name);
    try std.testing.expectEqualStrings("ChaChaPoly", XX.Cipher.name);
    try std.testing.expectEqualStrings("SHA256", XX.Hash.name);

    const psk = npf.Protocol("Noise_IKpsk2_448_AESGCM_BLAKE2b");
    try std.testing.expectEqualStrings("IKpsk2", psk.handshake_pattern.name);
    try std.testing.expect(psk.handshake_pattern.psk);
    try std.testing.expectEqual(@as(usize, 56), psk.Dh.dhlen);

    const fb = npf.Protocol("Noise_XXfallback_25519_ChaChaPoly_SHA256");
    try std.testing.expect(!fb.handshake_pattern.initiator_first);
}
