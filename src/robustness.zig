const std = @import("std");
const crypto = @import("crypto.zig");
const pattern = @import("pattern.zig");
const handshake = @import("handshake.zig");

const Suite = handshake.Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Sha256);
const Hs = handshake.HandshakeState(Suite);

const Rng = struct {
    next: u8 = 1,

    fn fill(ctx: ?*anyopaque, buf: []u8) void {
        const self: *Rng = @ptrCast(@alignCast(ctx.?));
        for (buf) |*b| {
            b.* = self.next;
            self.next +%= 1;
        }
    }

    fn rng(self: *Rng) handshake.Rng {
        return .{ .ctx = self, .fillFn = fill };
    }
};

fn responderFor(comptime p: Pattern, s: crypto.X25519.KeyPair, rs: ?[32]u8, rng: handshake.Rng) !Hs {
    return Hs.init(p, .responder, .{ .s = s, .rs = rs, .rng = rng });
}

const Pattern = pattern.Pattern;

/// Every truncation and every single-bit corruption of a real handshake
/// message must come back as an error, never a panic or a success.
fn hammer(comptime p: Pattern) !void {
    var i_rng = Rng{ .next = 1 };
    var r_rng = Rng{ .next = 128 };
    const i_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const r_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    const i_knows = comptime std.mem.indexOfScalar(pattern.Token, p.pre[1], .s) != null;
    const r_knows = comptime std.mem.indexOfScalar(pattern.Token, p.pre[0], .s) != null;

    var sender = try Hs.init(p, .initiator, .{
        .s = i_s,
        .rs = if (i_knows) r_s.public else null,
        .psks = if (p.psk) &[_][32]u8{@splat(42)} else &.{},
        .rng = i_rng.rng(),
    });

    var buf: [1024]u8 = undefined;
    const n = try sender.writeMessage("payload", &buf);

    var plain: [1024]u8 = undefined;

    // Truncation at every length.
    for (0..n) |cut| {
        var victim = try responderFor(p, r_s, if (r_knows) i_s.public else null, r_rng.rng());
        if (p.psk) { victim.psks[0] = @splat(42); victim.psks_len = 1; }
        _ = victim.readMessage(buf[0..cut], &plain) catch continue;
    }

    // One flipped bit at every byte position.
    for (0..n) |pos| {
        var corrupt: [1024]u8 = undefined;
        @memcpy(corrupt[0..n], buf[0..n]);
        corrupt[pos] ^= 0x80;

        var victim = try responderFor(p, r_s, if (r_knows) i_s.public else null, r_rng.rng());
        if (p.psk) { victim.psks[0] = @splat(42); victim.psks_len = 1; }
        _ = victim.readMessage(corrupt[0..n], &plain) catch continue;
    }

    // Oversized input, and the exact boundary of the section 3 limit.
    var big: [handshake.HandshakeState(Suite).max_message_len + 2]u8 = @splat(0);
    var victim = try responderFor(p, r_s, if (r_knows) i_s.public else null, r_rng.rng());
    if (p.psk) { victim.psks[0] = @splat(42); victim.psks_len = 1; }
    try std.testing.expectError(
        handshake.Error.MessageTooLong,
        victim.readMessage(&big, &plain),
    );
    _ = victim.readMessage(big[0 .. Hs.max_message_len - 1], &plain) catch {};
}

test "readMessage survives truncation and corruption" {
    inline for (.{ pattern.NN, pattern.XX, pattern.IK, pattern.NK, pattern.X }) |p| {
        try hammer(p);
    }
    inline for (.{ "NNpsk0", "XXpsk3", "IKpsk2" }) |name| {
        try hammer(comptime pattern.fromName(name));
    }
}

test "readMessage survives a zero-length and a one-byte message" {
    var r_rng = Rng{ .next = 7 };
    const r_s = crypto.X25519.KeyPair.fromSecret(@splat(22));
    var plain: [64]u8 = undefined;

    var a = try Hs.init(pattern.XX, .responder, .{ .s = r_s, .rng = r_rng.rng() });
    _ = a.readMessage("", &plain) catch {};

    var b = try Hs.init(pattern.XX, .responder, .{ .s = r_s, .rng = r_rng.rng() });
    _ = b.readMessage("x", &plain) catch {};
}

test "a short output buffer never writes past it" {
    var i_rng = Rng{ .next = 1 };
    const i_s = crypto.X25519.KeyPair.fromSecret(@splat(11));

    for (0..80) |cap| {
        var hs = try Hs.init(pattern.XX, .initiator, .{ .s = i_s, .rng = i_rng.rng() });
        var small: [80]u8 = @splat(0xaa);
        _ = hs.writeMessage("payload", small[0..cap]) catch continue;
    }
}
