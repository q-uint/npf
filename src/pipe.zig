const std = @import("std");
const pattern = @import("pattern.zig");
const handshake = @import("handshake.zig");

pub const Error = handshake.Error;

/// The Noise Pipe compound protocol (section 10.4).
///
/// Three patterns, one state machine:
///   - `XX` for a full handshake between parties that have not met
///   - `IK` for a zero-RTT handshake using a cached remote static
///   - `XXfallback` when the responder cannot decrypt an `IK` message,
///     typically because its static key changed
///
/// This type owns the pattern selection and the carry-over of the
/// initiator's semi-ephemeral key from `IK` into `XXfallback`. It does not
/// own the wire format. Noise does not specify how a responder tells an
/// `IK` message from an `XX` one, and section 13 puts that negotiation data
/// squarely in the application's hands, with a warning about rollback
/// attacks. So the application frames messages however it likes and tells
/// this type which kind arrived.
///
/// `Config.prologue` is borrowed, so it must outlive the pipe. It is reused
/// verbatim when falling back.
pub fn Pipe(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Hs = handshake.HandshakeState(S);
        pub const Config = Hs.Config;
        pub const Transport = Hs.Transport;
        pub const Digest = Hs.Digest;
        pub const dhlen = Hs.dhlen;

        /// Which pattern a message belongs to. The application carries this
        /// on the wire, for instance as a leading type byte.
        pub const Kind = enum { xx, ik, fallback };

        const xx_pattern = pattern.XX;
        const ik_pattern = pattern.IK;
        const fallback_pattern = pattern.XXfallback;

        hs: Hs,
        prologue: []const u8,
        kind: Kind,
        is_initiator: bool,

        /// Starts an initiator. Picks `IK` when a remote static is cached in
        /// `cfg.rs` and `XX` otherwise.
        pub fn initiator(cfg: Config) Error!Self {
            const kind: Kind = if (cfg.rs != null) .ik else .xx;
            return .{
                .hs = switch (kind) {
                    .ik => try Hs.init(ik_pattern, .initiator, cfg),
                    else => try Hs.init(xx_pattern, .initiator, cfg),
                },
                .prologue = cfg.prologue,
                .kind = kind,
                .is_initiator = true,
            };
        }

        /// Starts a responder for an incoming message of the given kind,
        /// which the application determines from its own framing.
        pub fn responder(cfg: Config, kind: Kind) Error!Self {
            return .{
                .hs = switch (kind) {
                    .ik => try Hs.init(ik_pattern, .responder, cfg),
                    .xx => try Hs.init(xx_pattern, .responder, cfg),
                    .fallback => return Error.InvalidPipeKind,
                },
                .prologue = cfg.prologue,
                .kind = kind,
                .is_initiator = false,
            };
        }

        pub fn currentKind(self: Self) Kind {
            return self.kind;
        }

        pub fn isFinished(self: Self) bool {
            return self.hs.isFinished();
        }

        pub fn isMyTurn(self: Self) bool {
            return self.hs.isMyTurn();
        }

        pub fn handshakeHash(self: Self) Digest {
            return self.hs.handshakeHash();
        }

        pub fn remoteStatic(self: Self) ?[dhlen]u8 {
            return self.hs.remoteStatic();
        }

        pub fn split(self: *Self) Error!Transport {
            return self.hs.split();
        }

        pub fn clear(self: *Self) void {
            self.hs.clear();
        }

        pub fn writeMessage(self: *Self, payload: []const u8, out: []u8) Error!usize {
            return self.hs.writeMessage(payload, out);
        }

        /// Reads a handshake message.
        ///
        /// When a responder fails to decrypt the first `IK` message, this
        /// switches itself to `XXfallback`, carrying over the initiator's
        /// semi-ephemeral key from the head of the failed message, and
        /// returns `FallbackRequired`. The caller then writes the next
        /// message, tagging it `.fallback` on the wire. No other error
        /// leaves the pipe in a usable state.
        pub fn readMessage(self: *Self, msg: []const u8, out: []u8) Error!usize {
            const first_ik = !self.is_initiator and self.kind == .ik and self.hs.index == 0;
            if (!first_ik) return self.hs.readMessage(msg, out);

            // readMessage is all or nothing, so a rejected IK message leaves
            // this handshake untouched and the fallback starts clean.
            if (self.hs.readMessage(msg, out)) |n| {
                return n;
            } else |err| {
                if (err != Error.AuthenticationFailed) return err;
                if (msg.len < dhlen) return Error.MessageTooShort;
                try self.fallback(msg[0..dhlen].*);
                return Error.FallbackRequired;
            }
        }

        /// Switches an initiator to `XXfallback` after learning that the
        /// responder rejected its `IK` message. Call this when a reply
        /// tagged `.fallback` arrives, before reading it.
        pub fn switchToFallback(self: *Self) Error!void {
            if (!self.is_initiator) return Error.FallbackRequired;
            try self.fallback(null);
        }

        fn fallback(self: *Self, semi_ephemeral: ?[dhlen]u8) Error!void {
            var cfg: Config = .{
                .prologue = self.prologue,
                .s = self.hs.s,
                .e = self.hs.e,
                .psks = self.hs.psks[0..self.hs.psks_len],
                .rng = self.hs.rng,
            };
            defer Hs.clearConfig(&cfg);
            if (self.is_initiator) {
                // Our IK ephemeral becomes the XXfallback pre-message.
                if (cfg.e == null) return Error.MissingEphemeral;
            } else {
                // The responder never sent an ephemeral during IK, so any
                // one it was configured with is still unused and carries
                // over. Left null it is generated from `rng` on first write.
                cfg.re = semi_ephemeral orelse return Error.MissingRemoteEphemeral;
            }
            const role: handshake.Role = if (self.is_initiator) .initiator else .responder;
            self.hs = try Hs.init(fallback_pattern, role, cfg);
            self.kind = .fallback;
        }
    };
}

const crypto = @import("crypto.zig");

const TestSuite = handshake.Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Sha256);
const TestPipe = Pipe(TestSuite);

const CountingRng = struct {
    next: u8 = 1,

    fn fill(ctx: ?*anyopaque, buf: []u8) void {
        const self: *CountingRng = @ptrCast(@alignCast(ctx.?));
        for (buf) |*b| {
            b.* = self.next;
            self.next +%= 1;
        }
    }

    fn rng(self: *CountingRng) handshake.Rng {
        return .{ .ctx = self, .fillFn = fill };
    }
};

const Wire = struct {
    kind: TestPipe.Kind,
    buf: [256]u8 = undefined,
    len: usize = 0,
};

fn finish(a: *TestPipe, b: *TestPipe, alice_s: anytype, bob_s: anytype) !void {
    var frame: Wire = .{ .kind = .xx };
    var plain: [256]u8 = undefined;

    while (!a.isFinished()) {
        const writer, const reader = if (a.isMyTurn()) .{ a, b } else .{ b, a };
        frame.len = try writer.writeMessage("payload", &frame.buf);
        const got = try reader.readMessage(frame.buf[0..frame.len], &plain);
        try std.testing.expectEqualStrings("payload", plain[0..got]);
    }

    try std.testing.expect(b.isFinished());
    try std.testing.expectEqual(a.handshakeHash(), b.handshakeHash());
    try std.testing.expectEqual(bob_s.public, a.remoteStatic().?);
    try std.testing.expectEqual(alice_s.public, b.remoteStatic().?);

    const ta = try a.split();
    const tb = try b.split();
    try std.testing.expectEqual(ta.send.k, tb.recv.k);
    try std.testing.expectEqual(ta.recv.k, tb.send.k);
}

test "noise pipe: full XX handshake when no static is cached" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    var alice = try TestPipe.initiator(.{ .s = alice_s, .rng = a_rng.rng() });
    var bob = try TestPipe.responder(.{ .s = bob_s, .rng = b_rng.rng() }, .xx);

    try std.testing.expectEqual(TestPipe.Kind.xx, alice.currentKind());
    try finish(&alice, &bob, alice_s, bob_s);
}

test "noise pipe: abbreviated IK handshake with a cached static" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = bob_s.public,
        .rng = a_rng.rng(),
    });
    var bob = try TestPipe.responder(.{ .s = bob_s, .rng = b_rng.rng() }, .ik);

    try std.testing.expectEqual(TestPipe.Kind.ik, alice.currentKind());
    try finish(&alice, &bob, alice_s, bob_s);
}

test "noise pipe: a stale cached static falls back to XXfallback" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));
    const stale_s = crypto.X25519.KeyPair.fromSecret(@splat(33));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = stale_s.public,
        .rng = a_rng.rng(),
    });
    var bob = try TestPipe.responder(.{ .s = bob_s, .rng = b_rng.rng() }, .ik);
    try std.testing.expectEqual(TestPipe.Kind.ik, alice.currentKind());

    var frame: Wire = .{ .kind = .ik };
    var plain: [256]u8 = undefined;

    // Alice sends 0-RTT data to a key Bob no longer holds.
    frame.len = try alice.writeMessage("0-rtt", &frame.buf);
    try std.testing.expectError(
        Error.FallbackRequired,
        bob.readMessage(frame.buf[0..frame.len], &plain),
    );

    // Bob has switched himself and carried Alice's semi-ephemeral across.
    try std.testing.expectEqual(TestPipe.Kind.fallback, bob.currentKind());
    try std.testing.expect(bob.isMyTurn());

    // The reply is tagged .fallback on the wire, so Alice switches too.
    try alice.switchToFallback();
    try std.testing.expectEqual(TestPipe.Kind.fallback, alice.currentKind());

    try finish(&alice, &bob, alice_s, bob_s);
}

test "noise pipe: an initiator can trial-decrypt instead of reading a tag" {
    // Section 10.5 describes hiding which handshake is in use by having
    // Alice distinguish an IK response from an XXfallback one by trial
    // decryption rather than by negotiation data.
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));
    const stale_s = crypto.X25519.KeyPair.fromSecret(@splat(33));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = stale_s.public,
        .rng = a_rng.rng(),
    });
    var bob = try TestPipe.responder(.{ .s = bob_s, .rng = b_rng.rng() }, .ik);

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    var n = try alice.writeMessage("0-rtt", &buf);
    try std.testing.expectError(Error.FallbackRequired, bob.readMessage(buf[0..n], &plain));
    n = try bob.writeMessage("reply", &buf);

    // Alice has no tag to read, so she tries IK first. The failed attempt
    // must leave her usable, which is what makes the retry possible.
    const got = alice.readMessage(buf[0..n], &plain) catch |err| blk: {
        try std.testing.expectEqual(Error.AuthenticationFailed, err);
        try alice.switchToFallback();
        break :blk try alice.readMessage(buf[0..n], &plain);
    };
    try std.testing.expectEqualStrings("reply", plain[0..got]);
    try std.testing.expectEqual(TestPipe.Kind.fallback, alice.currentKind());

    try finish(&alice, &bob, alice_s, bob_s);
}

test "noise pipe: a responder with the right key never falls back" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = bob_s.public,
        .rng = a_rng.rng(),
    });
    var bob = try TestPipe.responder(.{ .s = bob_s, .rng = b_rng.rng() }, .ik);

    var frame: Wire = .{ .kind = .ik };
    var plain: [256]u8 = undefined;
    frame.len = try alice.writeMessage("0-rtt", &frame.buf);
    const got = try bob.readMessage(frame.buf[0..frame.len], &plain);
    try std.testing.expectEqualStrings("0-rtt", plain[0..got]);
    try std.testing.expectEqual(TestPipe.Kind.ik, bob.currentKind());
}

test "noise pipe: fallback carries over a configured but unused ephemeral" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));
    const bob_e = crypto.X25519.KeyPair.fromSecret(@splat(44));
    const stale_s = crypto.X25519.KeyPair.fromSecret(@splat(33));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = stale_s.public,
        .rng = a_rng.rng(),
    });
    var bob = try TestPipe.responder(.{
        .s = bob_s,
        .e = bob_e,
        .rng = b_rng.rng(),
    }, .ik);

    var frame: Wire = .{ .kind = .ik };
    var plain: [256]u8 = undefined;
    frame.len = try alice.writeMessage("0-rtt", &frame.buf);
    try std.testing.expectError(
        Error.FallbackRequired,
        bob.readMessage(frame.buf[0..frame.len], &plain),
    );

    // The fallback config is rebuilt from the live handshake, so the keys
    // Bob never got to use must still be the ones he was configured with.
    try std.testing.expectEqual(bob_e.public, bob.hs.e.?.public);
    try std.testing.expectEqual(bob_s.public, bob.hs.s.?.public);
    try std.testing.expectEqual(@as(?[TestPipe.dhlen]u8, null), bob.hs.rs);

    try alice.switchToFallback();
    try finish(&alice, &bob, alice_s, bob_s);
}

test "noise pipe: falling back after clear does not resurrect wiped keys" {
    var a_rng = CountingRng{ .next = 1 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const stale_s = crypto.X25519.KeyPair.fromSecret(@splat(33));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = stale_s.public,
        .rng = a_rng.rng(),
    });
    var frame: Wire = .{ .kind = .ik };
    frame.len = try alice.writeMessage("0-rtt", &frame.buf);

    alice.clear();
    try std.testing.expectError(Error.MissingEphemeral, alice.switchToFallback());
}

test "noise pipe: a failed read leaves the pipe usable for fallback" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));
    const stale_s = crypto.X25519.KeyPair.fromSecret(@splat(33));

    var alice = try TestPipe.initiator(.{
        .s = alice_s,
        .rs = stale_s.public,
        .rng = a_rng.rng(),
    });
    var bob = try TestPipe.responder(.{ .s = bob_s, .rng = b_rng.rng() }, .ik);

    var frame: Wire = .{ .kind = .ik };
    var plain: [256]u8 = undefined;
    frame.len = try alice.writeMessage("0-rtt", &frame.buf);
    _ = bob.readMessage(frame.buf[0..frame.len], &plain) catch {};

    // Bob's fallback state must carry Alice's ephemeral, not a fresh one.
    try std.testing.expectEqual(alice.hs.e.?.public, bob.hs.re.?);
}
