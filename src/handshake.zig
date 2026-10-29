const std = @import("std");
const state = @import("state.zig");
const pattern = @import("pattern.zig");
const crypto = @import("crypto.zig");

const Pattern = pattern.Pattern;
const Token = pattern.Token;

pub const Error = state.Error || error{
    HandshakeFinished,
    HandshakeUnfinished,
    OutOfTurn,
    MissingStatic,
    MissingEphemeral,
    MissingRemoteStatic,
    MissingRemoteEphemeral,
    MissingPsk,
    TooManyPsks,
    RemoteKeyAlreadySet,
    FallbackRequired,
    InvalidPipeKind,
};

pub const Role = enum {
    initiator,
    responder,

    pub fn isInitiator(self: Role) bool {
        return self == .initiator;
    }
};

pub const Rng = struct {
    ctx: ?*anyopaque,
    fillFn: *const fn (?*anyopaque, []u8) void,

    pub fn fill(self: Rng, buf: []u8) void {
        self.fillFn(self.ctx, buf);
    }

    pub fn fromIo(io: *const std.Io) Rng {
        return .{
            .ctx = @constCast(io),
            .fillFn = struct {
                fn f(ctx: ?*anyopaque, buf: []u8) void {
                    const p: *const std.Io = @ptrCast(@alignCast(ctx.?));
                    p.random(buf);
                }
            }.f,
        };
    }
};

pub fn Suite(comptime D: type, comptime C: type, comptime H: type) type {
    return struct {
        pub const Dh = D;
        pub const Cipher = C;
        pub const Hash = H;
        pub const name = D.name ++ "_" ++ C.name ++ "_" ++ H.name;
    };
}

/// Resolves a full Noise protocol name, as defined in section 8, to a bound
/// handshake. The pattern and the three algorithms all come from the name.
///
///     const P = Protocol("Noise_XX_25519_ChaChaPoly_SHA256");
///     var hs = try P.init(.initiator, .{ .s = static, .rng = rng });
pub fn Protocol(comptime full_name: []const u8) type {
    const parts = comptime blk: {
        @setEvalBranchQuota(10_000);
        var it = std.mem.splitScalar(u8, full_name, '_');
        var found: [5][]const u8 = undefined;
        var n: usize = 0;
        while (it.next()) |part| {
            if (n == found.len) @compileError("not a Noise protocol name: " ++ full_name);
            found[n] = part;
            n += 1;
        }
        if (n != found.len or !std.mem.eql(u8, found[0], "Noise"))
            @compileError("not a Noise protocol name: " ++ full_name);
        break :blk found;
    };

    return struct {
        pub const name = full_name;
        pub const handshake_pattern = pattern.fromName(parts[1]);
        pub const Dh = crypto.dhByName(parts[2]);
        pub const Cipher = crypto.cipherByName(parts[3]);
        pub const Hash = crypto.hashByName(parts[4]);
        pub const Handshake = HandshakeState(Suite(Dh, Cipher, Hash));
        pub const Config = Handshake.Config;

        pub fn init(role: Role, cfg: Config) Error!Handshake {
            return Handshake.init(handshake_pattern, role, cfg);
        }
    };
}

pub fn HandshakeState(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Dh = S.Dh;
        pub const Cipher = S.Cipher;
        pub const Hash = S.Hash;
        pub const Ss = state.SymmetricState(S.Cipher, S.Hash);
        pub const Cs = Ss.Cs;
        pub const Digest = Ss.Digest;
        pub const dhlen = Dh.dhlen;
        pub const tag_len = Cipher.tag_len;
        pub const psk_len = 32;
        pub const max_psks = 8;
        pub const max_message_len = state.max_message_len;

        pub const Config = struct {
            prologue: []const u8 = &.{},
            s: ?Dh.KeyPair = null,
            e: ?Dh.KeyPair = null,
            rs: ?[dhlen]u8 = null,
            re: ?[dhlen]u8 = null,
            psks: []const [psk_len]u8 = &.{},
            rng: ?Rng = null,
        };

        ss: Ss,
        initiator: bool,
        pat: Pattern,
        index: usize,
        s: ?Dh.KeyPair,
        e: ?Dh.KeyPair,
        rs: ?[dhlen]u8,
        re: ?[dhlen]u8,
        psks: [max_psks][psk_len]u8,
        psks_len: usize,
        psk_index: usize,
        rng: ?Rng,

        pub fn protocolName(comptime p: Pattern) []const u8 {
            const full = "Noise_" ++ p.name ++ "_" ++ S.name;
            if (full.len > 255)
                @compileError("protocol name exceeds the 255 byte limit of section 8: " ++ full);
            return full;
        }

        pub fn init(comptime p: Pattern, role: Role, cfg: Config) Error!Self {
            const initiator = role.isInitiator();
            var self: Self = .{
                .ss = Ss.init(comptime protocolName(p)),
                .initiator = initiator,
                .pat = p,
                .index = 0,
                .s = cfg.s,
                .e = cfg.e,
                .rs = cfg.rs,
                .re = cfg.re,
                .psks = @splat(@splat(0)),
                .psks_len = cfg.psks.len,
                .psk_index = 0,
                .rng = cfg.rng,
            };
            if (cfg.psks.len > max_psks) return Error.TooManyPsks;
            for (cfg.psks, 0..) |psk, i| self.psks[i] = psk;
            self.ss.mixHash(cfg.prologue);

            for (p.pre, 0..) |tokens, party| {
                const mine = (party == 0) == initiator;
                for (tokens) |tok| {
                    const pk = switch (tok) {
                        .s => if (mine)
                            (self.s orelse return Error.MissingStatic).public
                        else
                            self.rs orelse return Error.MissingRemoteStatic,
                        .e => if (mine)
                            (self.e orelse return Error.MissingEphemeral).public
                        else
                            self.re orelse return Error.MissingRemoteEphemeral,
                        else => unreachable,
                    };
                    self.ss.mixHash(&pk);
                    if (p.psk and tok == .e) self.ss.mixKey(&pk);
                }
            }
            return self;
        }

        pub fn isFinished(self: Self) bool {
            return self.index >= self.pat.messages.len;
        }

        pub fn isMyTurn(self: Self) bool {
            return !self.isFinished() and self.pat.senderIsInitiator(self.index) == self.initiator;
        }

        pub fn handshakeHash(self: Self) Digest {
            return self.ss.handshakeHash();
        }

        pub fn remoteStatic(self: Self) ?[dhlen]u8 {
            return self.rs;
        }

        pub const Transport = struct {
            send: Cs,
            recv: Cs,

            /// Wipes both transport keys. Call when the session ends.
            pub fn clear(self: *Transport) void {
                self.send.clear();
                self.recv.clear();
            }
        };

        /// Transport keys, from this party's point of view. For a one-way
        /// pattern the second CipherState is discarded (section 7.4), so the
        /// unusable half comes back cleared.
        pub fn split(self: *Self) Error!Transport {
            if (!self.isFinished()) return Error.HandshakeUnfinished;
            const cs = self.ss.split();
            const sends_first = self.pat.senderIsInitiator(0) == self.initiator;
            var t: Transport = if (sends_first)
                .{ .send = cs[0], .recv = cs[1] }
            else
                .{ .send = cs[1], .recv = cs[0] };

            if (self.pat.messages.len == 1) {
                if (sends_first) t.recv.clear() else t.send.clear();
            }
            return t;
        }

        pub const HalfDuplex = state.HalfDuplexCipherState(Cipher);

        /// A single CipherState used for both directions (section 11.5).
        /// Both parties get the same one and the second output of Split is
        /// discarded.
        ///
        /// Only safe if the application protocol strictly alternates who
        /// sends, including defining which side sends first. If both parties
        /// ever encrypt under the same nonce the keystream repeats, which is
        /// a catastrophic failure. The returned type rejects a local
        /// double-encrypt, but it cannot see the peer. Prefer `split`.
        pub fn splitHalfDuplex(self: *Self) Error!HalfDuplex {
            if (!self.isFinished()) return Error.HandshakeUnfinished;
            return HalfDuplex.init(self.ss.split()[0]);
        }

        /// Transport keys for protocols with lossy or reordered delivery
        /// (section 11.4). `window_words * 64` messages may arrive out of
        /// order before the oldest is rejected as too old.
        pub fn UnorderedTransport(comptime window_words: usize) type {
            return struct {
                const T = @This();

                send: state.UnorderedSender(Cipher),
                recv: state.UnorderedReceiver(Cipher, window_words),

                /// Wipes both transport keys. Call when the session ends.
                pub fn clear(self: *T) void {
                    self.send.clear();
                    self.recv.clear();
                }
            };
        }

        pub fn splitUnordered(
            self: *Self,
            comptime window_words: usize,
        ) Error!UnorderedTransport(window_words) {
            const t = try self.split();
            return .{
                .send = state.UnorderedSender(Cipher).init(t.send),
                .recv = state.UnorderedReceiver(Cipher, window_words).init(t.recv),
            };
        }

        /// Wipes all key material held by this handshake. Call once the
        /// transport keys have been taken with `split`.
        pub fn clear(self: *Self) void {
            self.ss.clear();
            if (self.s) |*kp| std.crypto.secureZero(u8, &kp.secret);
            if (self.e) |*kp| std.crypto.secureZero(u8, &kp.secret);
            for (&self.psks) |*psk| std.crypto.secureZero(u8, psk);
            self.s = null;
            self.e = null;
            self.psks_len = 0;
            self.psk_index = 0;
        }

        /// Wipes the secrets in a `Config`, for callers that keep one alive
        /// past `init`. The borrowed prologue, the borrowed PSKs, and the
        /// public keys are left alone.
        pub fn clearConfig(cfg: *Config) void {
            if (cfg.s) |*kp| std.crypto.secureZero(u8, &kp.secret);
            if (cfg.e) |*kp| std.crypto.secureZero(u8, &kp.secret);
            cfg.s = null;
            cfg.e = null;
        }

        fn mixDh(self: *Self, tok: Token) Error!void {
            const local, const remote = switch (tok) {
                .ee => .{ self.e, self.re },
                .ss => .{ self.s, self.rs },
                .es => if (self.initiator) .{ self.e, self.rs } else .{ self.s, self.re },
                .se => if (self.initiator) .{ self.s, self.re } else .{ self.e, self.rs },
                else => unreachable,
            };
            const kp = local orelse return switch (tok) {
                .ss => Error.MissingStatic,
                .ee => Error.MissingEphemeral,
                else => if ((tok == .es) == self.initiator) Error.MissingEphemeral else Error.MissingStatic,
            };
            const pk = remote orelse return switch (tok) {
                .ss => Error.MissingRemoteStatic,
                .ee => Error.MissingRemoteEphemeral,
                else => if ((tok == .es) == self.initiator) Error.MissingRemoteStatic else Error.MissingRemoteEphemeral,
            };
            var shared = Dh.dh(kp, pk);
            defer std.crypto.secureZero(u8, &shared);
            self.ss.mixKey(&shared);
        }

        /// Section 9.2 allows a `psk` token to appear more than once. Each
        /// one consumes the next PSK in the order the caller supplied them.
        fn mixPsk(self: *Self) Error!void {
            if (self.psk_index >= self.psks_len) return Error.MissingPsk;
            self.ss.mixKeyAndHash(&self.psks[self.psk_index]);
            self.psk_index += 1;
        }

        fn localEphemeral(self: *Self) Error!Dh.KeyPair {
            if (self.e) |kp| return kp;
            const rng = self.rng orelse return Error.MissingEphemeral;
            var seed: [dhlen]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            rng.fill(&seed);
            self.e = Dh.KeyPair.fromSecret(seed);
            return self.e.?;
        }

        /// Writes the next handshake message.
        ///
        /// All or nothing: on any error this state is left exactly as it was,
        /// so a caller that can recover (see pipe.zig) may keep using it. The
        /// spec treats a failed handshake as fatal, but partially mixed state
        /// is a sharp edge worth filing off.
        pub fn writeMessage(self: *Self, payload: []const u8, out: []u8) Error!usize {
            var probe = self.*;
            defer probe.clear();
            const n = try probe.writeMessageInner(payload, out);
            self.* = probe;
            return n;
        }

        /// Reads the next handshake message. All or nothing, as `writeMessage`.
        pub fn readMessage(self: *Self, msg: []const u8, out: []u8) Error!usize {
            var probe = self.*;
            defer probe.clear();
            const n = try probe.readMessageInner(msg, out);
            self.* = probe;
            return n;
        }

        fn writeMessageInner(self: *Self, payload: []const u8, out: []u8) Error!usize {
            if (self.isFinished()) return Error.HandshakeFinished;
            if (!self.isMyTurn()) return Error.OutOfTurn;

            var n: usize = 0;
            for (self.pat.messages[self.index]) |tok| switch (tok) {
                .e => {
                    const kp = try self.localEphemeral();
                    if (out.len - n < dhlen) return Error.BufferTooSmall;
                    @memcpy(out[n..][0..dhlen], &kp.public);
                    n += dhlen;
                    self.ss.mixHash(&kp.public);
                    if (self.pat.psk) self.ss.mixKey(&kp.public);
                },
                .s => {
                    const kp = self.s orelse return Error.MissingStatic;
                    n += try self.ss.encryptAndHash(&kp.public, out[n..]);
                },
                .psk => try self.mixPsk(),
                else => try self.mixDh(tok),
            };
            n += try self.ss.encryptAndHash(payload, out[n..]);
            if (n > max_message_len) return Error.MessageTooLong;
            self.index += 1;
            return n;
        }

        fn readMessageInner(self: *Self, msg: []const u8, out: []u8) Error!usize {
            if (self.isFinished()) return Error.HandshakeFinished;
            if (self.isMyTurn()) return Error.OutOfTurn;
            if (msg.len > max_message_len) return Error.MessageTooLong;

            var i: usize = 0;
            for (self.pat.messages[self.index]) |tok| switch (tok) {
                .e => {
                    if (self.re != null) return Error.RemoteKeyAlreadySet;
                    if (msg.len - i < dhlen) return Error.MessageTooShort;
                    const pk = msg[i..][0..dhlen].*;
                    i += dhlen;
                    self.re = pk;
                    self.ss.mixHash(&pk);
                    if (self.pat.psk) self.ss.mixKey(&pk);
                },
                .s => {
                    if (self.rs != null) return Error.RemoteKeyAlreadySet;
                    const len: usize = dhlen + @as(usize, if (self.ss.cs.hasKey()) tag_len else 0);
                    if (msg.len - i < len) return Error.MessageTooShort;
                    var pk: [dhlen]u8 = undefined;
                    _ = try self.ss.decryptAndHash(msg[i..][0..len], &pk);
                    i += len;
                    self.rs = pk;
                },
                .psk => try self.mixPsk(),
                else => try self.mixDh(tok),
            };
            const n = try self.ss.decryptAndHash(msg[i..], out);
            self.index += 1;
            return n;
        }
    };
}


const TestSuite = Suite(crypto.X25519, crypto.ChaChaPoly, crypto.Sha256);
const Hs = HandshakeState(TestSuite);

const CountingRng = struct {
    next: u8 = 1,

    fn fill(ctx: ?*anyopaque, buf: []u8) void {
        const self: *CountingRng = @ptrCast(@alignCast(ctx.?));
        for (buf) |*b| {
            b.* = self.next;
            self.next +%= 1;
        }
    }

    fn rng(self: *CountingRng) Rng {
        return .{ .ctx = self, .fillFn = fill };
    }
};

fn run(comptime p: Pattern, i_cfg: Hs.Config, r_cfg: Hs.Config) !void {
    var initiator = try Hs.init(p, .initiator, i_cfg);
    var responder = try Hs.init(p, .responder, r_cfg);

    var buf: [512]u8 = undefined;
    var plain: [512]u8 = undefined;
    const payload = "handshake payload";

    while (!initiator.isFinished()) {
        const writer, const reader = if (initiator.isMyTurn())
            .{ &initiator, &responder }
        else
            .{ &responder, &initiator };
        const n = try writer.writeMessage(payload, &buf);
        const m = try reader.readMessage(buf[0..n], &plain);
        try std.testing.expectEqualStrings(payload, plain[0..m]);
    }

    try std.testing.expect(responder.isFinished());
    try std.testing.expectEqual(initiator.handshakeHash(), responder.handshakeHash());

    var i_keys = try initiator.split();
    var r_keys = try responder.split();
    try std.testing.expectEqual(i_keys.send.k, r_keys.recv.k);
    try std.testing.expectEqual(i_keys.recv.k, r_keys.send.k);

    var ct: [4 + Hs.tag_len]u8 = undefined;
    var pt: [4]u8 = undefined;
    _ = try i_keys.send.encryptWithAd("", "ping", &ct);
    const got = try r_keys.recv.decryptWithAd("", &ct, &pt);
    try std.testing.expectEqualStrings("ping", pt[0..got]);

    if (p.messages.len >= 2) {
        _ = try r_keys.send.encryptWithAd("", "pong", &ct);
        const back = try i_keys.recv.decryptWithAd("", &ct, &pt);
        try std.testing.expectEqualStrings("pong", pt[0..back]);
    }
}

test "protocol name follows section 8" {
    try std.testing.expectEqualStrings(
        "Noise_XX_25519_ChaChaPoly_SHA256",
        comptime Hs.protocolName(pattern.XX),
    );
    try std.testing.expectEqualStrings(
        "Noise_IKpsk2_25519_AESGCM_SHA512",
        comptime HandshakeState(Suite(crypto.X25519, crypto.AesGcm, crypto.Sha512))
            .protocolName(pattern.fromName("IKpsk2")),
    );
}

fn runWithKeys(comptime p: Pattern, psks: []const [32]u8) !void {
    var i_rng = CountingRng{ .next = 1 };
    var r_rng = CountingRng{ .next = 128 };
    const i_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const r_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    const i_knows_rs = comptime std.mem.indexOfScalar(Token, p.pre[1], .s) != null;
    const r_knows_rs = comptime std.mem.indexOfScalar(Token, p.pre[0], .s) != null;

    try run(p, .{
        .prologue = "prologue",
        .s = i_s,
        .rs = if (i_knows_rs) r_s.public else null,
        .psks = psks,
        .rng = i_rng.rng(),
    }, .{
        .prologue = "prologue",
        .s = r_s,
        .rs = if (r_knows_rs) i_s.public else null,
        .psks = psks,
        .rng = r_rng.rng(),
    });
}

test "every pattern in the spec completes" {
    inline for (pattern.all) |p| try runWithKeys(p, &.{});
}

test "psk patterns complete" {
    const psk: [32]u8 = @splat(42);
    inline for (.{ "Npsk0", "Xpsk1", "NNpsk0", "NNpsk2", "XXpsk3", "IKpsk1", "IKpsk2", "NKpsk0", "K1X1psk3" }) |name| {
        try runWithKeys(comptime pattern.fromName(name), &.{psk});
    }
}

test "XX transmits static keys" {
    var i_rng = CountingRng{ .next = 1 };
    var r_rng = CountingRng{ .next = 128 };
    const i_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const r_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    var initiator = try Hs.init(pattern.XX, .initiator, .{ .s = i_s, .rng = i_rng.rng() });
    var responder = try Hs.init(pattern.XX, .responder, .{ .s = r_s, .rng = r_rng.rng() });

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    try std.testing.expect(initiator.remoteStatic() == null);
    var n = try initiator.writeMessage("", &buf);
    _ = try responder.readMessage(buf[0..n], &plain);
    n = try responder.writeMessage("", &buf);
    _ = try initiator.readMessage(buf[0..n], &plain);
    try std.testing.expectEqual(r_s.public, initiator.remoteStatic().?);

    try std.testing.expect(responder.remoteStatic() == null);
    n = try initiator.writeMessage("", &buf);
    _ = try responder.readMessage(buf[0..n], &plain);
    try std.testing.expectEqual(i_s.public, responder.remoteStatic().?);
}

test "noise pipes: a rejected IK falls back to XXfallback" {
    var a_rng = CountingRng{ .next = 1 };
    var b_rng = CountingRng{ .next = 128 };
    const alice_s = crypto.X25519.KeyPair.fromSecret(@splat(11));
    const bob_s = crypto.X25519.KeyPair.fromSecret(@splat(22));
    const stale_s = crypto.X25519.KeyPair.fromSecret(@splat(33));

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    var alice_ik = try Hs.init(pattern.IK, .initiator, .{
        .s = alice_s,
        .rs = stale_s.public,
        .rng = a_rng.rng(),
    });
    var bob_ik = try Hs.init(pattern.IK, .responder, .{ .s = bob_s, .rng = b_rng.rng() });

    const n = try alice_ik.writeMessage("0-rtt", &buf);
    try std.testing.expectError(Error.AuthenticationFailed, bob_ik.readMessage(buf[0..n], &plain));

    const semi_ephemeral = buf[0..Hs.dhlen].*;
    try std.testing.expectEqual(alice_ik.e.?.public, semi_ephemeral);

    const fallback = pattern.XXfallback;
    var alice = try Hs.init(fallback, .initiator, .{
        .s = alice_s,
        .e = alice_ik.e.?,
        .rng = a_rng.rng(),
    });
    var bob = try Hs.init(fallback, .responder, .{
        .s = bob_s,
        .re = semi_ephemeral,
        .rng = b_rng.rng(),
    });

    try std.testing.expect(bob.isMyTurn());
    try std.testing.expect(!alice.isMyTurn());

    while (!alice.isFinished()) {
        const writer, const reader = if (alice.isMyTurn())
            .{ &alice, &bob }
        else
            .{ &bob, &alice };
        const len = try writer.writeMessage("fallback", &buf);
        const got = try reader.readMessage(buf[0..len], &plain);
        try std.testing.expectEqualStrings("fallback", plain[0..got]);
    }

    try std.testing.expectEqual(alice.handshakeHash(), bob.handshakeHash());
    try std.testing.expectEqual(bob_s.public, alice.remoteStatic().?);
    try std.testing.expectEqual(alice_s.public, bob.remoteStatic().?);

    const a_keys = try alice.split();
    const b_keys = try bob.split();
    try std.testing.expectEqual(a_keys.send.k, b_keys.recv.k);
    try std.testing.expectEqual(a_keys.recv.k, b_keys.send.k);
}

test "unordered transport survives reordering end to end" {
    var i_rng = CountingRng{ .next = 1 };
    var r_rng = CountingRng{ .next = 128 };

    var initiator = try Hs.init(pattern.NN, .initiator, .{ .rng = i_rng.rng() });
    var responder = try Hs.init(pattern.NN, .responder, .{ .rng = r_rng.rng() });

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    var n = try initiator.writeMessage("", &buf);
    _ = try responder.readMessage(buf[0..n], &plain);
    n = try responder.writeMessage("", &buf);
    _ = try initiator.readMessage(buf[0..n], &plain);

    var tx = try initiator.splitUnordered(2);
    var rx = try responder.splitUnordered(2);

    var frames: [3]struct { nonce: u64, buf: [4 + Hs.tag_len]u8, len: usize } = undefined;
    for (&frames) |*f| {
        var out: [4 + Hs.tag_len]u8 = undefined;
        const sealed = try tx.send.encrypt("", "ping", &out);
        f.* = .{ .nonce = sealed.nonce, .buf = out, .len = sealed.len };
    }

    var pt: [4]u8 = undefined;
    for ([_]usize{ 2, 0, 1 }) |i| {
        const got = try rx.recv.decrypt(frames[i].nonce, "", frames[i].buf[0..frames[i].len], &pt);
        try std.testing.expectEqualStrings("ping", pt[0..got]);
    }
    try std.testing.expectError(
        state.Error.ReplayedNonce,
        rx.recv.decrypt(frames[0].nonce, "", frames[0].buf[0..frames[0].len], &pt),
    );

    initiator.clear();
    responder.clear();
    try std.testing.expect(!initiator.ss.cs.hasKey());
}

test "half-duplex shares one cipherstate in both directions" {
    var i_rng = CountingRng{ .next = 1 };
    var r_rng = CountingRng{ .next = 128 };

    var initiator = try Hs.init(pattern.NN, .initiator, .{ .rng = i_rng.rng() });
    var responder = try Hs.init(pattern.NN, .responder, .{ .rng = r_rng.rng() });

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    var n = try initiator.writeMessage("", &buf);
    _ = try responder.readMessage(buf[0..n], &plain);
    n = try responder.writeMessage("", &buf);
    _ = try initiator.readMessage(buf[0..n], &plain);

    var a = try initiator.splitHalfDuplex();
    var b = try responder.splitHalfDuplex();
    try std.testing.expectEqual(a.cs.k, b.cs.k);

    // Both sides advance the same nonce sequence, so strict alternation
    // keeps them in lockstep.
    var ct: [4 + Hs.tag_len]u8 = undefined;
    var pt: [4]u8 = undefined;
    for (0..4) |i| {
        const sender, const receiver = if (i % 2 == 0) .{ &a, &b } else .{ &b, &a };
        _ = try sender.encrypt("", "ping", &ct);
        const got = try receiver.decrypt("", &ct, &pt);
        try std.testing.expectEqualStrings("ping", pt[0..got]);
        try std.testing.expectEqual(@as(u64, i + 1), a.cs.n);
        try std.testing.expectEqual(@as(u64, i + 1), b.cs.n);
    }
}

test "half-duplex rejects a broken turn order" {
    var i_rng = CountingRng{ .next = 1 };
    var r_rng = CountingRng{ .next = 128 };

    var initiator = try Hs.init(pattern.NN, .initiator, .{ .rng = i_rng.rng() });
    var responder = try Hs.init(pattern.NN, .responder, .{ .rng = r_rng.rng() });

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    var n = try initiator.writeMessage("", &buf);
    _ = try responder.readMessage(buf[0..n], &plain);
    n = try responder.writeMessage("", &buf);
    _ = try initiator.readMessage(buf[0..n], &plain);

    var a = try initiator.splitHalfDuplex();
    var b = try responder.splitHalfDuplex();

    var ct: [4 + Hs.tag_len]u8 = undefined;
    var pt: [4]u8 = undefined;
    _ = try a.encrypt("", "ping", &ct);
    try std.testing.expectError(state.Error.TurnViolation, a.encrypt("", "ping", &ct));
    try std.testing.expectEqual(@as(u64, 1), a.cs.n);

    _ = try b.decrypt("", &ct, &pt);
    try std.testing.expectError(state.Error.TurnViolation, b.decrypt("", &ct, &pt));
}

test "one-way patterns discard the second cipherstate" {
    var i_rng = CountingRng{ .next = 1 };
    const r_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    var sender = try Hs.init(pattern.N, .initiator, .{ .rs = r_s.public, .rng = i_rng.rng() });
    var recipient = try Hs.init(pattern.N, .responder, .{ .s = r_s });

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const n = try sender.writeMessage("one-way", &buf);
    const got = try recipient.readMessage(buf[0..n], &plain);
    try std.testing.expectEqualStrings("one-way", plain[0..got]);

    var tx = try sender.split();
    var rx = try recipient.split();

    var ct: [4 + Hs.tag_len]u8 = undefined;
    var pt: [4]u8 = undefined;
    _ = try tx.send.encryptWithAd("", "data", &ct);
    const back = try rx.recv.decryptWithAd("", &ct, &pt);
    try std.testing.expectEqualStrings("data", pt[0..back]);

    // Section 7.4: the recipient must not send, and the sender never receives.
    try std.testing.expectError(state.Error.CipherStateCleared, rx.send.encryptWithAd("", "no", &ct));
    try std.testing.expectError(state.Error.CipherStateCleared, tx.recv.decryptWithAd("", &ct, &pt));
}

test "out of turn and premature split are rejected" {
    var rng = CountingRng{};
    var initiator = try Hs.init(pattern.NN, .initiator, .{ .rng = rng.rng() });
    var buf: [256]u8 = undefined;

    try std.testing.expectError(Error.OutOfTurn, initiator.readMessage(&buf, &buf));
    try std.testing.expectError(Error.HandshakeUnfinished, initiator.split());
    _ = try initiator.writeMessage("", &buf);
    try std.testing.expectError(Error.OutOfTurn, initiator.writeMessage("", &buf));
}

test "a tampered handshake message fails to authenticate" {
    var i_rng = CountingRng{ .next = 1 };
    var r_rng = CountingRng{ .next = 128 };
    const r_s = crypto.X25519.KeyPair.fromSecret(@splat(22));

    var initiator = try Hs.init(pattern.NK, .initiator, .{ .rs = r_s.public, .rng = i_rng.rng() });
    var responder = try Hs.init(pattern.NK, .responder, .{ .s = r_s, .rng = r_rng.rng() });

    var buf: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const n = try initiator.writeMessage("secret", &buf);
    buf[n - 1] ^= 0xff;
    try std.testing.expectError(Error.AuthenticationFailed, responder.readMessage(buf[0..n], &plain));
}

test "a missing psk is reported" {
    var rng = CountingRng{};
    var initiator = try Hs.init(comptime pattern.fromName("NNpsk0"), .initiator, .{ .rng = rng.rng() });
    var buf: [256]u8 = undefined;
    try std.testing.expectError(Error.MissingPsk, initiator.writeMessage("", &buf));
}
