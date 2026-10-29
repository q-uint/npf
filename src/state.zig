const std = @import("std");

pub const MessageLen = u16;
pub const max_message_len = std.math.maxInt(MessageLen);

pub const Error = error{
    NonceExhausted,
    BufferTooSmall,
    MessageTooShort,
    MessageTooLong,
    AuthenticationFailed,
    ReplayedNonce,
    TurnViolation,
    CipherStateCleared,
    MissingKey,
};

pub fn CipherState(comptime C: type) type {
    return struct {
        const Self = @This();

        pub const Cipher = C;
        pub const max_nonce = std.math.maxInt(u64);

        k: ?[C.key_len]u8 = null,
        n: u64 = 0,
        cleared: bool = false,

        pub fn init(key: [C.key_len]u8) Self {
            return .{ .k = key, .n = 0 };
        }

        pub fn hasKey(self: Self) bool {
            return self.k != null;
        }

        pub fn setNonce(self: *Self, n: u64) void {
            self.n = n;
        }

        pub fn encryptWithAd(self: *Self, ad: []const u8, pt: []const u8, out: []u8) Error!usize {
            if (self.cleared) return Error.CipherStateCleared;
            const k = self.k orelse {
                if (out.len < pt.len) return Error.BufferTooSmall;
                @memcpy(out[0..pt.len], pt);
                return pt.len;
            };
            if (self.n == max_nonce) return Error.NonceExhausted;
            const len = pt.len + C.tag_len;
            if (len > max_message_len) return Error.MessageTooLong;
            if (out.len < len) return Error.BufferTooSmall;
            C.encrypt(k, self.n, ad, pt, out[0..len]);
            self.n += 1;
            return len;
        }

        pub fn decryptWithAd(self: *Self, ad: []const u8, ct: []const u8, out: []u8) Error!usize {
            if (self.cleared) return Error.CipherStateCleared;
            const k = self.k orelse {
                if (out.len < ct.len) return Error.BufferTooSmall;
                @memcpy(out[0..ct.len], ct);
                return ct.len;
            };
            if (self.n == max_nonce) return Error.NonceExhausted;
            if (ct.len > max_message_len) return Error.MessageTooLong;
            if (ct.len < C.tag_len) return Error.MessageTooShort;
            const len = ct.len - C.tag_len;
            if (out.len < len) return Error.BufferTooSmall;
            try C.decrypt(k, self.n, ad, ct, out[0..len]);
            self.n += 1;
            return len;
        }

        /// Section 11.3 only defines Rekey for a CipherState that has a key.
        pub fn rekey(self: *Self) Error!void {
            if (self.cleared) return Error.CipherStateCleared;
            const k = self.k orelse return Error.MissingKey;
            self.k = C.rekey(k);
        }

        /// Wipes the key material.
        pub fn clear(self: *Self) void {
            if (self.k) |*key| std.crypto.secureZero(u8, key);
            self.k = null;
            self.n = 0;
            self.cleared = true;
        }
    };
}

/// Sliding-window replay filter for section 11.4. Tracks which nonces have
/// already been accepted so a repeat can be rejected.
pub fn ReplayWindow(comptime words: usize) type {
    return struct {
        const Self = @This();

        pub const size = words * 64;

        latest: u64 = 0,
        started: bool = false,
        bits: [words]u64 = @splat(0),

        fn isSet(self: Self, delta: u64) bool {
            const word = delta / 64;
            const bit: u6 = @intCast(delta % 64);
            return (self.bits[word] >> bit) & 1 == 1;
        }

        fn set(self: *Self, delta: u64) void {
            const word = delta / 64;
            const bit: u6 = @intCast(delta % 64);
            self.bits[word] |= @as(u64, 1) << bit;
        }

        fn shift(self: *Self, by: u64) void {
            if (by >= size) {
                self.bits = @splat(0);
                return;
            }
            const word_shift: usize = @intCast(by / 64);
            const bit_shift: u6 = @intCast(by % 64);
            var i: usize = words;
            while (i > 0) {
                i -= 1;
                var value: u64 = 0;
                if (i >= word_shift) {
                    value = self.bits[i - word_shift] << bit_shift;
                    if (bit_shift != 0 and i > word_shift) {
                        value |= self.bits[i - word_shift - 1] >> @intCast(64 - @as(u7, bit_shift));
                    }
                }
                self.bits[i] = value;
            }
        }

        /// True if `n` has not been accepted before and is not older than the window.
        pub fn check(self: Self, n: u64) bool {
            if (!self.started) return true;
            if (n > self.latest) return true;
            const delta = self.latest - n;
            if (delta >= size) return false;
            return !self.isSet(delta);
        }

        /// Record `n` as accepted. Only call after a message authenticates.
        pub fn accept(self: *Self, n: u64) void {
            if (!self.started) {
                self.started = true;
                self.latest = n;
                self.set(0);
                return;
            }
            if (n > self.latest) {
                self.shift(n - self.latest);
                self.latest = n;
                self.set(0);
            } else {
                self.set(self.latest - n);
            }
        }
    };
}

/// A single CipherState shared in both directions (section 11.5).
///
/// Under strict alternation each party's operations must alternate encrypt,
/// decrypt, encrypt, decrypt. This type rejects a local double-encrypt or
/// double-decrypt with `TurnViolation`.
///
/// That is a backstop, not a guarantee. It cannot see the peer, so it cannot
/// catch the case where both parties encrypt as their very first operation.
/// Only the application protocol can rule that out, by defining which side
/// sends first. If it cannot, use `split` instead and pay for two keys.
pub fn HalfDuplexCipherState(comptime C: type) type {
    return struct {
        const Self = @This();

        pub const Cs = CipherState(C);

        cs: Cs,
        last: enum { none, encrypted, decrypted } = .none,

        pub fn init(cs: Cs) Self {
            return .{ .cs = cs };
        }

        pub fn encrypt(self: *Self, ad: []const u8, pt: []const u8, out: []u8) Error!usize {
            if (self.last == .encrypted) return Error.TurnViolation;
            const len = try self.cs.encryptWithAd(ad, pt, out);
            self.last = .encrypted;
            return len;
        }

        pub fn decrypt(self: *Self, ad: []const u8, ct: []const u8, out: []u8) Error!usize {
            if (self.last == .decrypted) return Error.TurnViolation;
            const len = try self.cs.decryptWithAd(ad, ct, out);
            self.last = .decrypted;
            return len;
        }

        pub fn clear(self: *Self) void {
            self.cs.clear();
            self.last = .none;
        }
    };
}

pub const Sealed = struct {
    nonce: u64,
    len: usize,
};

/// Sending half of a transport for lossy or reordered delivery (section
/// 11.4). The nonce travels alongside each message.
///
/// Deliberately separate from `UnorderedReceiver`. A receiver has to set its
/// nonce to whatever a peer claims, so letting one CipherState do both
/// directions would mean encrypting under an attacker-chosen nonce.
pub fn UnorderedSender(comptime C: type) type {
    return struct {
        const Self = @This();

        pub const Cs = CipherState(C);

        cs: Cs,

        pub fn init(cs: Cs) Self {
            return .{ .cs = cs };
        }

        /// Encrypts with the next nonce and reports which nonce was used, so
        /// the application can send it alongside the ciphertext.
        pub fn encrypt(self: *Self, ad: []const u8, pt: []const u8, out: []u8) Error!Sealed {
            const nonce = self.cs.n;
            const len = try self.cs.encryptWithAd(ad, pt, out);
            return .{ .nonce = nonce, .len = len };
        }

        pub fn clear(self: *Self) void {
            self.cs.clear();
        }
    };
}

/// Receiving half of a transport for lossy or reordered delivery (section
/// 11.4). Rejects any nonce already accepted, or older than the window.
pub fn UnorderedReceiver(comptime C: type, comptime window_words: usize) type {
    return struct {
        const Self = @This();

        pub const Cs = CipherState(C);
        pub const Window = ReplayWindow(window_words);

        /// Scratch. Reset before every decrypt from the peer's claimed
        /// nonce, so it carries no meaning between calls and is never used
        /// to encrypt.
        cs: Cs,
        window: Window = .{},

        pub fn init(cs: Cs) Self {
            return .{ .cs = cs };
        }

        /// Decrypts a message received with nonce `n`. The nonce is recorded
        /// only once the message authenticates, so forgeries cannot consume
        /// window slots.
        pub fn decrypt(self: *Self, n: u64, ad: []const u8, ct: []const u8, out: []u8) Error!usize {
            if (!self.window.check(n)) return Error.ReplayedNonce;
            self.cs.setNonce(n);
            const len = try self.cs.decryptWithAd(ad, ct, out);
            self.window.accept(n);
            return len;
        }

        pub fn clear(self: *Self) void {
            self.cs.clear();
            self.window = .{};
        }
    };
}

pub fn SymmetricState(comptime C: type, comptime H: type) type {
    return struct {
        const Self = @This();

        pub const Cipher = C;
        pub const Hash = H;
        pub const Digest = H.Digest;
        pub const Cs = CipherState(C);

        cs: Cs,
        ck: Digest,
        h: Digest,

        pub fn init(protocol_name: []const u8) Self {
            var h: Digest = @splat(0);
            if (protocol_name.len <= H.hashlen) {
                @memcpy(h[0..protocol_name.len], protocol_name);
            } else {
                h = H.hash(protocol_name);
            }
            return .{ .cs = .{}, .ck = h, .h = h };
        }

        fn key(d: Digest) [C.key_len]u8 {
            return d[0..C.key_len].*;
        }

        fn wipeDerived(out: anytype) void {
            for (out) |*d| std.crypto.secureZero(u8, d);
        }

        pub fn mixKey(self: *Self, ikm: []const u8) void {
            var out = H.hkdf(self.ck, ikm, 2);
            defer wipeDerived(&out);
            self.ck = out[0];
            self.cs = Cs.init(key(out[1]));
        }

        pub fn mixHash(self: *Self, data: []const u8) void {
            self.h = H.hashCat(&self.h, data);
        }

        pub fn mixKeyAndHash(self: *Self, ikm: []const u8) void {
            var out = H.hkdf(self.ck, ikm, 3);
            defer wipeDerived(&out);
            self.ck = out[0];
            self.mixHash(&out[1]);
            self.cs = Cs.init(key(out[2]));
        }

        pub fn handshakeHash(self: Self) Digest {
            return self.h;
        }

        pub fn encryptAndHash(self: *Self, pt: []const u8, out: []u8) Error!usize {
            const len = try self.cs.encryptWithAd(&self.h, pt, out);
            self.mixHash(out[0..len]);
            return len;
        }

        pub fn decryptAndHash(self: *Self, ct: []const u8, out: []u8) Error!usize {
            const len = try self.cs.decryptWithAd(&self.h, ct, out);
            self.mixHash(ct);
            return len;
        }

        pub fn split(self: *Self) [2]Cs {
            var out = H.hkdf(self.ck, &.{}, 2);
            defer wipeDerived(&out);
            return .{ Cs.init(key(out[0])), Cs.init(key(out[1])) };
        }

        /// Wipes the chaining key and cipher key. `h` is not secret.
        pub fn clear(self: *Self) void {
            std.crypto.secureZero(u8, &self.ck);
            self.cs.clear();
        }
    };
}

const crypto = @import("crypto.zig");
const TestCs = CipherState(crypto.ChaChaPoly);
const TestSs = SymmetricState(crypto.ChaChaPoly, crypto.Sha256);

test "cipherstate without key is a passthrough" {
    var cs = TestCs{};
    var out: [5]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 5), try cs.encryptWithAd("ad", "hello", &out));
    try std.testing.expectEqualStrings("hello", &out);
    try std.testing.expectEqual(@as(u64, 0), cs.n);
}

test "cipherstate round trip advances the nonce" {
    var tx = TestCs.init(@splat(9));
    var rx = TestCs.init(@splat(9));
    var ct: [5 + crypto.ChaChaPoly.tag_len]u8 = undefined;
    var pt: [5]u8 = undefined;
    for (0..3) |i| {
        _ = try tx.encryptWithAd("ad", "hello", &ct);
        _ = try rx.decryptWithAd("ad", &ct, &pt);
        try std.testing.expectEqualStrings("hello", &pt);
        try std.testing.expectEqual(@as(u64, i + 1), rx.n);
    }
    rx.setNonce(0);
    try std.testing.expectError(Error.AuthenticationFailed, rx.decryptWithAd("ad", &ct, &pt));
}

test "cipherstate rekey needs a key and survives being cleared" {
    var cs = TestCs.init(@splat(9));
    const before = cs.k.?;
    try cs.rekey();
    try std.testing.expect(!std.mem.eql(u8, &before, &cs.k.?));

    var fresh = TestCs{};
    try std.testing.expectError(Error.MissingKey, fresh.rekey());

    cs.clear();
    try std.testing.expectError(Error.CipherStateCleared, cs.rekey());
}

test "cipherstate rejects an exhausted nonce" {
    var cs = TestCs.init(@splat(1));
    cs.setNonce(TestCs.max_nonce);
    var out: [21]u8 = undefined;
    try std.testing.expectError(Error.NonceExhausted, cs.encryptWithAd("", "hello", &out));
}

test "a cleared cipherstate does not fall back to passthrough" {
    var cs = TestCs.init(@splat(1));
    cs.clear();
    var out: [32]u8 = undefined;
    try std.testing.expect(!cs.hasKey());
    try std.testing.expectError(Error.CipherStateCleared, cs.encryptWithAd("", "hello", &out));
    try std.testing.expectError(Error.CipherStateCleared, cs.decryptWithAd("", "hello", &out));
}

test "cipherstate reports a short buffer" {
    var cs = TestCs.init(@splat(1));
    var out: [5]u8 = undefined;
    try std.testing.expectError(Error.BufferTooSmall, cs.encryptWithAd("", "hello", &out));
    try std.testing.expectError(Error.MessageTooShort, cs.decryptWithAd("", "hi", &out));
}

test "symmetricstate seeds h from a short protocol name" {
    const name = "Noise_XX_25519_ChaChaPoly_SHA256";
    const ss = TestSs.init(name);
    try std.testing.expectEqual(@as(usize, 32), name.len);
    try std.testing.expectEqualStrings(name, &ss.h);
    try std.testing.expectEqual(ss.h, ss.ck);
    try std.testing.expect(!ss.cs.hasKey());
}

test "symmetricstate hashes a long protocol name" {
    const name = "Noise_XXfallback+psk0_25519_ChaChaPoly_BLAKE2s_padding";
    const ss = SymmetricState(crypto.ChaChaPoly, crypto.Blake2s).init(name);
    try std.testing.expect(name.len > 32);
    try std.testing.expectEqual(crypto.Blake2s.hash(name), ss.h);
}

test "symmetricstate mirrors across two peers" {
    var a = TestSs.init("Noise_NN_25519_ChaChaPoly_SHA256");
    var b = TestSs.init("Noise_NN_25519_ChaChaPoly_SHA256");

    a.mixHash("prologue");
    b.mixHash("prologue");
    try std.testing.expectEqual(a.h, b.h);

    a.mixKey("shared-secret");
    b.mixKey("shared-secret");
    try std.testing.expect(a.cs.hasKey());

    a.mixKeyAndHash("psk");
    b.mixKeyAndHash("psk");
    try std.testing.expectEqual(a.ck, b.ck);
    try std.testing.expectEqual(a.h, b.h);

    var ct: [7 + crypto.ChaChaPoly.tag_len]u8 = undefined;
    var pt: [7]u8 = undefined;
    const n = try a.encryptAndHash("payload", &ct);
    try std.testing.expectEqual(@as(usize, 7), try b.decryptAndHash(ct[0..n], &pt));
    try std.testing.expectEqualStrings("payload", &pt);
    try std.testing.expectEqual(a.handshakeHash(), b.handshakeHash());

    const ka = a.split();
    const kb = b.split();
    try std.testing.expectEqual(ka[0].k, kb[0].k);
    try std.testing.expectEqual(ka[1].k, kb[1].k);
    try std.testing.expect(!std.mem.eql(u8, &ka[0].k.?, &ka[1].k.?));
}

const TestWindow = ReplayWindow(4);

test "replay window accepts fresh nonces in order" {
    var w = TestWindow{};
    for (0..200) |i| {
        try std.testing.expect(w.check(i));
        w.accept(i);
        try std.testing.expect(!w.check(i));
    }
}

test "replay window accepts out-of-order nonces once each" {
    var w = TestWindow{};
    for ([_]u64{ 5, 3, 9, 1, 7 }) |n| {
        try std.testing.expect(w.check(n));
        w.accept(n);
    }
    for ([_]u64{ 1, 3, 5, 7, 9 }) |n| {
        try std.testing.expect(!w.check(n));
    }
    for ([_]u64{ 0, 2, 4, 6, 8, 10 }) |n| {
        try std.testing.expect(w.check(n));
    }
}

test "replay window rejects nonces older than the window" {
    var w = TestWindow{};
    w.accept(0);
    w.accept(TestWindow.size);
    try std.testing.expect(!w.check(0));
    try std.testing.expect(w.check(1));
    try std.testing.expect(!w.check(TestWindow.size));

    w.accept(TestWindow.size * 4);
    try std.testing.expect(!w.check(1));
    try std.testing.expect(!w.check(TestWindow.size));
    try std.testing.expect(w.check(TestWindow.size * 4 - 1));
}

test "replay window survives a word-aligned shift" {
    var w = TestWindow{};
    w.accept(0);
    w.accept(64);
    w.accept(128);
    try std.testing.expect(!w.check(0));
    try std.testing.expect(!w.check(64));
    try std.testing.expect(!w.check(128));
    try std.testing.expect(w.check(63));
}

const TestSender = UnorderedSender(crypto.ChaChaPoly);
const TestReceiver = UnorderedReceiver(crypto.ChaChaPoly, 4);

test "out-of-order transport rejects replays but allows reordering" {
    const key: [32]u8 = @splat(5);
    var tx = TestSender.init(TestCs.init(key));
    var rx = TestReceiver.init(TestCs.init(key));

    var frames: [4]struct { nonce: u64, buf: [5 + crypto.ChaChaPoly.tag_len]u8, len: usize } = undefined;
    for (&frames, 0..) |*f, i| {
        _ = i;
        var buf: [5 + crypto.ChaChaPoly.tag_len]u8 = undefined;
        const sealed = try tx.encrypt("ad", "hello", &buf);
        f.* = .{ .nonce = sealed.nonce, .buf = buf, .len = sealed.len };
    }
    try std.testing.expectEqual(@as(u64, 0), frames[0].nonce);
    try std.testing.expectEqual(@as(u64, 3), frames[3].nonce);

    var pt: [5]u8 = undefined;
    for ([_]usize{ 2, 0, 3, 1 }) |i| {
        const got = try rx.decrypt(frames[i].nonce, "ad", frames[i].buf[0..frames[i].len], &pt);
        try std.testing.expectEqualStrings("hello", pt[0..got]);
    }

    for (frames) |f| {
        try std.testing.expectError(
            Error.ReplayedNonce,
            rx.decrypt(f.nonce, "ad", f.buf[0..f.len], &pt),
        );
    }
}

test "a forged message does not consume its nonce" {
    const key: [32]u8 = @splat(5);
    var tx = TestSender.init(TestCs.init(key));
    var rx = TestReceiver.init(TestCs.init(key));

    var buf: [5 + crypto.ChaChaPoly.tag_len]u8 = undefined;
    const sealed = try tx.encrypt("ad", "hello", &buf);

    var tampered = buf;
    tampered[0] ^= 0xff;
    var pt: [5]u8 = undefined;
    try std.testing.expectError(
        Error.AuthenticationFailed,
        rx.decrypt(sealed.nonce, "ad", tampered[0..sealed.len], &pt),
    );

    const got = try rx.decrypt(sealed.nonce, "ad", buf[0..sealed.len], &pt);
    try std.testing.expectEqualStrings("hello", pt[0..got]);
}

test "symmetricstate with sha512 truncates the cipher key" {
    var ss = SymmetricState(crypto.ChaChaPoly, crypto.Sha512).init("Noise_NN_25519_ChaChaPoly_SHA512");
    ss.mixKey("ikm");
    try std.testing.expectEqual(@as(usize, 32), ss.cs.k.?.len);
    try std.testing.expectEqual(@as(usize, 64), ss.ck.len);
}
