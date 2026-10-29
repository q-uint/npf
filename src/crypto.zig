const std = @import("std");

pub const X25519 = struct {
    pub const name = "25519";
    pub const dhlen = 32;

    const Impl = std.crypto.dh.X25519;

    pub const KeyPair = struct {
        public: [dhlen]u8,
        secret: [dhlen]u8,

        pub fn fromSecret(secret: [dhlen]u8) KeyPair {
            var kp = Impl.KeyPair.generateDeterministic(secret);
            defer std.crypto.secureZero(u8, &kp.secret_key);
            return .{ .public = kp.public_key, .secret = kp.secret_key };
        }

        pub fn generate(io: std.Io) KeyPair {
            var seed: [dhlen]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            io.random(&seed);
            return fromSecret(seed);
        }
    };

    pub fn dh(kp: KeyPair, pk: [dhlen]u8) [dhlen]u8 {
        return Impl.scalarmult(kp.secret, pk) catch @splat(0);
    }
};

pub const X448 = @import("x448.zig").X448;

test {
    _ = @import("x448.zig");
}

fn AeadCipher(comptime Impl: type, comptime cipher_name: []const u8, comptime endian: std.builtin.Endian) type {
    return struct {
        const Self = @This();

        pub const name = cipher_name;
        pub const key_len = Impl.key_length;
        pub const tag_len = Impl.tag_length;

        comptime {
            std.debug.assert(Impl.nonce_length == 12);
        }

        fn nonce(n: u64) [Impl.nonce_length]u8 {
            var out: [Impl.nonce_length]u8 = @splat(0);
            std.mem.writeInt(u64, out[4..12], n, endian);
            return out;
        }

        pub fn encrypt(k: [key_len]u8, n: u64, ad: []const u8, pt: []const u8, out: []u8) void {
            std.debug.assert(out.len == pt.len + tag_len);
            Impl.encrypt(out[0..pt.len], out[pt.len..][0..tag_len], pt, ad, nonce(n), k);
        }

        pub fn decrypt(k: [key_len]u8, n: u64, ad: []const u8, ct: []const u8, out: []u8) error{AuthenticationFailed}!void {
            std.debug.assert(ct.len >= tag_len);
            std.debug.assert(out.len == ct.len - tag_len);
            const body = ct[0 .. ct.len - tag_len];
            const tag = ct[body.len..][0..tag_len].*;
            Impl.decrypt(out, body, tag, ad, nonce(n), k) catch return error.AuthenticationFailed;
        }

        pub fn rekey(k: [key_len]u8) [key_len]u8 {
            const zeros: [key_len]u8 = @splat(0);
            var buf: [key_len + tag_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &buf);
            Self.encrypt(k, std.math.maxInt(u64), &.{}, &zeros, &buf);
            return buf[0..key_len].*;
        }
    };
}

pub const ChaChaPoly = AeadCipher(std.crypto.aead.chacha_poly.ChaCha20Poly1305, "ChaChaPoly", .little);
pub const AesGcm = AeadCipher(std.crypto.aead.aes_gcm.Aes256Gcm, "AESGCM", .big);

fn HashFns(comptime Impl: type, comptime hash_name: []const u8) type {
    return struct {
        const Self = @This();

        pub const name = hash_name;
        pub const hashlen = Impl.digest_length;
        pub const blocklen = Impl.block_length;
        pub const Digest = [hashlen]u8;
        pub const Hmac = std.crypto.auth.hmac.Hmac(Impl);

        pub fn hash(data: []const u8) Digest {
            var out: Digest = undefined;
            Impl.hash(data, &out, .{});
            return out;
        }

        pub fn hashCat(a: []const u8, b: []const u8) Digest {
            var st = Impl.init(.{});
            st.update(a);
            st.update(b);
            var out: Digest = undefined;
            st.final(&out);
            return out;
        }

        pub fn hmac(key: Digest, data: []const u8) Digest {
            var out: Digest = undefined;
            Hmac.create(&out, data, &key);
            return out;
        }

        pub fn hkdf(ck: Digest, ikm: []const u8, comptime outputs: usize) [outputs]Digest {
            comptime std.debug.assert(outputs >= 1 and outputs <= 3);
            var temp = Self.hmac(ck, ikm);
            defer std.crypto.secureZero(u8, &temp);
            var out: [outputs]Digest = undefined;
            inline for (0..outputs) |i| {
                var st = Hmac.init(&temp);
                if (i > 0) st.update(&out[i - 1]);
                st.update(&[_]u8{i + 1});
                st.final(&out[i]);
            }
            return out;
        }
    };
}

/// Resolves a section 8.2 algorithm name to its implementation.
pub fn dhByName(comptime n: []const u8) type {
    inline for (.{ X25519, X448 }) |D| {
        if (comptime std.mem.eql(u8, n, D.name)) return D;
    }
    @compileError("unknown DH function: " ++ n);
}

pub fn cipherByName(comptime n: []const u8) type {
    inline for (.{ ChaChaPoly, AesGcm }) |C| {
        if (comptime std.mem.eql(u8, n, C.name)) return C;
    }
    @compileError("unknown cipher function: " ++ n);
}

pub fn hashByName(comptime n: []const u8) type {
    inline for (.{ Sha256, Sha512, Blake2s, Blake2b }) |H| {
        if (comptime std.mem.eql(u8, n, H.name)) return H;
    }
    @compileError("unknown hash function: " ++ n);
}

pub const Sha256 = HashFns(std.crypto.hash.sha2.Sha256, "SHA256");
pub const Sha512 = HashFns(std.crypto.hash.sha2.Sha512, "SHA512");
pub const Blake2s = HashFns(std.crypto.hash.blake2.Blake2s256, "BLAKE2s");
pub const Blake2b = HashFns(std.crypto.hash.blake2.Blake2b512, "BLAKE2b");

test "dh is symmetric" {
    const a = X25519.KeyPair.fromSecret(@splat(1));
    const b = X25519.KeyPair.fromSecret(@splat(2));
    try std.testing.expectEqual(X25519.dh(a, b.public), X25519.dh(b, a.public));
}

test "dh on low-order point yields zeros" {
    const a = X25519.KeyPair.fromSecret(@splat(1));
    const zeros: [X25519.dhlen]u8 = @splat(0);
    try std.testing.expectEqual(zeros, X25519.dh(a, @splat(0)));
}

test "aead round trip" {
    inline for (.{ ChaChaPoly, AesGcm }) |C| {
        const k: [C.key_len]u8 = @splat(7);
        const pt = "noise";
        var ct: [pt.len + C.tag_len]u8 = undefined;
        var out: [pt.len]u8 = undefined;
        C.encrypt(k, 42, "ad", pt, &ct);
        try C.decrypt(k, 42, "ad", &ct, &out);
        try std.testing.expectEqualStrings(pt, &out);
        try std.testing.expectError(error.AuthenticationFailed, C.decrypt(k, 43, "ad", &ct, &out));
        try std.testing.expect(!std.mem.eql(u8, &k, &C.rekey(k)));
    }
}

test "hkdf outputs are distinct and deterministic" {
    inline for (.{ Sha256, Sha512, Blake2s, Blake2b }) |H| {
        const ck: H.Digest = @splat(3);
        const a = H.hkdf(ck, "ikm", 3);
        const b = H.hkdf(ck, "ikm", 3);
        try std.testing.expectEqual(a, b);
        try std.testing.expect(!std.mem.eql(u8, &a[0], &a[1]));
        try std.testing.expect(!std.mem.eql(u8, &a[1], &a[2]));
        try std.testing.expectEqual(a[0], H.hkdf(ck, "ikm", 2)[0]);
        try std.testing.expectEqual(a[1], H.hkdf(ck, "ikm", 2)[1]);
        try std.testing.expectEqual(H.hash("ab"), H.hashCat("a", "b"));
    }
}
