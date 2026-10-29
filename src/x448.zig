const std = @import("std");
const builtin = @import("builtin");

const fiat = if (builtin.target.ptrBitWidth() >= 64)
    @import("fiat/p448_solinas_64.zig")
else
    @import("fiat/p448_solinas_32.zig");

pub const X448 = struct {
    pub const name = "448";
    pub const dhlen = 56;

    const Tight = fiat.TightFieldElement;
    const Loose = fiat.LooseFieldElement;

    const zero: Tight = @splat(0);
    const one: Tight = blk: {
        var out: Tight = @splat(0);
        out[0] = 1;
        break :blk out;
    };
    const a24: Loose = blk: {
        var out: Loose = @splat(0);
        out[0] = 39081;
        break :blk out;
    };

    const base_u: [dhlen]u8 = blk: {
        var out: [dhlen]u8 = @splat(0);
        out[0] = 5;
        break :blk out;
    };

    /// p - d as little-endian bytes, where p = 2^448 - 2^224 - 1. The high half
    /// is 2^224 - 2, so byte 28 is 0xfe and every other byte is 0xff. Only
    /// d <= 0xfd is supported, since a larger d would borrow out of byte 0.
    fn pMinus(comptime d: u8) [dhlen]u8 {
        var out: [dhlen]u8 = @splat(0xff);
        out[28] = 0xfe;
        out[0] -= d;
        return out;
    }

    fn mul(a: Loose, b: Loose) Tight {
        var out: Tight = undefined;
        fiat.carryMul(&out, a, b);
        return out;
    }

    fn sq(a: Loose) Tight {
        var out: Tight = undefined;
        fiat.carrySquare(&out, a);
        return out;
    }

    fn add(a: Tight, b: Tight) Loose {
        var out: Loose = undefined;
        fiat.add(&out, a, b);
        return out;
    }

    fn sub(a: Tight, b: Tight) Loose {
        var out: Loose = undefined;
        fiat.sub(&out, a, b);
        return out;
    }

    fn relax(a: Tight) Loose {
        var out: Loose = undefined;
        fiat.relax(&out, a);
        return out;
    }

    fn cswap(swap: u1, a: *Tight, b: *Tight) void {
        var na: Tight = undefined;
        var nb: Tight = undefined;
        fiat.selectznz(&na, swap, a.*, b.*);
        fiat.selectznz(&nb, swap, b.*, a.*);
        a.* = na;
        b.* = nb;
    }

    /// a^(2^n), by squaring n times.
    fn sqn(a: Tight, n: usize) Tight {
        var out = a;
        for (0..n) |_| out = sq(relax(out));
        return out;
    }

    /// z^(p-2) == z^-1 for z != 0, and 0 for z == 0. Fermat inversion over an
    /// addition chain, with the runs of ones built by Itoh-Tsujii doubling.
    ///
    /// Written MSB first, p - 2 is 223 ones, a zero, 222 ones, a zero, then a
    /// one. So the chain builds `xN` = z^(2^N - 1) up to N = 223, doubling the
    /// run length where it can, then shifts each run into place:
    ///
    ///   x223 << 223, times x222  ->  [223 ones][0][222 ones]
    ///   that  <<   2, times z    ->  [223 ones][0][222 ones][0][1]
    ///
    /// 447 squarings and 14 multiplications, against 448 and 446 for a
    /// square-and-multiply over the same exponent. Every shift count is
    /// public, so none of this branches on z.
    fn invert(z: Tight) Tight {
        const x1 = z;
        const x2 = mul(relax(sqn(x1, 1)), relax(x1));
        const x3 = mul(relax(sqn(x2, 1)), relax(x1));
        const x6 = mul(relax(sqn(x3, 3)), relax(x3));
        const x9 = mul(relax(sqn(x6, 3)), relax(x3));
        const x11 = mul(relax(sqn(x9, 2)), relax(x2));
        const x22 = mul(relax(sqn(x11, 11)), relax(x11));
        const x44 = mul(relax(sqn(x22, 22)), relax(x22));
        const x88 = mul(relax(sqn(x44, 44)), relax(x44));
        const x176 = mul(relax(sqn(x88, 88)), relax(x88));
        const x220 = mul(relax(sqn(x176, 44)), relax(x44));
        const x222 = mul(relax(sqn(x220, 2)), relax(x2));
        const x223 = mul(relax(sqn(x222, 1)), relax(x1));

        // [223 ones][0][222 ones], then shift two and set the low bit.
        const r = mul(relax(sqn(x223, 223)), relax(x222));
        return mul(relax(sqn(r, 2)), relax(x1));
    }

    fn ladder(scalar: [dhlen]u8, point: [dhlen]u8) [dhlen]u8 {
        var k = scalar;
        defer std.crypto.secureZero(u8, &k);
        k[0] &= 252;
        k[dhlen - 1] |= 128;

        var x1: Tight = undefined;
        fiat.fromBytes(&x1, point);
        const x1l = relax(x1);

        var x2 = one;
        var z2 = zero;
        var x3 = x1;
        var z3 = one;

        var swap: u1 = 0;
        var t: usize = dhlen * 8;
        while (t > 0) {
            t -= 1;
            const kt: u1 = @truncate(k[t >> 3] >> @intCast(t & 7));
            swap ^= kt;
            cswap(swap, &x2, &x3);
            cswap(swap, &z2, &z3);
            swap = kt;

            const a = add(x2, z2);
            const aa = sq(a);
            const b = sub(x2, z2);
            const bb = sq(b);
            const e = sub(aa, bb);
            const c = add(x3, z3);
            const d = sub(x3, z3);
            const da = mul(d, a);
            const cb = mul(c, b);

            x3 = sq(add(da, cb));
            z3 = mul(x1l, relax(sq(sub(da, cb))));
            x2 = mul(relax(aa), relax(bb));
            z2 = mul(e, add(aa, mul(a24, e)));
        }
        cswap(swap, &x2, &x3);
        cswap(swap, &z2, &z3);

        var out: [dhlen]u8 = undefined;
        fiat.toBytes(&out, mul(relax(x2), relax(invert(z2))));
        return out;
    }

    pub const KeyPair = struct {
        public: [dhlen]u8,
        secret: [dhlen]u8,

        pub fn fromSecret(secret: [dhlen]u8) KeyPair {
            return .{ .secret = secret, .public = ladder(secret, base_u) };
        }

        pub fn generate(io: std.Io) KeyPair {
            var seed: [dhlen]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            io.random(&seed);
            return fromSecret(seed);
        }
    };

    pub fn dh(kp: KeyPair, pk: [dhlen]u8) [dhlen]u8 {
        return ladder(kp.secret, pk);
    }
};

fn hex(comptime s: []const u8) [X448.dhlen]u8 {
    var out: [X448.dhlen]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "rfc 7748 x448 scalar multiplication" {
    const cases = .{
        .{
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
            "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
        },
        .{
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
            "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
        },
    };

    inline for (cases) |case| {
        const kp = X448.KeyPair{ .secret = hex(case[0]), .public = undefined };
        try std.testing.expectEqual(hex(case[2]), X448.dh(kp, hex(case[1])));
    }
}

test "rfc 7748 x448 diffie-hellman" {
    const alice = X448.KeyPair.fromSecret(hex(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    ));
    const bob = X448.KeyPair.fromSecret(hex(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    ));
    const shared = hex(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
    );

    try std.testing.expectEqual(hex(
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
    ), alice.public);
    try std.testing.expectEqual(hex(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609",
    ), bob.public);

    try std.testing.expectEqual(shared, X448.dh(alice, bob.public));
    try std.testing.expectEqual(shared, X448.dh(bob, alice.public));
}

test "x448 on low-order points yields zeros" {
    // u = 0 has order 2, and u = 1 and u = p - 1 both double to it, so they
    // have order 4. The cofactor clamp clears the low two scalar bits, which
    // sends every one of them to the identity.
    const kp = X448.KeyPair.fromSecret(@splat(7));
    const zeros: [X448.dhlen]u8 = @splat(0);
    const u_one: [X448.dhlen]u8 = blk: {
        var out: [X448.dhlen]u8 = @splat(0);
        out[0] = 1;
        break :blk out;
    };
    try std.testing.expectEqual(zeros, X448.dh(kp, @splat(0)));
    try std.testing.expectEqual(zeros, X448.dh(kp, u_one));
    try std.testing.expectEqual(zeros, X448.dh(kp, X448.pMinus(1)));
}

test "x448 accepts a non-canonical u-coordinate" {
    const kp = X448.KeyPair.fromSecret(@splat(9));
    const zeros: [X448.dhlen]u8 = @splat(0);
    try std.testing.expectEqual(zeros, X448.dh(kp, X448.pMinus(0)));
}

test "x448 inversion is a field inverse" {
    const one_le: [X448.dhlen]u8 = blk: {
        var out: [X448.dhlen]u8 = @splat(0);
        out[0] = 1;
        break :blk out;
    };
    const samples = [_][X448.dhlen]u8{
        one_le,
        X448.base_u,
        @splat(7),
        @splat(0xfe),
        X448.pMinus(1),
        hex("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"),
    };

    for (samples) |s| {
        var z: X448.Tight = undefined;
        fiat.fromBytes(&z, s);
        var out: [X448.dhlen]u8 = undefined;
        fiat.toBytes(&out, X448.mul(X448.relax(z), X448.relax(X448.invert(z))));
        try std.testing.expectEqual(one_le, out);
    }

    // Zero has no inverse. The chain yields zero rather than misbehaving,
    // which is what makes a low-order point come out as all zeros.
    var z: X448.Tight = undefined;
    fiat.fromBytes(&z, @splat(0));
    var out: [X448.dhlen]u8 = undefined;
    fiat.toBytes(&out, X448.invert(z));
    try std.testing.expectEqual(@as([X448.dhlen]u8, @splat(0)), out);
}

test "rfc 7748 x448 iterated scalar multiplication" {
    var k = X448.base_u;
    var u = k;
    for (0..1000) |i| {
        const next = X448.dh(.{ .secret = k, .public = undefined }, u);
        u = k;
        k = next;
        if (i == 0) try std.testing.expectEqual(hex(
            "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113",
        ), k);
    }
    try std.testing.expectEqual(hex(
        "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
    ), k);
}
