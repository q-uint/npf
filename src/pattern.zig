const std = @import("std");

pub const Token = enum { e, s, ee, es, se, ss, psk };

pub const Pattern = struct {
    name: []const u8,
    pre: [2][]const Token,
    messages: []const []const Token,
    psk: bool,
    initiator_first: bool,

    pub fn senderIsInitiator(self: Pattern, index: usize) bool {
        return (index % 2 == 0) == self.initiator_first;
    }

    pub fn sender(self: Pattern, index: usize) usize {
        return if (self.senderIsInitiator(index)) 0 else 1;
    }
};

pub fn parse(comptime name: []const u8, comptime src: []const u8) Pattern {
    var pre: [2][]const Token = .{ &.{}, &.{} };
    var messages: []const []const Token = &.{};
    var in_pre = std.mem.indexOf(u8, src, "...") != null;

    var lines = std.mem.tokenizeScalar(u8, src, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "...")) {
            in_pre = false;
            continue;
        }
        const from_initiator = if (std.mem.startsWith(u8, line, "->"))
            true
        else if (std.mem.startsWith(u8, line, "<-"))
            false
        else
            @compileError(name ++ ": bad line '" ++ line ++ "'");

        var tokens: []const Token = &.{};
        var items = std.mem.tokenizeAny(u8, line[2..], " ,");
        while (items.next()) |item| {
            const tok = std.meta.stringToEnum(Token, item) orelse
                @compileError(name ++ ": bad token '" ++ item ++ "'");
            tokens = tokens ++ [_]Token{tok};
        }

        if (in_pre) {
            const party = if (from_initiator) 0 else 1;
            for (tokens) |tok| if (tok != .e and tok != .s)
                @compileError(name ++ ": pre-messages may only carry e or s");
            pre[party] = pre[party] ++ tokens;
        } else {
            if (from_initiator != (messages.len % 2 == 0))
                @compileError(name ++ ": message directions must alternate, starting with ->");
            messages = messages ++ [_][]const Token{tokens};
        }
    }
    if (messages.len == 0) @compileError(name ++ ": no message patterns");

    const p: Pattern = .{
        .name = name,
        .pre = pre,
        .messages = messages,
        .psk = false,
        .initiator_first = true,
    };
    validate(p);
    return p;
}

const Key = enum { ephemeral, static };

fn dhRoles(tok: Token, party: usize) struct { Key, Key } {
    const initiator = party == 0;
    return switch (tok) {
        .ee => .{ .ephemeral, .ephemeral },
        .ss => .{ .static, .static },
        .es => if (initiator) .{ .ephemeral, .static } else .{ .static, .ephemeral },
        .se => if (initiator) .{ .static, .ephemeral } else .{ .ephemeral, .static },
        else => unreachable,
    };
}

fn validate(comptime p: Pattern) void {
    var sent_e: [2]bool = @splat(false);
    var sent_s: [2]bool = @splat(false);
    var dh_seen: []const Token = &.{};
    var psk_seen = false;
    var has_key = false;

    var static_dh: [2][2]bool = @splat(@splat(false));
    var ephemeral_dh: [2][2]bool = @splat(@splat(false));

    // Section 7.3 rule 1: a party may only perform a DH with keys it holds.
    // has_local[party][key] is its own, has_remote[party][key] is the peer's
    // as received so far.
    var has_local: [2][2]bool = @splat(@splat(false));
    var has_remote: [2][2]bool = @splat(@splat(false));

    const reveal = struct {
        fn f(party: usize, k: Key, local: *[2][2]bool, remote: *[2][2]bool) void {
            const slot = @intFromEnum(k);
            local[party][slot] = true;
            remote[1 - party][slot] = true;
        }
    }.f;

    const checkEncrypt = struct {
        fn f(
            comptime name: []const u8,
            comptime where: []const u8,
            party: usize,
            statics: [2][2]bool,
            ephemerals: [2][2]bool,
        ) void {
            for (0..2) |remote| {
                if (statics[party][remote] and !ephemerals[party][remote])
                    @compileError(name ++ ": " ++ where ++
                        " encrypted under a key with no local ephemeral contribution");
            }
        }
    }.f;

    // Section 7.1: a pre-message pattern is exactly one of "e", "s",
    // "e, s", or empty. The order is load-bearing, because Initialize
    // hashes pre-message keys in the order they are listed.
    for (p.pre) |tokens| {
        const legal = switch (tokens.len) {
            0 => true,
            1 => tokens[0] == .e or tokens[0] == .s,
            2 => tokens[0] == .e and tokens[1] == .s,
            else => false,
        };
        if (!legal)
            @compileError(p.name ++ ": a pre-message must be empty, \"e\", \"s\", or \"e, s\"");
    }

    for (p.pre, 0..) |tokens, party| for (tokens) |tok| switch (tok) {
        .e => {
            sent_e[party] = true;
            reveal(party, .ephemeral, &has_local, &has_remote);
        },
        .s => {
            sent_s[party] = true;
            reveal(party, .static, &has_local, &has_remote);
        },
        else => unreachable,
    };

    for (p.messages, 0..) |tokens, index| {
        const party = p.sender(index);
        for (tokens) |tok| switch (tok) {
            .e => {
                if (sent_e[party]) @compileError(p.name ++ ": e sent twice by the same party");
                sent_e[party] = true;
                reveal(party, .ephemeral, &has_local, &has_remote);
            },
            .s => {
                if (sent_s[party]) @compileError(p.name ++ ": s sent twice by the same party");
                sent_s[party] = true;
                if (psk_seen and !sent_e[party])
                    @compileError(p.name ++ ": encryption after psk without a sent e");
                if (has_key)
                    checkEncrypt(p.name, "static key", party, static_dh, ephemeral_dh);
                reveal(party, .static, &has_local, &has_remote);
            },
            .psk => {
                psk_seen = true;
                has_key = true;
            },
            else => {
                for (dh_seen) |prev| if (prev == tok)
                    @compileError(p.name ++ ": DH performed more than once per handshake");
                dh_seen = dh_seen ++ [_]Token{tok};
                has_key = true;
                for (0..2) |who| {
                    const local, const remote = dhRoles(tok, who);
                    if (!has_local[who][@intFromEnum(local)])
                        @compileError(p.name ++ ": \"" ++ @tagName(tok) ++
                            "\" needs a local " ++ @tagName(local) ++ " key that party does not have");
                    if (!has_remote[who][@intFromEnum(remote)])
                        @compileError(p.name ++ ": \"" ++ @tagName(tok) ++
                            "\" needs a remote " ++ @tagName(remote) ++ " key that has not been received");
                    const slot = @intFromEnum(remote);
                    switch (local) {
                        .static => static_dh[who][slot] = true,
                        .ephemeral => ephemeral_dh[who][slot] = true,
                    }
                }
            },
        };
        if (psk_seen and !sent_e[party])
            @compileError(p.name ++ ": encrypted payload after psk without a sent e");
        if (has_key)
            checkEncrypt(p.name, "handshake payload", party, static_dh, ephemeral_dh);
    }

    const senders = if (p.messages.len >= 2) [_]usize{ 0, 1 } else [_]usize{p.sender(0)};
    for (senders) |party| {
        checkEncrypt(p.name, "transport payload", party, static_dh, ephemeral_dh);
    }
}

pub fn withPsk(comptime p: Pattern, comptime n: usize) Pattern {
    return comptime blk: {
        if (n > p.messages.len) @compileError(p.name ++ ": psk index out of range");
        var messages: []const []const Token = &.{};
        for (p.messages, 0..) |tokens, i| {
            const patched: []const Token = if (n == 0 and i == 0)
                [_]Token{.psk} ++ tokens
            else if (n > 0 and i == n - 1)
                tokens ++ [_]Token{.psk}
            else
                tokens;
            messages = messages ++ [_][]const Token{patched};
        }
        const out: Pattern = .{
            .name = p.name ++ std.fmt.comptimePrint("psk{d}", .{n}),
            .pre = p.pre,
            .messages = messages,
            .psk = true,
            .initiator_first = p.initiator_first,
        };
        validate(out);
        break :blk out;
    };
}

pub fn withFallback(comptime p: Pattern) Pattern {
    return comptime blk: {
        if (!p.initiator_first) @compileError(p.name ++ ": fallback applied twice");
        if (p.messages.len < 2) @compileError(p.name ++ ": nothing left after fallback");
        for (p.messages[0]) |tok| if (tok != .e and tok != .s)
            @compileError(p.name ++ ": first message must be usable as a pre-message");

        const out: Pattern = .{
            .name = p.name ++ "fallback",
            .pre = .{ p.pre[0] ++ p.messages[0], p.pre[1] },
            .messages = p.messages[1..],
            .psk = p.psk,
            .initiator_first = false,
        };
        validate(out);
        break :blk out;
    };
}

pub const N = parse("N",
    \\<- s
    \\...
    \\-> e, es
);
pub const K = parse("K",
    \\-> s
    \\<- s
    \\...
    \\-> e, es, ss
);
pub const X = parse("X",
    \\<- s
    \\...
    \\-> e, es, s, ss
);

pub const NN = parse("NN",
    \\-> e
    \\<- e, ee
);
pub const NK = parse("NK",
    \\<- s
    \\...
    \\-> e, es
    \\<- e, ee
);
pub const NX = parse("NX",
    \\-> e
    \\<- e, ee, s, es
);
pub const XN = parse("XN",
    \\-> e
    \\<- e, ee
    \\-> s, se
);
pub const XK = parse("XK",
    \\<- s
    \\...
    \\-> e, es
    \\<- e, ee
    \\-> s, se
);
pub const XX = parse("XX",
    \\-> e
    \\<- e, ee, s, es
    \\-> s, se
);
pub const KN = parse("KN",
    \\-> s
    \\...
    \\-> e
    \\<- e, ee, se
);
pub const KK = parse("KK",
    \\-> s
    \\<- s
    \\...
    \\-> e, es, ss
    \\<- e, ee, se
);
pub const KX = parse("KX",
    \\-> s
    \\...
    \\-> e
    \\<- e, ee, se, s, es
);
pub const IN = parse("IN",
    \\-> e, s
    \\<- e, ee, se
);
pub const IK = parse("IK",
    \\<- s
    \\...
    \\-> e, es, s, ss
    \\<- e, ee, se
);
pub const IX = parse("IX",
    \\-> e, s
    \\<- e, ee, se, s, es
);

pub const NK1 = parse("NK1",
    \\<- s
    \\...
    \\-> e
    \\<- e, ee, es
);
pub const NX1 = parse("NX1",
    \\-> e
    \\<- e, ee, s
    \\-> es
);
pub const X1N = parse("X1N",
    \\-> e
    \\<- e, ee
    \\-> s
    \\<- se
);
pub const X1K = parse("X1K",
    \\<- s
    \\...
    \\-> e, es
    \\<- e, ee
    \\-> s
    \\<- se
);
pub const XK1 = parse("XK1",
    \\<- s
    \\...
    \\-> e
    \\<- e, ee, es
    \\-> s, se
);
pub const X1K1 = parse("X1K1",
    \\<- s
    \\...
    \\-> e
    \\<- e, ee, es
    \\-> s
    \\<- se
);
pub const X1X = parse("X1X",
    \\-> e
    \\<- e, ee, s, es
    \\-> s
    \\<- se
);
pub const XX1 = parse("XX1",
    \\-> e
    \\<- e, ee, s
    \\-> es, s, se
);
pub const X1X1 = parse("X1X1",
    \\-> e
    \\<- e, ee, s
    \\-> es, s
    \\<- se
);
pub const K1N = parse("K1N",
    \\-> s
    \\...
    \\-> e
    \\<- e, ee
    \\-> se
);
pub const K1K = parse("K1K",
    \\-> s
    \\<- s
    \\...
    \\-> e, es
    \\<- e, ee
    \\-> se
);
pub const KK1 = parse("KK1",
    \\-> s
    \\<- s
    \\...
    \\-> e
    \\<- e, ee, se, es
);
pub const K1K1 = parse("K1K1",
    \\-> s
    \\<- s
    \\...
    \\-> e
    \\<- e, ee, es
    \\-> se
);
pub const K1X = parse("K1X",
    \\-> s
    \\...
    \\-> e
    \\<- e, ee, s, es
    \\-> se
);
pub const KX1 = parse("KX1",
    \\-> s
    \\...
    \\-> e
    \\<- e, ee, se, s
    \\-> es
);
pub const K1X1 = parse("K1X1",
    \\-> s
    \\...
    \\-> e
    \\<- e, ee, s
    \\-> se, es
);
pub const I1N = parse("I1N",
    \\-> e, s
    \\<- e, ee
    \\-> se
);
pub const I1K = parse("I1K",
    \\<- s
    \\...
    \\-> e, es, s
    \\<- e, ee
    \\-> se
);
pub const IK1 = parse("IK1",
    \\<- s
    \\...
    \\-> e, s
    \\<- e, ee, se, es
);
pub const I1K1 = parse("I1K1",
    \\<- s
    \\...
    \\-> e, s
    \\<- e, ee, es
    \\-> se
);
pub const I1X = parse("I1X",
    \\-> e, s
    \\<- e, ee, s, es
    \\-> se
);
pub const IX1 = parse("IX1",
    \\-> e, s
    \\<- e, ee, se, s
    \\-> es
);
pub const I1X1 = parse("I1X1",
    \\-> e, s
    \\<- e, ee, s
    \\-> se, es
);

/// The switch pattern of the Noise Pipe compound protocol (sections 10.2
/// and 10.4). Not a fundamental pattern, so it is not in `all`.
pub const XXfallback = withFallback(XX);

pub const one_way = [_]Pattern{ N, K, X };
pub const fundamental = [_]Pattern{ NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX };
pub const deferred = [_]Pattern{
    NK1,  NX1, X1N, X1K,  XK1,  X1K1, X1X,  XX1,
    X1X1, K1N, K1K, KK1,  K1K1, K1X,  KX1,  K1X1,
    I1N,  I1K, IK1, I1K1, I1X,  IX1,  I1X1,
};
pub const all = one_way ++ fundamental ++ deferred;

pub fn find(name: []const u8) ?Pattern {
    for (all) |p| {
        if (std.mem.eql(u8, p.name, name)) return p;
    }
    return null;
}

pub fn fromName(comptime name: []const u8) Pattern {
    return comptime blk: {
        @setEvalBranchQuota(2_000_000);
        var base: ?Pattern = null;
        for (all) |p| {
            if (!std.mem.startsWith(u8, name, p.name)) continue;
            if (base == null or p.name.len > base.?.name.len) base = p;
        }
        var out = base orelse @compileError("unknown handshake pattern: " ++ name);
        const rest = name[out.name.len..];
        if (rest.len == 0) break :blk out;

        var mods = std.mem.splitScalar(u8, rest, '+');
        while (mods.next()) |mod| {
            if (std.mem.eql(u8, mod, "fallback")) {
                out = withFallback(out);
            } else if (std.mem.startsWith(u8, mod, "psk")) {
                const n = std.fmt.parseInt(usize, mod[3..], 10) catch
                    @compileError("bad psk modifier: " ++ mod);
                out = withPsk(out, n);
            } else {
                @compileError("unsupported pattern modifier: " ++ mod);
            }
        }
        out.name = name;
        break :blk out;
    };
}

test "pattern counts match the spec" {
    try std.testing.expectEqual(@as(usize, 3), one_way.len);
    try std.testing.expectEqual(@as(usize, 12), fundamental.len);
    try std.testing.expectEqual(@as(usize, 23), deferred.len);
    try std.testing.expectEqual(@as(usize, 38), all.len);
}

test "parse splits pre-messages from messages" {
    try std.testing.expectEqualSlices(Token, &.{}, XX.pre[0]);
    try std.testing.expectEqualSlices(Token, &.{}, XX.pre[1]);
    try std.testing.expectEqual(@as(usize, 3), XX.messages.len);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee, .s, .es }, XX.messages[1]);

    try std.testing.expectEqualSlices(Token, &.{.s}, KK.pre[0]);
    try std.testing.expectEqualSlices(Token, &.{.s}, KK.pre[1]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .es, .ss }, KK.messages[0]);

    try std.testing.expectEqualSlices(Token, &.{}, IK.pre[0]);
    try std.testing.expectEqualSlices(Token, &.{.s}, IK.pre[1]);
}

test "psk modifiers place the token per section 9.4" {
    const npsk0 = withPsk(N, 0);
    try std.testing.expectEqualStrings("Npsk0", npsk0.name);
    try std.testing.expect(npsk0.psk);
    try std.testing.expectEqualSlices(Token, &.{ .psk, .e, .es }, npsk0.messages[0]);

    const xpsk1 = withPsk(X, 1);
    try std.testing.expectEqualSlices(Token, &.{ .e, .es, .s, .ss, .psk }, xpsk1.messages[0]);

    const nnpsk2 = withPsk(NN, 2);
    try std.testing.expectEqualSlices(Token, &.{.e}, nnpsk2.messages[0]);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee, .psk }, nnpsk2.messages[1]);
}

test "section 7.3 validity rules reject unsafe patterns" {
    try std.testing.expect(!@hasDecl(@This(), "NNbroken"));

    inline for (all) |p| {
        var dh_seen: [4]usize = @splat(0);
        inline for (p.messages) |tokens| inline for (tokens) |tok| switch (tok) {
            .ee, .es, .se, .ss => dh_seen[@backingInt(tok) - 2] += 1,
            else => {},
        };
        for (dh_seen) |count| try std.testing.expect(count <= 1);
    }
}

test "section 7.1 pre-message forms" {
    inline for (all ++ [_]Pattern{XXfallback}) |p| {
        inline for (p.pre) |tokens| {
            try std.testing.expect(tokens.len <= 2);
            if (tokens.len == 1)
                try std.testing.expect(tokens[0] == .e or tokens[0] == .s);
            if (tokens.len == 2) {
                try std.testing.expectEqual(Token.e, tokens[0]);
                try std.testing.expectEqual(Token.s, tokens[1]);
            }
        }
    }
    // withFallback on a pattern whose initiator already has an "s"
    // pre-message would concatenate to "s, e", which is not a legal form
    // and is rejected at comptime. See withFallback(KX).
}

test "fallback turns the first message into a pre-message" {
    const fb = withFallback(XX);
    try std.testing.expectEqualStrings("XXfallback", fb.name);
    try std.testing.expect(!fb.initiator_first);
    try std.testing.expectEqualSlices(Token, &.{.e}, fb.pre[0]);
    try std.testing.expectEqualSlices(Token, &.{}, fb.pre[1]);
    try std.testing.expectEqual(@as(usize, 2), fb.messages.len);
    try std.testing.expectEqualSlices(Token, &.{ .e, .ee, .s, .es }, fb.messages[0]);
    try std.testing.expectEqualSlices(Token, &.{ .s, .se }, fb.messages[1]);

    try std.testing.expect(!fb.senderIsInitiator(0));
    try std.testing.expect(fb.senderIsInitiator(1));
    try std.testing.expectEqual(@as(usize, 1), fb.sender(0));
    try std.testing.expectEqual(@as(usize, 0), fb.sender(1));
}

test "fromName resolves patterns and modifiers" {
    try std.testing.expectEqualStrings("XX", fromName("XX").name);
    try std.testing.expectEqualStrings("X1X1", fromName("X1X1").name);
    try std.testing.expectEqualStrings("IKpsk2", fromName("IKpsk2").name);
    try std.testing.expectEqualStrings("XXfallback", fromName("XXfallback").name);
    try std.testing.expectEqualStrings("XXfallback+psk0", fromName("XXfallback+psk0").name);
    try std.testing.expect(fromName("XXfallback+psk0").psk);
    try std.testing.expect(!fromName("XXfallback+psk0").initiator_first);
    try std.testing.expectEqualSlices(
        Token,
        &.{ .psk, .e, .ee, .s, .es },
        fromName("XXfallback+psk0").messages[0],
    );
    try std.testing.expect(fromName("NNpsk0").psk);
    try std.testing.expect(find("XX") != null);
    try std.testing.expect(find("QQ") == null);
}

test "every pattern alternates and ends without leftovers" {
    inline for (all) |p| {
        try std.testing.expect(p.messages.len >= 1);
        try std.testing.expect(!p.psk);
        try std.testing.expect(p.initiator_first);
        inline for (p.messages) |tokens| try std.testing.expect(tokens.len >= 1);
    }
}
