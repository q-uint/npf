const std = @import("std");

pub const crypto = @import("crypto.zig");
pub const state = @import("state.zig");
pub const pattern = @import("pattern.zig");
pub const handshake = @import("handshake.zig");
pub const pipe = @import("pipe.zig");

pub const CipherState = state.CipherState;
pub const SymmetricState = state.SymmetricState;
pub const UnorderedSender = state.UnorderedSender;
pub const UnorderedReceiver = state.UnorderedReceiver;
pub const HalfDuplexCipherState = state.HalfDuplexCipherState;
pub const ReplayWindow = state.ReplayWindow;
pub const max_message_len = state.max_message_len;
pub const HandshakeState = handshake.HandshakeState;
pub const Suite = handshake.Suite;
pub const Protocol = handshake.Protocol;
pub const Role = handshake.Role;
pub const Pipe = pipe.Pipe;
pub const Rng = handshake.Rng;
pub const Pattern = pattern.Pattern;
pub const Token = pattern.Token;
pub const Error = handshake.Error;

test {
    std.testing.refAllDecls(@This());
    _ = crypto;
    _ = state;
    _ = pattern;
    _ = handshake;
    _ = pipe;
    _ = @import("readme_example.zig");
    _ = @import("robustness.zig");
}
