const pattern = @import("npf").pattern;

// Section 7.3 rule 1: "ee" needs a remote ephemeral that was never sent.
comptime {
    _ = pattern.parse("NoRemoteE",
        \\-> e, ee
    );
}
