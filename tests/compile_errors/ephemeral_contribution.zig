const pattern = @import("npf").pattern;

// Section 7.3 rule 4: payload encrypted under a key with no local
// ephemeral contribution.
comptime {
    _ = pattern.parse("NoEphemeralContribution",
        \\-> s
        \\<- s
        \\...
        \\-> e, ss
    );
}
