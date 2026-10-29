const pattern = @import("npf").pattern;

// Section 9.3: must not encrypt after a psk token without having sent an e.
comptime {
    _ = pattern.parse("PskNoE",
        \\-> psk
        \\<- e
    );
}
