const pattern = @import("npf").pattern;

// Section 7.3 rule 3: each DH token at most once per handshake.
comptime {
    _ = pattern.parse("DupDh",
        \\-> e
        \\<- e, ee
        \\-> ee
    );
}
