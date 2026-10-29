const pattern = @import("npf").pattern;

// Section 7.3 rule 2: a party may send "e" only once.
comptime {
    _ = pattern.parse("DoubleE",
        \\-> e
        \\<- e, ee
        \\-> e
    );
}
