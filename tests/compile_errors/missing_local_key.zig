const pattern = @import("npf").pattern;

// Section 7.3 rule 1: "se" needs a local static this party never has.
comptime {
    _ = pattern.parse("NoLocalS",
        \\-> e
        \\<- e, ee
        \\-> se
    );
}
