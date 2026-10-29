const pattern = @import("npf").pattern;

// KX has an initiator pre-message "-> s" and a first message "-> e", so
// fallback would concatenate them into "s, e", which section 7.1 does not
// allow as a pre-message pattern.
comptime {
    _ = pattern.withFallback(pattern.KX);
}
