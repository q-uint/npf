# fiat-crypto field arithmetic

Vendored verbatim. Do not edit. Regenerate or re-download instead.

- Upstream: https://github.com/mit-plv/fiat-crypto `fiat-zig/src/`
- Commit: `f3ecb2cf1f771de34771e967193ee7f0ee0b0acf`
- License: `MIT OR Apache-2.0 OR BSD-1-Clause`, see `LICENSE-MIT`

| File | sha256 |
|---|---|
| `p448_solinas_64.zig` | `7eb40997dcdab931a4104c21ef6592be2ab95a2799af7622c29cb3fa8a76600c` |
| `p448_solinas_32.zig` | `8e8e97dd29e86b72f3b9f39bc79c1c0d3c2400a8518e118a833021daa5619924` |

Field arithmetic modulo the Goldilocks prime `p = 2^448 - 2^224 - 1`, used by `../x448.zig`. `p448_solinas_64.zig` uses 8 limbs of 56 bits. The 32-bit variant uses 16 limbs of 28 bits. `x448.zig` selects between them on `builtin.target.ptrBitWidth()`.

These files are machine-generated from a Coq development and carry machine-checked proofs of functional correctness and of the limb bounds (no overflow). Nothing here was written or transcribed by hand.

## Regenerating

The generator is extracted to OCaml from the Coq proofs, so building it requires a full Coq + OCaml toolchain. The exact invocation is recorded on line 1 of each file:

```
src/ExtractionOCaml/unsaturated_solinas --lang Zig --internal-static \
  --public-function-case camelCase --private-function-case camelCase \
  --public-type-case UpperCamelCase --private-type-case UpperCamelCase \
  --no-prefix-fiat --package-name p448 '' 64 8 '2^448 - 2^224 - 1' \
  carry_mul carry_square carry add sub opp selectznz to_bytes from_bytes relax
```

(`64` is the machine word size and `8` the limb count. The 32-bit file uses `32 16`.)

Upstream CI runs this and commits the result, so regenerating with the same flags and upstream revision reproduces these files byte-for-byte. Re-downloading is equivalent and far cheaper:

```sh
curl -sSL --output-dir src/fiat -O \
  https://raw.githubusercontent.com/mit-plv/fiat-crypto/master/fiat-zig/src/p448_solinas_64.zig
curl -sSL --output-dir src/fiat -O \
  https://raw.githubusercontent.com/mit-plv/fiat-crypto/master/fiat-zig/src/p448_solinas_32.zig
```

Not consumed as a Zig package dependency: the fiat-crypto repository is ~185 MB of Coq sources with no separate release artifact for `fiat-zig`, and these two files are 120 KB. Zig's own standard library vendors the same generator's output (`std/crypto/pcurves/p256/p256_64.zig` and friends) for the same reason.
