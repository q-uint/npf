# Test vectors

Third-party files, vendored verbatim. Do not edit. Refresh from upstream instead.

## cacophony.txt

- Upstream: https://github.com/centromere/cacophony `vectors/cacophony.txt`
- License: Unlicense (public domain), see `LICENSE.cacophony`
- sha256: `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae`

Covers 59 handshake patterns across 16 cipher suites (944 vectors). All of them run.

The copy distributed by [snow](https://github.com/mcginty/snow) under `tests/vectors/cacophony.txt` is byte-identical.

## snow.txt

- Upstream: https://github.com/mcginty/snow `tests/vectors/snow.txt`
- License: Apache-2.0, see `LICENSE.snow`
- sha256: `69da433305fd045f6c9f01b656662a389d022688986fd39fbe7af009cd402fd3`

408 vectors, 25519 only, and no `handshake_hash` field. Mostly overlaps cacophony, so only the 13 patterns cacophony lacks are run, 104 vectors. All 13 carry more than one `psk` modifier, for example `XXpsk0+psk1+psk2+psk3`. Section 9.2 permits repeated `psk` tokens and no other vector file we have exercises them.

`snow-extended.txt` is not vendored. It covers `P256` and `XChaChaPoly`, neither of which is in revision 34.

## noise-c-fallback.txt

- Upstream: https://github.com/rweather/noise-c `tests/vector/noise-c-fallback.txt`
- License: MIT, Copyright (C) 2016 Southern Storm Software, Pty Ltd, see `LICENSE.noise-c`

`Noise_XXfallback` vectors for Noise Pipes. Uses the pre-revision-32 vector schema (`pattern`/`dh`/`cipher`/`hash` instead of `protocol_name`). The `NoisePSK_*` entries use the deprecated pre-revision-32 PSK construction and are skipped, because the current `pskN` modifiers are not compatible with them.

## Format

All three files follow the [Noise test vector format](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors). The `.txt` extension is deliberate: the format is JSON-compatible but line-oriented so that implementations without a JSON parser can consume it.

## Refreshing

```sh
curl -sSLO --output-dir tests/vectors \
  https://raw.githubusercontent.com/centromere/cacophony/master/vectors/cacophony.txt
curl -sSLO --output-dir tests/vectors \
  https://raw.githubusercontent.com/mcginty/snow/main/tests/vectors/snow.txt
curl -sSL --output-dir tests/vectors -o noise-c-fallback.txt \
  https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-fallback.txt
```
