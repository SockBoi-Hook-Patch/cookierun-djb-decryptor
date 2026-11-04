# Changelog

## 0.2.0 — Working Copy Full Upgrade

- Introduced installable src package and cookierun-djb CLI.
- Added defensive Gen1/Gen2 header parsing with full u64 size handling.
- Added explicit verification states; missing Gen2 BLAKE3 no longer reports full success.
- Added bounds-checked FastLZ and record parsing.
- Added experimental raw-payload Forge with round-trip checks.
- Added atomic output, relative-path-preserving batch mode, CI, security notes and roadmap.
- Added synthetic Gen1/Gen2 tests; genuine samples are not included in the repository.
