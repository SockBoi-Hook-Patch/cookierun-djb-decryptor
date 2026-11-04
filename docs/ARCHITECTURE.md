# Architecture

The package is organized around a small defensive core:

- core.py: DJBF header parsing, AES decryption, FastLZ decoding, record parsing,
  CRC32 and BLAKE3 verification.
- forge.py: experimental raw-payload container writer with decrypt/verify
  round-trip checks.
- cli.py: info, decrypt, batch and forge commands with atomic file output.

The CLI is a thin layer over the Python API. Binary parsing enforces explicit
limits for header size, declared plaintext size, record counts and string sizes.
