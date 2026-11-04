# Reverse-engineering notes

This document is a historical write-up carried forward from the uploaded source
archive. Its measurements, key derivation, and compatibility claims have not
been independently reproduced in this Working Copy. Treat them as author-
reported observations until verified against source binaries and genuine
Gen1/Gen2 samples.

The original notes describe:
- a packed native game library and a repeating-XOR unpacking hypothesis;
- a DJBF loader path that reconstructs ciphertext from the body and displaced
  tail, then performs AES decryption and optional FastLZ decompression;
- per-generation key and IV derivation differences;
- a FastLZ L2 far-distance convention using a base of 8192.

These are working hypotheses, not a definitive format specification. See
FORMAT.md for the current confidence boundaries and ROADMAP.md for validation
requirements.
