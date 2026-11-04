# Security and safe handling

- Treat every .djb file as untrusted input. The parser enforces declared-size,
  record-count, string-length, header, AES alignment and decompression bounds.
- Work on copies of game data you are authorized to inspect. This project does
  not provide network exploitation or online-game manipulation features.
- Batch output preserves relative paths and writes atomically to reduce filename
  collisions and partial output files.
- Gen2 BLAKE3 verification is reported as partially_verified when the optional
  blake3 package is unavailable. A CRC pass alone is not reported as full Gen2
  verification.
- Forge currently emits raw (uncompressed) AES-protected payloads only. It does
  not claim compatibility with a live game loader.
