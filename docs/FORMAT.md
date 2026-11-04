# DJBF format notes (working specification)

This document records format assumptions carried forward from the supplied
source archive. Items marked as assumptions require confirmation against genuine
Gen1 and Gen2 files.

## Header layouts

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0x00 | 4 | Magic | ASCII DJBF |
| 0x04 | 2 | Version | Big-endian; 0x01xx Gen1, 0x02xx Gen2 |
| 0x06 | 2 | Reserved | Preserved/ignored |
| 0x08 | 4 | CRC-32 | Little-endian; first byte is IV salt |
| 0x0C | 8 | Plaintext size | Little-endian u64, implementation safety cap 512 MiB |
| 0x14 | 1 | Flags | 0x01 ECB, 0x02 CBC, 0x80 FastLZ |
| 0x15 | 32 | BLAKE3-256 | Gen2 only |
| 0x15 / 0x35 | 15 | Displaced tail | Gen1 / Gen2 suffix area |
| 0x24 / 0x44 | 1 | Tail length | Gen1 / Gen2; accepted range 0..15 |

Header lengths: Gen1 0x25 (37 bytes); Gen2 0x45 (69 bytes).

## Payload handling

The original implementation describes ciphertext reconstruction as on-disk body
followed by the displaced tail bytes stored in the header. AES ciphertext must be
16-byte aligned. CBC IV is derived from the low byte of the CRC field and a
per-generation base vector. FastLZ is applied after decryption when flag 0x80
is set; otherwise plaintext is truncated to the declared size.

## Integrity

- Gen1: CRC-32 with initial value 0x00000000.
- Gen2: CRC-32 with initial value 0x20240424, plus BLAKE3-256.
- A Gen2 CRC pass without the BLAKE3 package is only a partial verification.

These details are inherited from the supplied project and are not independently
confirmed as a definitive public specification.
