# CookieRun DJB Decryptor

**Inspect · Decrypt · Verify · Rebuild** Cookie Run DJBF (.djb) containers.

> **Status: 0.2.0 — core stabilization.** The package has 23 passing synthetic
> tests in the local working copy. A supplied local corpus was also used for
> preliminary exploration (200 Gen2 files passed the recorded AES/FastLZ/CRC
> checks; 5 Gen1 files remain unresolved). The proprietary corpus is not included
> in this repository, and these exploratory results are not yet CI fixtures.

## Features

- Detect and inspect Gen1 (0x01xx) and Gen2 (0x02xx) DJBF headers.
- AES-256 ECB/CBC decryption using the configured Kakao and QQ Gen1 profiles.
- Bounded FastLZ L1/L2 decompression, including the current L2 far-distance
  convention carried over from the original implementation.
- CRC-32 and optional BLAKE3 verification with explicit states:
  fully_verified, partially_verified, failed.
- Defensive length-prefixed record parsing and JSON export.
- Recursive batch decryption that preserves relative paths and writes atomically.
- Experimental Forge for raw (uncompressed) payloads, with decrypt/verify
  round-trip validation.

## Important limitations

1. **Gen1 is not yet fully supported.** Five Gen1 samples in the supplied local
   corpus remain unresolved. See docs/ROADMAP.md.
2. **Forge is experimental.** It writes raw AES-protected payloads; it does not
   encode FastLZ. Acceptance by the actual game loader has not been demonstrated.
3. **Gen2 verification needs BLAKE3.** Without the optional dependency, CRC can
   pass but the result is reported as partially_verified, never fully_verified.
4. **QQ Gen2 is unsupported** because no key profile is available in the supplied
   source material.
5. The parser reads a 64-bit plaintext size at offset 0x0C and applies a 512 MiB
   safety limit. Confirm this interpretation against additional real files
   before treating it as a definitive format rule.
6. Key-material provenance requires review before public redistribution. See
   NOTICE.md.

## Install

Python 3.10+ is required.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# Linux/macOS:
# source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test,verify]"
```

For decrypt-only use, install the required AES dependency without extras:

```bash
python -m pip install -e .
```

## CLI

```bash
cookierun-djb info path/to/file.djb
cookierun-djb decrypt path/to/file.djb
cookierun-djb decrypt path/to/file.djb --verify
cookierun-djb decrypt path/to/file.djb --json
cookierun-djb batch path/to/djb-folder output-folder --verify
cookierun-djb forge plaintext.bin rebuilt.djb --generation 2 --build kakao --mode cbc
```

The Forge command is experimental and currently supports raw payloads only.

## Development and tests

```bash
python -m pip install -e ".[test,verify]"
pytest -q
```

The checked-in test suite uses synthetic containers. Do not mistake these for
genuine game fixtures. Proprietary DJB files and decrypted BIN outputs are
excluded from this repository; the .gitignore prevents common local sample
extensions from being committed.

## Project layout

```text
src/cookierun_djb/    core parser, decryptor, forge, CLI
tests/                unit and synthetic integration tests
docs/                 format assumptions, architecture, security, roadmap
.github/workflows/    CI
```

## Roadmap

See docs/ROADMAP.md. The release gate for 1.0.0 requires validated genuine Gen1
and Gen2 samples and evidence of game-loader compatibility.

## Disclaimer

For research, education, and interoperability with game data you are authorized
to inspect. Not affiliated with or endorsed by Devsisters. Do not redistribute
proprietary game assets or use this project to gain an unfair advantage in
online play.

---

## ภาษาไทย

โปรเจกต์นี้ใช้สำหรับตรวจสอบ (Inspect), ถอดรหัส (Decrypt), ตรวจสอบความถูกต้อง
(Verify) และทดลองสร้างไฟล์กลับ (Forge) สำหรับไฟล์ Cookie Run DJBF (.djb)

**สถานะ 0.2.0:** ชุดทดสอบ Synthetic ผ่าน 23 รายการใน Working Copy และมีผล
ทดสอบเบื้องต้นกับ Corpus จริงที่ผู้ใช้ส่งมา โดย Gen2 ผ่าน 200 ไฟล์ ส่วน Gen1
อีก 5 ไฟล์ยังต้องตรวจสอบเพิ่มเติม ไฟล์ตัวอย่างจริงจะไม่ถูกเผยแพร่ใน Repository

Forge ยังเป็น Experimental และรองรับเฉพาะ Raw Payload ยังไม่ยืนยันว่า Game
Loader ยอมรับไฟล์ที่สร้างขึ้น ดูรายละเอียดที่ docs/ROADMAP.md และ NOTICE.md
