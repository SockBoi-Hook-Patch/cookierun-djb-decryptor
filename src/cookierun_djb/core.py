"""Defensive DJBF parsing, FastLZ decompression, decryption and verification."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

MAGIC = b"DJBF"
FLAG_ECB, FLAG_CBC, FLAG_FASTLZ = 0x01, 0x02, 0x80
MAX_PLAINTEXT_SIZE = 512 * 1024 * 1024
MAX_RECORDS = 2_000_000
MAX_FIELDS_PER_RECORD = 100_000
MAX_STRING_SIZE = 64 * 1024 * 1024
_FAR_BASE = 8192

KEYCHAIN = {
    ("kakao", 1): (
        bytes.fromhex("c001c1e1261110da90903581feba9a7fa1451c4f978871fac3f1f8293ddee2b3"),
        bytes.fromhex("58a8b9dd136162aa99887a1ff23f7c91"), "add"),
    ("kakao", 2): (
        bytes.fromhex("e8911c7a40bc1f6059a1d910538543bc5df44840cc684d5f1493a3f6daf0fe1e"),
        bytes.fromhex("2a790622e6fef51e5cca503eca4d5c40"), "mul"),
    ("qq", 1): (
        bytes.fromhex("c029c1e1268871faa1451c4f97ded2b390943581feba a97fc3f1f8293d1110fa".replace(" ", "")),
        bytes.fromhex("136162aa38a8b9dd996ff23f7c91887a"), "add"),
}

class DjbError(Exception):
    """Invalid, unsupported, or unverifiable DJBF input."""

class VerificationResult(str, Enum):
    FULL = "fully_verified"
    PARTIAL = "partially_verified"
    FAILED = "failed"
    NOT_CHECKED = "not_checked"

@dataclass(frozen=True)
class Profile:
    header_size: int
    suffix_off: int
    crc_init: int
    has_blake3: bool

PROFILE_V1 = Profile(0x25, 0x15, 0x00000000, False)
PROFILE_V2 = Profile(0x45, 0x35, 0x20240424, True)

@dataclass(frozen=True)
class DjbHeader:
    version: int
    generation: int
    profile: Profile
    crc: int
    size: int
    flags: int
    iv_salt: int
    suffix_size: int
    blake3: bytes | None
    @property
    def uses_ecb(self) -> bool: return bool(self.flags & FLAG_ECB)
    @property
    def uses_cbc(self) -> bool: return bool(self.flags & FLAG_CBC)
    @property
    def uses_fastlz(self) -> bool: return bool(self.flags & FLAG_FASTLZ)

_CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_TABLE.append(_c)

def crc32(data: bytes, init: int = 0) -> int:
    c = (~init) & 0xFFFFFFFF
    for b in data:
        c = _CRC_TABLE[(b ^ c) & 0xFF] ^ (c >> 8)
        c &= 0xFFFFFFFF
    return (~c) & 0xFFFFFFFF

def parse_header(data: bytes) -> DjbHeader:
    if len(data) < 6:
        raise DjbError("file is too short to contain a DJBF version")
    if data[:4] != MAGIC:
        raise DjbError("not a DJBF file (bad magic)")
    version = struct.unpack_from(">H", data, 4)[0]
    if 0x0100 <= version <= 0x01FF:
        generation, profile = 1, PROFILE_V1
    elif 0x0200 <= version <= 0x02FF:
        generation, profile = 2, PROFILE_V2
    else:
        raise DjbError(f"unsupported DJBF version 0x{version:04x}")
    if len(data) < profile.header_size:
        raise DjbError(f"truncated generation-{generation} header: {len(data)} < {profile.header_size} bytes")
    crc = struct.unpack_from("<I", data, 8)[0]
    size = struct.unpack_from("<Q", data, 12)[0]
    if size > MAX_PLAINTEXT_SIZE:
        raise DjbError(f"declared plaintext size {size} exceeds safety limit {MAX_PLAINTEXT_SIZE}")
    flags = data[0x14]
    if version < 0x0101: flags &= ~FLAG_FASTLZ
    if version < 0x0102: flags &= ~FLAG_CBC
    if flags & FLAG_ECB and flags & FLAG_CBC:
        raise DjbError("invalid header: AES-ECB and AES-CBC flags are mutually exclusive")
    suffix_size = data[profile.suffix_off + 15]
    if suffix_size > 15:
        raise DjbError(f"invalid displaced-tail length {suffix_size}; expected 0..15")
    digest = data[0x15:0x35] if profile.has_blake3 else None
    return DjbHeader(version, generation, profile, crc, size, flags, data[8], suffix_size, digest)

def derive_iv(salt: int, base: bytes, operation: str) -> bytes:
    if len(base) != 16: raise DjbError("AES IV base must be exactly 16 bytes")
    if operation == "mul": return bytes((salt * b) & 0xFF for b in base)
    if operation == "add": return bytes((b + salt) & 0xFF for b in base)
    raise DjbError(f"unknown IV derivation operation: {operation}")

def _copy_match(out: bytearray, ref: int, count: int, limit: int) -> None:
    if ref < 0: raise DjbError("FastLZ back-reference points before output buffer")
    if count < 0 or len(out) + count > limit: raise DjbError("FastLZ output exceeds declared plaintext size")
    for _ in range(count):
        if ref < 0 or ref >= len(out): raise DjbError("invalid FastLZ back-reference")
        out.append(out[ref]); ref += 1

def fastlz_decompress(data: bytes, maxout: int) -> bytes:
    """Strict FastLZ L1/L2 decoder; rejects truncated and over-expanding streams."""
    if not data: raise DjbError("empty FastLZ stream")
    if maxout < 0 or maxout > MAX_PLAINTEXT_SIZE: raise DjbError("invalid FastLZ output limit")
    level = (data[0] >> 5) + 1
    if level not in (1, 2): raise DjbError(f"unsupported FastLZ level {level}")
    ip, n, out = 1, len(data), bytearray()
    ctrl = data[0] & 31
    while True:
        if ctrl >= 32:
            length = (ctrl >> 5) - 1
            ofs = (ctrl & 31) << 8
            ref = len(out) - ofs - 1
            if length == 6:
                if level == 1:
                    if ip >= n: raise DjbError("truncated FastLZ L1 length extension")
                    length += data[ip]; ip += 1
                else:
                    while True:
                        if ip >= n: raise DjbError("truncated FastLZ L2 length extension")
                        code = data[ip]; ip += 1; length += code
                        if code != 255: break
            if ip >= n: raise DjbError("truncated FastLZ match offset")
            code = data[ip]; ip += 1
            ref -= code
            if level == 2 and code == 255 and ofs == (31 << 8):
                if ip + 2 > n: raise DjbError("truncated FastLZ far-distance offset")
                far = (data[ip] << 8) | data[ip + 1]; ip += 2
                ref = len(out) - far - _FAR_BASE
            _copy_match(out, ref, length + 3, maxout)
        else:
            count = ctrl + 1
            if ip + count > n: raise DjbError("truncated FastLZ literal run")
            if len(out) + count > maxout: raise DjbError("FastLZ output exceeds declared plaintext size")
            out.extend(data[ip:ip + count]); ip += count
        if len(out) == maxout: return bytes(out)
        if ip >= n: break
        ctrl = data[ip]; ip += 1
    if len(out) != maxout:
        raise DjbError(f"FastLZ output size mismatch: got {len(out)}, expected {maxout}")
    return bytes(out)

def _aes():
    try:
        from Crypto.Cipher import AES
        return AES
    except ImportError as exc:
        raise DjbError("AES support missing; install with: pip install pycryptodome") from exc

def decrypt_djb(data: bytes, build: str = "kakao") -> bytes:
    h = parse_header(data)
    key_info = KEYCHAIN.get((build.lower(), h.generation))
    if key_info is None: raise DjbError(f"no key for build={build!r}, generation={h.generation}")
    body = data[h.profile.header_size:]
    tail = data[h.profile.suffix_off:h.profile.suffix_off + h.suffix_size]
    ciphertext = body + tail
    if (h.uses_ecb or h.uses_cbc) and len(ciphertext) % 16: raise DjbError(f"ciphertext is not AES block-aligned ({len(ciphertext)} bytes)")
    if h.size and not ciphertext: raise DjbError("missing ciphertext for non-empty plaintext")
    key, iv_base, iv_op = key_info
    if h.uses_ecb:
        plaintext = _aes().new(key, _aes().MODE_ECB).decrypt(ciphertext)
    elif h.uses_cbc:
        plaintext = _aes().new(key, _aes().MODE_CBC, derive_iv(h.iv_salt, iv_base, iv_op)).decrypt(ciphertext)
    else:
        plaintext = ciphertext
    if h.uses_fastlz:
        return fastlz_decompress(plaintext, h.size)
    if len(plaintext) < h.size: raise DjbError(f"decrypted data too short: {len(plaintext)} < {h.size}")
    return plaintext[:h.size]

def verify(data: bytes, plaintext: bytes, build: str = "kakao") -> VerificationResult:
    h = parse_header(data)
    if len(plaintext) != h.size: return VerificationResult.FAILED
    if crc32(plaintext, h.profile.crc_init) != h.crc: return VerificationResult.FAILED
    if h.blake3 is None: return VerificationResult.FULL
    try:
        from blake3 import blake3
    except ImportError:
        return VerificationResult.PARTIAL
    return VerificationResult.FULL if blake3(plaintext).digest() == h.blake3 else VerificationResult.FAILED

def parse_records(plaintext: bytes, *, strict_utf8: bool = True) -> dict[str, dict[str, str]]:
    """Parse length-prefixed records with strict bounds and duplicate detection."""
    pos, total = 0, len(plaintext)
    def read_u32() -> int:
        nonlocal pos
        if pos + 4 > total: raise DjbError(f"truncated record stream at offset 0x{pos:x} (u32)")
        value = struct.unpack_from("<I", plaintext, pos)[0]; pos += 4
        return value
    def read_string() -> str:
        nonlocal pos
        size = read_u32()
        if size > MAX_STRING_SIZE: raise DjbError(f"string length {size} exceeds safety limit")
        if pos + size > total: raise DjbError(f"truncated string at offset 0x{pos:x}: need {size} bytes")
        raw = plaintext[pos:pos + size]; pos += size
        try: return raw.decode("utf-8", "strict" if strict_utf8 else "replace")
        except UnicodeDecodeError as exc: raise DjbError(f"invalid UTF-8 at offset 0x{pos - size:x}") from exc
    count = read_u32()
    if count > MAX_RECORDS: raise DjbError(f"record count {count} exceeds safety limit")
    records: dict[str, dict[str, str]] = {}
    for _ in range(count):
        field_count = read_u32()
        if field_count > MAX_FIELDS_PER_RECORD: raise DjbError("field count exceeds safety limit")
        fields: dict[str, str] = {}
        for _ in range(field_count):
            key, value = read_string(), read_string()
            if key in fields: raise DjbError(f"duplicate field name {key!r}")
            fields[key] = value
        name = read_string()
        if name in records: raise DjbError(f"duplicate record name {name!r}")
        records[name] = fields
    if pos != total: raise DjbError(f"trailing data after parse ({pos} != {total})")
    return records
