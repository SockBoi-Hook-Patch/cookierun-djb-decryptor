"""Experimental DJBF writer. Supports raw (uncompressed) payloads only."""
from __future__ import annotations
import struct
from pathlib import Path
from .core import DjbError, KEYCHAIN, PROFILE_V1, PROFILE_V2, FLAG_CBC, FLAG_ECB, crc32, derive_iv, decrypt_djb, verify, VerificationResult

def forge_djb(plaintext: bytes, *, generation: int = 2, build: str = "kakao", mode: str = "cbc", version: int | None = None) -> bytes:
    """Build a DJBF container and verify it by decrypting it again."""
    if generation not in (1, 2): raise DjbError("generation must be 1 or 2")
    build = build.lower()
    key_info = KEYCHAIN.get((build, generation))
    if key_info is None: raise DjbError(f"no key for build={build!r}, generation={generation}")
    if mode not in ("cbc", "ecb"): raise DjbError("mode must be 'cbc' or 'ecb'")
    if len(plaintext) > 512 * 1024 * 1024: raise DjbError("plaintext exceeds safety limit")
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise DjbError("AES support missing; install pycryptodome") from exc
    profile = PROFILE_V2 if generation == 2 else PROFILE_V1
    ver = version if version is not None else (0x0200 if generation == 2 else 0x0103)
    if generation == 1 and not 0x0100 <= ver <= 0x01FF: raise DjbError("Gen1 version must be 0x0100..0x01ff")
    if generation == 2 and not 0x0200 <= ver <= 0x02FF: raise DjbError("Gen2 version must be 0x0200..0x02ff")
    crc = crc32(plaintext, profile.crc_init)
    salt = crc & 0xFF
    key, iv_base, iv_op = key_info
    padded = plaintext + b"\0" * ((-len(plaintext)) % 16)
    flags = FLAG_CBC if mode == "cbc" else FLAG_ECB
    if mode == "cbc": ciphertext = AES.new(key, AES.MODE_CBC, derive_iv(salt, iv_base, iv_op)).encrypt(padded)
    else: ciphertext = AES.new(key, AES.MODE_ECB).encrypt(padded)
    digest = b""
    if generation == 2:
        try:
            from blake3 import blake3
        except ImportError as exc:
            raise DjbError("Gen2 Forge requires BLAKE3; install with pip install '.[verify]'") from exc
        digest = blake3(plaintext).digest()
    header = b"DJBF" + struct.pack(">H", ver) + b"\0\0"
    header += struct.pack("<I", crc) + struct.pack("<Q", len(plaintext)) + bytes([flags]) + digest
    header += b"\0" * 16
    if len(header) != profile.header_size: raise DjbError("internal header size error")
    result = header + ciphertext
    recovered = decrypt_djb(result, build)
    if recovered != plaintext: raise DjbError("Forge round-trip mismatch")
    verdict = verify(result, recovered, build)
    if verdict != VerificationResult.FULL: raise DjbError(f"Forge integrity check did not fully pass: {verdict.value}")
    return result

def forge_file(source: str | Path, destination: str | Path, **kwargs) -> None:
    payload = Path(source).read_bytes()
    result = forge_djb(payload, **kwargs)
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_name(target.name + ".tmp")
    try:
        temp.write_bytes(result)
        temp.replace(target)
    finally:
        if temp.exists(): temp.unlink()
