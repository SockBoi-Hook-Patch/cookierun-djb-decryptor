import struct
import pytest
from cookierun_djb.core import PROFILE_V1, PROFILE_V2, crc32

@pytest.fixture
def make_header():
    def _make(generation=2, size=0, flags=0, payload=b""):
        p = PROFILE_V2 if generation == 2 else PROFILE_V1
        ver = 0x0200 if generation == 2 else 0x0103
        checksum = crc32(payload, p.crc_init)
        h = b"DJBF" + struct.pack(">H", ver) + b"\0\0"
        h += struct.pack("<I", checksum) + struct.pack("<Q", size) + bytes([flags])
        if generation == 2: h += b"\0" * 32
        h += b"\0" * 15 + b"\0"
        return h
    return _make
