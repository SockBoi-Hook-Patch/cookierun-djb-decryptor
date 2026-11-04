from cookierun_djb.core import DjbError, derive_iv, crc32, parse_header
import pytest

def test_crc32_standard_vector():
    assert crc32(b"123456789") == 0xCBF43926

def test_derive_iv_add():
    assert derive_iv(1, bytes(16), "add") == bytes([1] * 16)

def test_derive_iv_mul():
    assert derive_iv(7, bytes([2] * 16), "mul") == bytes([14] * 16)

def test_rejects_conflicting_cipher_flags(make_header):
    raw = bytearray(make_header(2))
    raw[0x14] = 0x03
    with pytest.raises(DjbError): parse_header(bytes(raw))
