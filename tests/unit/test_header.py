import pytest
from cookierun_djb.core import DjbError, parse_header

def test_gen1_header(make_header):
    h = parse_header(make_header(1))
    assert h.generation == 1 and h.version == 0x0103

def test_gen2_header(make_header):
    h = parse_header(make_header(2))
    assert h.generation == 2 and h.profile.header_size == 0x45

@pytest.mark.parametrize("data", [b"", b"DJBF", b"NOPE\0\0", b"DJBF\x03\0"])
def test_rejects_short_or_bad_header(data):
    with pytest.raises(DjbError): parse_header(data)

def test_rejects_unknown_version():
    with pytest.raises(DjbError): parse_header(b"DJBF\x03\x00" + b"\0" * 100)

def test_rejects_oversized_plaintext(make_header):
    h = bytearray(make_header(2))
    h[12:20] = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    with pytest.raises(DjbError): parse_header(bytes(h))
