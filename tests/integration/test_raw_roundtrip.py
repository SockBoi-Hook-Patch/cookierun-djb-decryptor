from cookierun_djb.core import parse_header

def test_header_roundtrip_fixture(make_header):
    blob = make_header(2, 0)
    h = parse_header(blob)
    assert h.generation == 2
    assert h.size == 0
