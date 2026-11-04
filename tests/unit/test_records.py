import struct
import pytest
from cookierun_djb.core import DjbError, parse_records

def s(value):
    b = value.encode()
    return struct.pack("<I", len(b)) + b

def test_empty_record_table():
    assert parse_records(struct.pack("<I", 0)) == {}

def test_one_record():
    data = struct.pack("<II", 1, 1) + s("key") + s("value") + s("record")
    assert parse_records(data) == {"record": {"key": "value"}}

def test_truncated_record_rejected():
    with pytest.raises(DjbError): parse_records(b"\x01\0\0\0")

def test_duplicate_field_rejected():
    data = struct.pack("<II", 1, 2) + s("k") + s("a") + s("k") + s("b") + s("r")
    with pytest.raises(DjbError): parse_records(data)
