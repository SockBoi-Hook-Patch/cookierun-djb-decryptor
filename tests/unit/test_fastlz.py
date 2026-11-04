import pytest
from cookierun_djb.core import DjbError, fastlz_decompress

def test_literal_run():
    assert fastlz_decompress(bytes([2]) + b"abc", 3) == b"abc"

def test_empty_stream_rejected():
    with pytest.raises(DjbError): fastlz_decompress(b"", 0)

def test_truncated_literal_rejected():
    with pytest.raises(DjbError): fastlz_decompress(bytes([4]) + b"ab", 5)

def test_output_limit_enforced():
    with pytest.raises(DjbError): fastlz_decompress(bytes([2]) + b"abc", 2)
