from cookierun_djb.core import VerificationResult, verify

def test_gen1_crc_verifies(make_header):
    payload = b"test payload"
    assert verify(make_header(1, len(payload), 0, payload), payload) == VerificationResult.FULL

def test_size_mismatch_fails(make_header):
    assert verify(make_header(1, 3, 0, b"abc"), b"no") == VerificationResult.FAILED
