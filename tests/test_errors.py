import pytest

from fingerprintiq._errors import (
    APIError,
    FingerprintIQError,
    RateLimitError,
)
from fingerprintiq._errors import (
    TimeoutError as FIQTimeoutError,
)


def test_api_error_is_fingerprintiq_error():
    err = APIError("bad request", status_code=400, body="invalid")
    assert isinstance(err, FingerprintIQError)
    assert err.status_code == 400
    assert err.body == "invalid"


def test_rate_limit_error_carries_retry_after():
    err = RateLimitError("too many requests", retry_after=30)
    assert isinstance(err, APIError)
    assert err.status_code == 429
    assert err.retry_after == 30


def test_timeout_error_hierarchy():
    err = FIQTimeoutError("timed out after 5s")
    assert isinstance(err, FingerprintIQError)


def test_base_error_inherits_from_exception():
    with pytest.raises(FingerprintIQError):
        raise FingerprintIQError("boom")
