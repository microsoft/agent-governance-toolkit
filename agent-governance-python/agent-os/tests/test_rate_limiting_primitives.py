# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest

from agent_os.policies import RateLimitConfig, RateLimitExceeded, TokenBucket


def test_rate_limit_config_exposes_rate_alias() -> None:
    config = RateLimitConfig(capacity=5.0, refill_rate=2.0)
    assert config.rate == 2.0


def test_token_bucket_from_config_supports_zero_refill() -> None:
    bucket = TokenBucket.from_config(
        RateLimitConfig(capacity=3.0, refill_rate=0.0, initial_tokens=1.0)
    )
    assert bucket.consume() is True
    assert bucket.tokens_available() == pytest.approx(0.0, abs=0.01)
    assert bucket.time_until_available() == float("inf")


def test_rate_limit_exceeded_is_exception() -> None:
    exc = RateLimitExceeded("slow down")
    assert isinstance(exc, Exception)
    assert str(exc) == "slow down"
