from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


SAMPLING_DOMAIN_VERSION = "1.0.0"


class SamplingOutcome:
    NOT_ENABLED = "not_enabled"
    IN_ALLOWLIST_OVERRIDE = "in_allowlist_override"
    OUT_ALLOWLIST_OVERRIDE = "out_allowlist_override"
    SAMPLED_IN = "sampled_in"
    SAMPLED_OUT = "sampled_out"
    OVERRIDDEN_FORCE = "overridden_force"


@dataclass
class SamplingDecision:
    sampled_in: bool
    rate_applied: float
    outcome: str
    allowlist_event_name: Optional[str] = None
    bucket_value: Optional[int] = None
    bucket_max: Optional[int] = None
    reason: Optional[str] = None
    token_version: str = SAMPLING_DOMAIN_VERSION


def compute_sampling_token(
    account_tag: Optional[str],
    event_name: str,
    session_tag: Optional[str] = None,
    extra_salt: Optional[str] = None,
) -> str:
    payload_parts = [
        account_tag or "anon",
        event_name,
        session_tag or "",
        extra_salt or "",
    ]
    payload = "|".join(payload_parts)
    hashed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return "st-v1:" + hashed[:8]


def deterministic_sample_decision(
    sampling_token: str,
    rate: float,
    bucket_max: int = 1_000_000,
) -> Tuple[bool, int]:
    if rate < 0.0:
        rate = 0.0
    if rate > 1.0:
        rate = 1.0
    if bucket_max < 1:
        bucket_max = 1
    if rate <= 0.0:
        return False, 0
    if rate >= 1.0:
        return True, bucket_max
    hash_val = int(hashlib.sha256(sampling_token.encode("utf-8")).hexdigest()[:12], 16)
    bucket = hash_val % bucket_max
    threshold = int(rate * bucket_max)
    return bucket < threshold, bucket


class Sampler:
    enabled: bool
    default_rate: float
    allowlist_overrides: Dict[str, float]
    bucket_max: int

    def __init__(
        self,
        enabled: bool = True,
        default_rate: float = 1.0,
        allowlist_overrides: Optional[Dict[str, float]] = None,
        bucket_max: int = 1_000_000,
    ) -> None:
        if not (0.0 <= default_rate <= 1.0):
            raise ValueError(f"default_rate must be in [0,1], got {default_rate}")
        self.enabled = enabled
        self.default_rate = default_rate
        self.allowlist_overrides = dict(allowlist_overrides) if allowlist_overrides is not None else {}
        self.bucket_max = bucket_max

    def decide(
        self,
        event_name: str,
        account_tag: Optional[str] = None,
        session_tag: Optional[str] = None,
        extra_salt: Optional[str] = None,
        force: Optional[bool] = None,
    ) -> SamplingDecision:
        if force is True:
            return SamplingDecision(
                sampled_in=True,
                rate_applied=1.0,
                outcome=SamplingOutcome.OVERRIDDEN_FORCE,
                reason="force_true",
            )
        if force is False:
            return SamplingDecision(
                sampled_in=False,
                rate_applied=0.0,
                outcome=SamplingOutcome.OVERRIDDEN_FORCE,
                reason="force_false",
            )
        if not self.enabled:
            return SamplingDecision(
                sampled_in=True,
                rate_applied=1.0,
                outcome=SamplingOutcome.NOT_ENABLED,
                reason="sampling_disabled_treated_as_in",
            )
        effective_rate = self.allowlist_overrides.get(event_name, self.default_rate)
        override_applied = event_name in self.allowlist_overrides
        token = compute_sampling_token(account_tag, event_name, session_tag, extra_salt)
        sampled_in, bucket = deterministic_sample_decision(token, effective_rate, self.bucket_max)
        if override_applied:
            outcome = SamplingOutcome.IN_ALLOWLIST_OVERRIDE if sampled_in else SamplingOutcome.OUT_ALLOWLIST_OVERRIDE
        else:
            outcome = SamplingOutcome.SAMPLED_IN if sampled_in else SamplingOutcome.SAMPLED_OUT
        return SamplingDecision(
            sampled_in=sampled_in,
            rate_applied=effective_rate,
            outcome=outcome,
            allowlist_event_name=event_name if override_applied else None,
            bucket_value=bucket,
            bucket_max=self.bucket_max,
            token_version=SAMPLING_DOMAIN_VERSION,
        )
