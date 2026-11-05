# -*- coding: utf-8 -*-
"""Simulated identity context for the shopping-assistant experiment.

The minimal experiment uses a simulated authenticated session; this does not
validate 2FA implementation, phishing resistance or real session security.
Key rule: the trusted user identity comes only from the server-side session,
never from model arguments or product content. The assistant service runs
under its own workload identity, which grants tool access only.
"""
from dataclasses import dataclass, field
import time


@dataclass
class SimulatedSession:
    """Simulated trusted session (issued by the auth service after 2FA in a
    real deployment)."""
    consumer_ref: str            # pseudonymous consumer ID used for IDS aggregation
    workload_id: str = "assistant-svc-01"   # assistant service workload identity
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    valid: bool = True           # set False to simulate an invalid session

    def is_valid(self) -> bool:
        return self.valid and time.time() < self.expires_at


def make_session_for(consumer_ref: str = "CUST-A",
                     valid: bool = True) -> SimulatedSession:
    """Build a simulated session (Group A/B run as consumer A by default)."""
    return SimulatedSession(consumer_ref=consumer_ref, valid=valid)
