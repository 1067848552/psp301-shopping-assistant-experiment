# -*- coding: utf-8 -*-
"""Independent rule-based IDS for the shopping-assistant experiment.

Application-layer baseline that flags anomalous tool-access patterns. It does
not cover network/host intrusion and does not detect natural-language prompt
injection itself. The authorisation engine decides whether a single request is
legal; the IDS correlates cross-request patterns and drives session response.

Baseline rules (starting values, not tuned optima):
  R1  Repeated cross-object probing: >= 3 distinct order refs with
      owner_mismatch / not_found for the same consumer within a rolling 60s
      window -> alert + suspend that consumer's order queries for 300s
  R2  Query-rate anomaly: >= 12 get_order_status attempts within 60s
      -> rate alert + suspension

Design notes:
- Events are aggregated by consumer_ref (not session), so switching sessions
  does not reset counters; a suspension affects only that consumer's order
  tool, never the shared assistant workload identity.
- Requests during a suspension are rejected before data access and do not
  extend the window or regenerate the same alert.
- If the engine fails, the gateway keeps enforcing full object authorisation
  and emits a separate health alert (availability/safety trade-off).
"""
import time
from collections import defaultdict, deque

WINDOW_SEC = 60.0
R1_MIN_DISTINCT = 3
R2_MIN_ATTEMPTS = 12
SUSPEND_SEC = 300.0

ANOMALY_RESULTS = {"owner_mismatch", "not_found"}


class IDSEngine:
    def __init__(self, clock=None, window_sec=WINDOW_SEC,
                 r1_min_distinct=R1_MIN_DISTINCT, r2_min_attempts=R2_MIN_ATTEMPTS,
                 suspend_sec=SUSPEND_SEC):
        self.clock = clock or time.time
        self.window = window_sec
        self.r1_min = r1_min_distinct
        self.r2_min = r2_min_attempts
        self.suspend_sec = suspend_sec
        # consumer_ref -> deque[(ts, order_ref_hash, auth_result)]
        self._events = defaultdict(deque)
        # consumer_ref -> suspension expiry (None = not suspended)
        self._suspended_until = defaultdict(lambda: None)
        self.alerts = []
        self.healthy = True

    def ingest(self, event):
        if not self.healthy:
            return                 # on failure events are dropped; a health
                                   # alert is raised by the caller
        if event.tool_name != "get_order_status":
            return                 # only the order tool is observed
        self._events[event.consumer_ref].append(
            (event.ts, event.order_ref_hash, event.auth_result))
        self._evaluate(event)

    def _evaluate(self, event):
        c = event.consumer_ref
        now = event.ts
        dq = self._events[c]
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

        already_suspended = self._suspended_until[c] is not None

        anomalous_refs = {h for (t, h, r) in dq if r in ANOMALY_RESULTS}
        attempts = len(dq)

        rule_hit, detail = None, None
        if len(anomalous_refs) >= self.r1_min:
            rule_hit, detail = "R1", f"{len(anomalous_refs)} distinct anomalous order refs in {self.window:.0f}s"
        elif attempts >= self.r2_min:
            rule_hit, detail = "R2", f"{attempts} order-status attempts in {self.window:.0f}s"

        if rule_hit and not already_suspended:
            self._suspended_until[c] = now + self.suspend_sec
            self.alerts.append({
                "ts": now, "consumer_ref": c, "rule": rule_hit,
                "detail": detail,
                "window_state": {"attempts": attempts,
                                 "distinct_anomalous_refs": len(anomalous_refs)},
            })

    def is_suspended(self, consumer_ref, now=None) -> bool:
        if not self.healthy:
            return False
        until = self._suspended_until[consumer_ref]
        now = self.clock() if now is None else now
        if until is not None and now >= until:
            # expiry: clear the rule window and resume normal authorisation
            self._suspended_until[consumer_ref] = None
            self._events[consumer_ref].clear()
            return False
        return until is not None

    def set_healthy(self, healthy: bool):
        """Simulate detection-engine failure (authorisation is unaffected)."""
        self.healthy = healthy
        if not healthy:
            self.alerts.append({
                "ts": self.clock(), "consumer_ref": "*",
                "rule": "HEALTH",
                "detail": "IDS engine unavailable; object authorisation continues",
            })
