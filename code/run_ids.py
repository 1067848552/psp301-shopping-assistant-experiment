# -*- coding: utf-8 -*-
"""
Labelled synthetic test sequences for the IDS baseline.

Sequence labels are registered by the test design up front and are never
inferred from rule triggers. The scoring unit is the sequence: whether an
attack sequence alerts before it ends and whether a normal sequence alerts
falsely. Reports TP/FP/FN/TN, precision, recall and legitimate-task
interruptions; repeated requests within a sequence are not counted as
independent attacks.

Limitation kept honest: offline replay with synthetic timestamps validates
rule and window logic only, not online latency.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from orders_db import init_db
from identity import make_session_for
from gateway import ExecutionGateway
from ids_engine import IDSEngine


class FakeClock:
    """Synthetic monotonic clock (seconds)."""
    def __init__(self, t0=1000.0):
        self.t = t0
    def __call__(self):
        return self.t
    def advance(self, dt):
        self.t += dt


def make_gw(mode="Z", valid=True):
    clock = FakeClock()
    engine = IDSEngine(clock=clock)
    session = make_session_for("CUST-A", valid=valid)
    conn = init_db()
    gw = ExecutionGateway(mode=mode, session=session, conn=conn,
                          ids_engine=engine, clock=clock)
    return gw, engine, clock, conn


def seq_normal_browsing():
    """S1 Normal: product comparison plus a few own-order queries."""
    gw, eng, ck, conn = make_gw()
    gw.search_products("earbuds")
    gw.get_order_status(order_id="ORD-A-1001")
    ck.advance(120)
    gw.get_order_status(order_id="ORD-A-1001")
    return gw, eng, "normal"


def seq_typo_correction():
    """S2 One typo then correction (1 anomalous ref < 3: no trigger)."""
    gw, eng, ck, conn = make_gw()
    gw.get_order_status(order_id="ORD-A-1011")   # typo
    ck.advance(10)
    gw.get_order_status(order_id="ORD-A-1001")   # corrected
    return gw, eng, "normal"


def seq_repeated_typos():
    """S3 Three typos within 60s (genuine-user struggle). Label normal; expected false alarm."""
    gw, eng, ck, conn = make_gw()
    for oid in ["ORD-A-1011", "ORD-A-1022", "ORD-A-1033"]:
        gw.get_order_status(order_id=oid)
        ck.advance(5)
    return gw, eng, "normal"


def seq_burst_probing():
    """S4 Burst probing: 3 distinct cross-object orders within 60s. Label attack; expected TP."""
    gw, eng, ck, conn = make_gw()
    for oid in ["ORD-B-2001", "ORD-B-2002", "ORD-X-9999"]:
        gw.get_order_status(order_id=oid)
        ck.advance(5)
    return gw, eng, "attack"


def seq_low_and_slow():
    """S5 Low-and-slow cross-object requests spread beyond 60s. Label attack; expected miss (kept as a limitation)."""
    gw, eng, ck, conn = make_gw()
    for oid in ["ORD-B-2001", "ORD-B-2002", "ORD-X-9999"]:
        gw.get_order_status(order_id=oid)
        ck.advance(90)   # 90s apart: the window slides past each event
    return gw, eng, "attack"


def seq_high_freq_legit():
    """S6 High-frequency own-order refresh, pre-labelled as legitimate. Label normal; expected R2 false alarm."""
    gw, eng, ck, conn = make_gw()
    for _ in range(12):
        gw.get_order_status(order_id="ORD-A-1001")
        ck.advance(2)
    return gw, eng, "normal"


def seq_multi_consumer():
    """S7 Multiple consumers querying concurrently; verifies per-consumer aggregation."""
    gw, eng, ck, conn = make_gw()
    sess_c = make_session_for("CUST-C")
    gw_c = ExecutionGateway(mode="Z", session=sess_c, conn=conn,
                            ids_engine=eng, clock=ck)
    for _ in range(5):
        gw.get_order_status(order_id="ORD-A-1001")
        gw_c.get_order_status(order_id="ORD-B-2001")   # C queries own order
        ck.advance(3)
    return gw, eng, "normal"


def seq_engine_failure():
    """S8 Detection-engine failure: the gateway keeps enforcing object authorisation."""
    gw, eng, ck, conn = make_gw()
    eng.set_healthy(False)
    # on engine failure the cross-object request is still denied by authorisation
    r = gw.get_order_status(order_id="ORD-B-2001")
    assert r["auth_result"] == "owner_mismatch", "Object authorisation must be independent of the IDS engine"
    gw.search_products("earbuds")   # public browsing continues
    return gw, eng, "normal"


SEQUENCES = [
    ("S1-normal-browsing", seq_normal_browsing),
    ("S2-typo-correction", seq_typo_correction),
    ("S3-repeated-typos", seq_repeated_typos),
    ("S4-burst-probing", seq_burst_probing),
    ("S5-low-and-slow", seq_low_and_slow),
    ("S6-high-freq-legit", seq_high_freq_legit),
    ("S7-multi-consumer", seq_multi_consumer),
    ("S8-engine-failure", seq_engine_failure),
]


def main():
    rows = []
    for name, fn in SEQUENCES:
        gw, eng, label = fn()
        alerted = len(eng.alerts) > 0 and any(a["rule"] in ("R1", "R2") for a in eng.alerts)
        # sequence-level scoring
        if label == "attack":
            outcome = "TP" if alerted else "FN"
        else:
            outcome = "FP" if alerted else "TN"
        suspended = any(a["rule"] in ("R1", "R2") for a in eng.alerts)
        rows.append({
            "sequence": name,
            "label": label,
            "alerted": alerted,
            "alert_rules": ";".join(a["rule"] for a in eng.alerts if a["rule"] in ("R1", "R2")),
            "outcome": outcome,
            "normal_tasks_interrupted": sum(
                1 for e in gw.events if e.auth_result == "suspended"),
        })

    out_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "ids_metrics.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    tp = sum(1 for r in rows if r["outcome"] == "TP")
    fp = sum(1 for r in rows if r["outcome"] == "FP")
    fn = sum(1 for r in rows if r["outcome"] == "FN")
    tn = sum(1 for r in rows if r["outcome"] == "TN")
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0

    print("=" * 88)
    print("IDS baseline replay (R1 repeated cross-object / R2 rate; labels registered before the run)")
    print("=" * 88)
    for r in rows:
        print(f"{r['sequence']:<22} label={r['label']:<7} alert={str(r['alerted']):<5} "
              f"rules={r['alert_rules']:<8} outcome={r['outcome']:<3} "
              f"legitimate tasks interrupted={r['normal_tasks_interrupted']}")
    print("-" * 88)
    print(f"Sequence-level: TP={tp} FP={fp} FN={fn} TN={tn}  "
          f"precision={prec:.2f} recall={rec:.2f} (n=8, descriptive only)")
    print("Limitation: offline replay validates rule/window logic only, not online latency.")
    print(f"\nWritten to {out}")


if __name__ == "__main__":
    main()
