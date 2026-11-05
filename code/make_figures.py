# -*- coding: utf-8 -*-
"""
Figure generation: F2 results table and F3 IDS timeline.

F2: Group B X/Y comparison table (source of report Table 1).
F3: IDS timeline for the burst-probing sequence (event stream, R1 trigger,
300s suspension window).
"""
import csv
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.normpath(os.path.join(HERE, "..", "results"))
sys.path.insert(0, HERE)


def make_f2():
    """F2: formatted Group B comparison table from the CSV produced by run_group_b.py."""
    src = os.path.join(RESULTS, "b_group_results.csv")
    if not os.path.exists(src):
        print("Run run_group_b.py first"); return
    with open(src, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    out = os.path.join(RESULTS, "F2_table1_source.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("| Config | Case | Request | Auth result | Data returned | Non-A data | Error message |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for r in rows:
            req = r["description"].split("(")[0].strip()
            non_a = r["returned_non_A_data"] == "True"  # CSV booleans are strings
            f.write(f"| {r['mode']} | {r['case_id']} | {req} "
                    f"| {r['auth_result']} | {r['returned_fields'] or '—'} "
                    f"| {'**YES**' if non_a else 'no'} "
                    f"| {r['error_message'] or '—'} |\n")
    print("F2 table source ->", out)


def make_f3():
    """F3: replay S4 (burst probing) and plot the event timeline, R1 trigger and 300s suspension."""
    from orders_db import init_db
    from identity import make_session_for
    from gateway import ExecutionGateway
    from ids_engine import IDSEngine

    class Clock:
        def __init__(self): self.t = 1000.0
        def __call__(self): return self.t
        def advance(self, dt): self.t += dt

    clock = Clock()
    engine = IDSEngine(clock=clock)
    conn = init_db()
    gw = ExecutionGateway(mode="Z", session=make_session_for("CUST-A"),
                          conn=conn, ids_engine=engine, clock=clock)

    events_t, events_label = [], []
    for oid in ["ORD-B-2001", "ORD-B-2002", "ORD-X-9999"]:
        t_before = clock.t
        gw.get_order_status(order_id=oid)
        for e in gw.events:
            if e.ts >= t_before and e.tool_name == "get_order_status":
                events_t.append(e.ts); events_label.append(e.auth_result)
        clock.advance(5)

    alert = next(a for a in engine.alerts if a["rule"] == "R1")
    fig, ax = plt.subplots(figsize=(8, 3.6))
    colors = {"owner_mismatch": "#cc3311", "not_found": "#ee7733",
              "allow": "#228833", "suspended": "#8899aa"}
    offsets = [(-28, 12), (0, -18), (30, 12)]   # stagger labels to avoid overlap
    for (t, lab), (dx, dy) in zip(zip(events_t, events_label), offsets):
        ax.scatter(t, 1, s=90, color=colors.get(lab, "#888888"), zorder=3)
        ax.annotate(lab, (t, 1), textcoords="offset points", xytext=(dx, dy),
                    ha="center", fontsize=8)
    ax.axvline(alert["ts"], color="#228833", ls="--", lw=1.5,
               label=f"R1 alert (t={alert['ts']:.0f}s): {alert['detail']}")
    # 300s suspension annotated with an arrow to keep the view on the events
    ax.annotate("", xy=(alert["ts"] + 55, 1.30),
                xytext=(alert["ts"], 1.30),
                arrowprops=dict(arrowstyle="->", color="#226633", lw=1.2))
    ax.annotate("order queries suspended for 300s\n(total, extends beyond view);\npublic browsing continues",
                (alert["ts"] + 3, 1.36), ha="left", va="top",
                fontsize=8, color="#226633")
    ax.set_xlim(events_t[0] - 8, alert["ts"] + 80)
    ax.set_ylim(0.55, 1.4); ax.set_yticks([])
    ax.set_xlabel("Synthetic time (s) — offline replay only, no wall-clock latency claim")
    ax.set_title("F3: R1 collective-anomaly trigger on burst cross-object probing")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(alpha=0.25, axis="x")
    fig.tight_layout()
    out = os.path.join(RESULTS, "fig_ids_timeline.png")
    fig.savefig(out, dpi=150)
    print("F3 figure ->", out)


def make_b_group_fig():
    """Additional figure: X/Y comparison bars."""
    src = os.path.join(RESULTS, "b_group_results.csv")
    with open(src, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    cases = ["B1", "B2", "B3", "B4", "B5"]
    def ok_of(mode, case):
        r = next(r for r in rows if r["mode"] == mode and r["case_id"] == case)
        return 1 if r["ok"] == "True" else 0   # CSV booleans are strings

    x_data = [ok_of("X", c) for c in cases]
    y_data = [ok_of("Y", c) for c in cases]
    fig, ax = plt.subplots(figsize=(7, 3.6))
    xs = range(len(cases))
    ax.bar([x - 0.18 for x in xs], x_data, 0.36, color="#cc3311",
           label="X: ownership check OFF (induced failure baseline)")
    ax.bar([x + 0.18 for x in xs], y_data, 0.36, color="#228833",
           label="Y: server-side authorization ON")
    ax.set_xticks(list(xs)); ax.set_xticklabels(cases)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["denied", "data returned"])
    ax.set_title("F2-fig: cross-order request outcomes, X vs Y (synthetic)")
    ax.legend(fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.16),
              ncol=1, framealpha=1)
    fig.subplots_adjust(bottom=0.24)
    out = os.path.join(RESULTS, "fig_b_group_xy.png")
    fig.savefig(out, dpi=150)
    print("Group B comparison figure ->", out)


if __name__ == "__main__":
    make_f2()
    make_f3()
    make_b_group_fig()
