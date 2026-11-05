# -*- coding: utf-8 -*-
"""Tool execution gateway for the shopping-assistant experiment.

Configuration switch (single variable under test):
  X: induced failure baseline — ownership check disabled (synthetic only)
  Y: enforcement configuration — identity taken from the trusted session and
     order ownership checked on every request
  Z: Y + independent IDS and response enabled

Reporting rules:
- Preset requests demonstrate enforcement behaviour only, not model
  persuasion;
- An authorisation denial is authorisation control, not an IDS alert;
- X and Y differ only in the object-ownership check.
"""
import hashlib
import time
from orders_db import ALLOWED_FIELDS

GENERIC_ORDER_ERROR = "Unable to provide this order information."
GENERIC_SCHEMA_ERROR = "Invalid tool invocation."
SUSPENDED_MSG = "Order queries are temporarily unavailable for this account."

VALID_MODES = ("X", "Y", "Z")


class GatewayEvent:
    """Minimal detection event. Contains no model content, order plaintext,
    names, addresses or payment data."""

    def __init__(self, consumer_ref, tool_name, order_ref_raw,
                 auth_result, fields_returned, ts=None):
        self.ts = time.time() if ts is None else ts
        self.request_id = f"req-{int(self.ts*1000)}-{hashlib.md5(str(time.time()).encode()).hexdigest()[:6]}"
        self.session_ref = "sim-session"
        self.consumer_ref = consumer_ref
        self.tool_name = tool_name
        # hashed order reference: no plaintext order IDs in detection logs
        self.order_ref_hash = hashlib.sha256(
            str(order_ref_raw).encode()).hexdigest()[:12]
        self.auth_result = auth_result   # allow / owner_mismatch / not_found / schema_rejected / session_invalid / suspended
        self.fields_returned = fields_returned


class ExecutionGateway:
    def __init__(self, mode: str, session, conn, ids_engine=None,
                 clock=None):
        assert mode in VALID_MODES, f"mode must be one of {VALID_MODES}"
        self.mode = mode
        self.session = session
        self.conn = conn
        self.ids_engine = ids_engine   # only injected in mode Z
        self.clock = clock or time.time
        self.events = []

    def _emit(self, ev: GatewayEvent):
        self.events.append(ev)
        if self.ids_engine is not None:
            self.ids_engine.ingest(ev)

    def _lookup(self, order_id: str):
        row = self.conn.execute(
            "SELECT order_id, owner_id, product_title, status, "
            "estimated_delivery_date, recipient_name, delivery_address, "
            "payment_reference FROM orders WHERE order_id = ?",
            (order_id,)).fetchone()
        return row

    # ---------- Tool 1: search_products (public data, no consumer records) ----------

    def search_products(self, query: str) -> dict:
        """Public product catalog search. Content is treated as untrusted
        business data, never as operational instructions."""
        q = str(query).lower()
        hits = []
        for pid, name, desc in self.conn.execute(
                "SELECT product_id, name, description FROM products").fetchall():
            if q and (q in name.lower() or q in desc.lower()):
                hits.append({"product_id": pid, "name": name, "description": desc})
        return {"results": hits}

    # ---------- Tool 2: get_order_status (protected) ----------

    def get_order_status(self, **kwargs) -> dict:
        """Protected order lookup. The model may pass only order_id; any
        extra parameters are rejected at the gateway."""
        consumer = self.session.consumer_ref
        ts = self.clock()

        # 1. session validity and tool permission (identity cannot be
        #    overridden by model arguments)
        if not self.session.is_valid():
            ev = GatewayEvent(consumer, "get_order_status",
                              kwargs.get("order_id", ""), "session_invalid", 0, ts)
            self._emit(ev)
            return {"ok": False, "error": GENERIC_ORDER_ERROR,
                    "auth_result": "session_invalid"}

        # 2. is this consumer's order tool under an IDS suspension?
        if self.ids_engine is not None and self.ids_engine.is_suspended(consumer, ts):
            ev = GatewayEvent(consumer, "get_order_status",
                              kwargs.get("order_id", ""), "suspended", 0, ts)
            self._emit(ev)
            return {"ok": False, "error": SUSPENDED_MSG,
                    "auth_result": "suspended"}

        # 3. strict parameter validation + order_id format check
        if set(kwargs.keys()) != {"order_id"} or not isinstance(
                kwargs.get("order_id"), str) or not kwargs["order_id"]:
            ev = GatewayEvent(consumer, "get_order_status",
                              str(kwargs), "schema_rejected", 0, ts)
            self._emit(ev)
            return {"ok": False, "error": GENERIC_SCHEMA_ERROR,
                    "auth_result": "schema_rejected"}

        order_id = kwargs["order_id"]
        row = self._lookup(order_id)

        # 4. object-ownership decision (mode X disables the check: induced
        #    failure baseline)
        if row is None:
            ev = GatewayEvent(consumer, "get_order_status",
                              order_id, "not_found", 0, ts)
            self._emit(ev)
            # identical message to owner_mismatch: no existence leakage
            return {"ok": False, "error": GENERIC_ORDER_ERROR,
                    "auth_result": "not_found"}

        owner = row[1]
        if self.mode in ("Y", "Z"):
            if owner != self.session.consumer_ref:
                ev = GatewayEvent(consumer, "get_order_status",
                                  order_id, "owner_mismatch", 0, ts)
                self._emit(ev)
                return {"ok": False, "error": GENERIC_ORDER_ERROR,
                        "auth_result": "owner_mismatch"}

        # 5. four-field allowlist projection (decoy fields never returned)
        record = dict(zip(["order_id", "owner_id", "product_title", "status",
                           "estimated_delivery_date", "recipient_name",
                           "delivery_address", "payment_reference"], row))
        projected = {k: record[k] for k in ALLOWED_FIELDS}
        ev = GatewayEvent(consumer, "get_order_status",
                          order_id, "allow", len(projected), ts)
        self._emit(ev)

        # 6. minimal event emitted above, consumed by the IDS engine
        # 7. return value (model context) and final display are judged
        #    separately
        return {"ok": True, "order": projected, "auth_result": "allow"}

    def record_disclosure(self, consumer_ref: str, order_ids_shown: list):
        """Step 7 helper: record what the final answer actually displayed."""
        self.events.append(GatewayEvent(
            consumer_ref, "final_response", ",".join(order_ids_shown),
            "disclosure_checked", len(order_ids_shown)))
