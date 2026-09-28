#!/usr/bin/env python3
"""Durable local store for Checklane paid reports and the purchase ledger.

Stdlib only (sqlite3). Replaces the old in-memory REPORT_CACHE and the
purchases.jsonl ledger so a paid report survives process restarts.

Concurrency model (single process, ThreadingHTTPServer):
  - one shared connection (check_same_thread=False) guarded by a
    module-level threading.RLock: every public function takes the lock, so
    concurrent webhook redeliveries cannot interleave a check-then-act.
  - PRAGMA journal_mode=WAL + busy_timeout: readers never block writers if
    a second connection ever opens the file (tests, tools).
  - PRIMARY KEYs make fulfillment naturally idempotent: a redelivered
    checkout.session.completed inserts the same session_id twice and the
    second insert is ignored; receipt-sent state lives in the purchases row,
    not in a process-local set.

Tables:
  reports(report_token TEXT PRIMARY KEY, stripe_session_id TEXT,
          domain TEXT, report_json TEXT NOT NULL, paid INTEGER NOT NULL
          DEFAULT 0, created_at INTEGER NOT NULL)
  purchases(stripe_session_id TEXT PRIMARY KEY, email TEXT,
            amount_cents INTEGER, currency TEXT, status TEXT NOT NULL
            DEFAULT 'paid', payment_intent TEXT, report_token TEXT,
            domain TEXT, score INTEGER, receipt_sent_at INTEGER,
            created_at INTEGER NOT NULL)
  charge_events(event_id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                charge_id TEXT, payment_intent TEXT, amount_cents INTEGER,
                currency TEXT, dispute_reason TEXT, created_at INTEGER
                NOT NULL)

TTL semantics (compatible with the old in-memory cache): unpaid (free-audit)
reports expire after REPORT_TTL_S (2h): get_report returns None for them
past the TTL. Paid reports never expire.

Durability note: on the Render free tier the disk is ephemeral across
deploys, so this DB survives process restarts but not redeploys. The buyer
receipt email (permanent /report?session_id= link) and the Stripe dashboard
remain the durable records; the purchase ledger is also mirrored as rich
JSON events to stdout, which Render retains.
"""

import json
import os
import sqlite3
import threading
import time

_LOCK = threading.RLock()
_CONN = None
_DB_PATH = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_token      TEXT PRIMARY KEY,
    stripe_session_id TEXT,
    domain            TEXT,
    report_json       TEXT NOT NULL,
    paid              INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS purchases (
    stripe_session_id TEXT PRIMARY KEY,
    email             TEXT,
    amount_cents      INTEGER,
    currency          TEXT,
    status            TEXT NOT NULL DEFAULT 'paid',
    payment_intent    TEXT,
    report_token      TEXT,
    domain            TEXT,
    score             INTEGER,
    receipt_sent_at   INTEGER,
    created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS charge_events (
    event_id       TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    charge_id      TEXT,
    payment_intent TEXT,
    amount_cents   INTEGER,
    currency       TEXT,
    dispute_reason TEXT,
    created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_purchases_payment_intent
    ON purchases(payment_intent);
"""


def configure(db_path):
    """Point the store at a DB file (creates it). Safe to call twice."""
    global _CONN, _DB_PATH
    with _LOCK:
        if _DB_PATH == db_path and _CONN is not None:
            return
        if _CONN is not None:
            try:
                _CONN.close()
            except Exception:
                pass
            _CONN = None
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        _CONN = sqlite3.connect(db_path, check_same_thread=False,
                                timeout=10.0)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode=WAL;")
        _CONN.execute("PRAGMA busy_timeout=10000;")
        _CONN.execute("PRAGMA synchronous=NORMAL;")
        with _CONN:
            _CONN.executescript(_SCHEMA)
        _DB_PATH = db_path


def _conn():
    if _CONN is None:
        raise RuntimeError("store.configure(db_path) has not been called")
    return _CONN


def close():
    """Close the connection (tests / restart simulation)."""
    global _CONN, _DB_PATH
    with _LOCK:
        if _CONN is not None:
            try:
                _CONN.close()
            except Exception:
                pass
            _CONN = None
        _DB_PATH = None


# -- reports ------------------------------------------------------------ #
def save_report(report_token, report, stripe_session_id=None, domain=None,
                paid=0, created_at=None):
    """Insert or replace a report. report is the audit dict."""
    if not report_token:
        raise ValueError("report_token is required")
    ts = int(created_at if created_at is not None else time.time())
    with _LOCK:
        _conn().execute(
            "INSERT OR REPLACE INTO reports "
            "(report_token, stripe_session_id, domain, report_json, paid,"
            " created_at) VALUES (?,?,?,?,?,?)",
            (report_token, stripe_session_id, domain,
             json.dumps(report), 1 if paid else 0, ts))
        _conn().commit()


def get_report(report_token, ttl_s=None):
    """Return the stored report dict, or None.

    Unpaid reports older than ttl_s (default: no expiry check here, the
    caller passes REPORT_TTL_S) are treated as expired and pruned.
    Paid reports never expire.
    """
    with _LOCK:
        row = _conn().execute(
            "SELECT report_json, paid, created_at FROM reports"
            " WHERE report_token=?", (report_token,)).fetchone()
        if row is None:
            return None
        if not row["paid"] and ttl_s is not None:
            if time.time() - row["created_at"] > ttl_s:
                _conn().execute("DELETE FROM reports WHERE report_token=?",
                                (report_token,))
                _conn().commit()
                return None
        try:
            return json.loads(row["report_json"])
        except Exception:
            return None


def prune_unpaid(ttl_s):
    """Delete unpaid reports older than ttl_s. Returns rows deleted."""
    cutoff = int(time.time() - ttl_s)
    with _LOCK:
        cur = _conn().execute(
            "DELETE FROM reports WHERE paid=0 AND created_at < ?", (cutoff,))
        _conn().commit()
        return cur.rowcount


# -- purchases ----------------------------------------------------------- #
def record_purchase(session_id, email=None, amount_cents=None, currency=None,
                    status="paid", payment_intent=None, report_token=None,
                    domain=None, score=None):
    """Idempotent purchase insert. Returns True if this call created the row,
    False if the session was already recorded (e.g. webhook redelivery)."""
    with _LOCK:
        cur = _conn().execute(
            "INSERT OR IGNORE INTO purchases "
            "(stripe_session_id, email, amount_cents, currency, status,"
            " payment_intent, report_token, domain, score, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (session_id, email, amount_cents, currency, status,
             payment_intent, report_token, domain, score,
             int(time.time())))
        _conn().commit()
        return cur.rowcount == 1


def get_purchase(session_id):
    with _LOCK:
        row = _conn().execute(
            "SELECT * FROM purchases WHERE stripe_session_id=?",
            (session_id,)).fetchone()
        return dict(row) if row else None


def set_purchase_status(session_id, status):
    with _LOCK:
        cur = _conn().execute(
            "UPDATE purchases SET status=? WHERE stripe_session_id=?",
            (status, session_id))
        _conn().commit()
        return cur.rowcount


def set_purchase_status_by_payment_intent(payment_intent, status):
    """Mark purchase(s) for a refund/dispute. Returns rows updated."""
    if not payment_intent:
        return 0
    with _LOCK:
        cur = _conn().execute(
            "UPDATE purchases SET status=? WHERE payment_intent=?",
            (status, payment_intent))
        _conn().commit()
        return cur.rowcount


def receipt_sent(session_id):
    with _LOCK:
        row = _conn().execute(
            "SELECT receipt_sent_at FROM purchases WHERE stripe_session_id=?",
            (session_id,)).fetchone()
        return bool(row and row["receipt_sent_at"])


def mark_receipt_sent(session_id):
    with _LOCK:
        _conn().execute(
            "UPDATE purchases SET receipt_sent_at=? WHERE stripe_session_id=?",
            (int(time.time()), session_id))
        _conn().commit()


def purchase_count():
    with _LOCK:
        return _conn().execute(
            "SELECT COUNT(*) FROM purchases").fetchone()[0]


# -- charge events (refunds / disputes, idempotent on Stripe event id) ----- #
def record_charge_event(event_id, kind, charge_id=None, payment_intent=None,
                        amount_cents=None, currency=None, dispute_reason=None):
    """Idempotent charge-event insert. Returns True if new, False if this
    Stripe event id was already recorded (redelivery)."""
    if not event_id:
        raise ValueError("event_id is required")
    with _LOCK:
        cur = _conn().execute(
            "INSERT OR IGNORE INTO charge_events "
            "(event_id, kind, charge_id, payment_intent, amount_cents,"
            " currency, dispute_reason, created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (event_id, kind, charge_id, payment_intent, amount_cents,
             currency, dispute_reason, int(time.time())))
        _conn().commit()
        return cur.rowcount == 1


def charge_event_count():
    with _LOCK:
        return _conn().execute(
            "SELECT COUNT(*) FROM charge_events").fetchone()[0]


# -- one-time migration --------------------------------------------------- #
def migrate_jsonl(path):
    """Import legacy purchases.jsonl rows into the DB. Idempotent
    (INSERT OR IGNORE on stripe_session_id); skips rows without one.
    Returns the number of rows newly imported."""
    if not os.path.exists(path):
        return 0
    imported = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            session_id = row.get("session_id")
            if not session_id or row.get("type") in ("refund", "dispute"):
                # Refund/dispute rows carry no session id; they stay in the
                # jsonl as history. Only purchase rows migrate.
                continue
            if record_purchase(
                    session_id,
                    email=row.get("buyer_email"),
                    amount_cents=row.get("amount_cents"),
                    currency=row.get("currency"),
                    status="paid",
                    report_token=row.get("report_token"),
                    domain=row.get("domain"),
                    score=row.get("score")):
                imported += 1
    return imported
