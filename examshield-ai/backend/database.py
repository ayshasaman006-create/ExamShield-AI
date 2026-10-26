"""SQLite storage for cases and trapdoor hits."""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examshield.db")


@contextmanager
def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,            -- email | activity
                title TEXT NOT NULL,
                score INTEGER NOT NULL,
                level TEXT NOT NULL,
                findings TEXT NOT NULL,        -- JSON
                ai TEXT NOT NULL,              -- JSON
                extra TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS trap_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                trap TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                detail TEXT,
                severity TEXT NOT NULL,
                points INTEGER NOT NULL
            );
            """
        )


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def add_case(kind, title, score, level, findings, ai, extra=None):
    with conn() as c:
        cur = c.execute(
            "INSERT INTO cases (created_at, kind, title, score, level, findings, ai, extra) VALUES (?,?,?,?,?,?,?,?)",
            (now(), kind, title, score, level, json.dumps(findings), json.dumps(ai), json.dumps(extra or {})),
        )
        return cur.lastrowid


def _case(row):
    d = dict(row)
    d["findings"] = json.loads(d["findings"])
    d["ai"] = json.loads(d["ai"])
    d["extra"] = json.loads(d["extra"])
    return d


def get_case(case_id):
    with conn() as c:
        row = c.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    return _case(row) if row else None


def list_cases(limit=100):
    with conn() as c:
        rows = c.execute("SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_case(r) for r in rows]


def add_trap_hit(trap, method, path, ip, ua, detail, severity, points):
    with conn() as c:
        c.execute(
            "INSERT INTO trap_hits (created_at, trap, method, path, ip, user_agent, detail, severity, points) VALUES (?,?,?,?,?,?,?,?,?)",
            (now(), trap, method, path, ip, ua, detail, severity, points),
        )


def list_trap_hits(limit=200):
    with conn() as c:
        rows = c.execute("SELECT * FROM trap_hits ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear_all():
    with conn() as c:
        c.execute("DELETE FROM cases")
        c.execute("DELETE FROM trap_hits")
