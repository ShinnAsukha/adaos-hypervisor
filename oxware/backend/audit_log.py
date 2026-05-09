"""
audit_log.py - SQLite tabanlı kullanıcı aksiyon kaydı.
DB: /var/lib/oxware/audit.db
"""

import sqlite3
import threading
import time
import os
import json
import csv
import io
import logging

log = logging.getLogger("oxware.audit")

DB_PATH = "/var/lib/oxware/audit.db"
_lock   = threading.Lock()


# ---------------------------------------------------------------------------
# DB kurulumu
# ---------------------------------------------------------------------------

def init_db():
    """audit_entries tablosunu ve indekslerini oluşturur."""
    try:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts            INTEGER NOT NULL,
                    username      TEXT,
                    role          TEXT,
                    action        TEXT    NOT NULL,
                    resource_type TEXT,
                    resource_id   TEXT,
                    details       TEXT,
                    ip_address    TEXT,
                    user_agent    TEXT,
                    result        TEXT DEFAULT 'success'
                );
                CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_entries(ts);
                CREATE INDEX IF NOT EXISTS idx_audit_username  ON audit_entries(username);
                CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_entries(action);
            """)
            conn.commit()
            conn.close()
        log.info("audit_log DB hazır: %s", DB_PATH)
    except Exception as e:
        log.error("init_db hatası: %s", e)


# ---------------------------------------------------------------------------
# Kayıt ekleme
# ---------------------------------------------------------------------------

def log_action(username, action, resource_type="", resource_id="",
               details=None, ip="", user_agent="", result="success", role=""):
    """
    Yeni audit kaydı ekler.

    Parametreler:
        username      – işlemi yapan kullanıcı adı
        action        – yapılan işlem (örn. "vm.start", "user.login")
        resource_type – etkilenen kaynak tipi (örn. "vm", "user")
        resource_id   – etkilenen kaynağın ID'si
        details       – ek bilgi (dict veya herhangi bir nesne → JSON'a çevrilir)
        ip            – istemci IP adresi
        user_agent    – HTTP User-Agent başlığı
        result        – "success" | "failed" | "error"
        role          – kullanıcı rolü
    """
    try:
        details_str = json.dumps(details, ensure_ascii=False) if details is not None else None
        ts = int(time.time())
        with _lock:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                """INSERT INTO audit_entries
                   (ts, username, role, action, resource_type, resource_id,
                    details, ip_address, user_agent, result)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (ts, username, role, action, resource_type, resource_id,
                 details_str, ip, user_agent, result),
            )
            conn.commit()
            conn.close()
    except Exception as e:
        log.error("log_action hatası (action=%s): %s", action, e)


# ---------------------------------------------------------------------------
# Sorgular
# ---------------------------------------------------------------------------

def get_logs(username=None, action=None, resource_type=None,
             since=None, until=None, limit=100, offset=0):
    """
    Filtreli audit kaydı listesi döndürür (dict listesi).

    since / until: unix timestamp veya None.
    """
    try:
        clauses, params = [], []

        if username:
            clauses.append("username = ?")
            params.append(username)
        if action:
            clauses.append("action LIKE ?")
            params.append(f"%{action}%")
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if since is not None:
            clauses.append("ts >= ?")
            params.append(int(since))
        if until is not None:
            clauses.append("ts <= ?")
            params.append(int(until))

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"""
            SELECT * FROM audit_entries
            {where}
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        """
        params += [limit, offset]

        with _lock:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = []
            for r in conn.execute(query, params).fetchall():
                d = dict(r)
                if d.get("details"):
                    try:
                        d["details"] = json.loads(d["details"])
                    except Exception:
                        pass
                rows.append(d)
            conn.close()
        return rows
    except Exception as e:
        log.error("get_logs hatası: %s", e)
        return []


# ---------------------------------------------------------------------------
# İstatistikler
# ---------------------------------------------------------------------------

def get_stats():
    """
    Döndürür:
      - total     : toplam kayıt sayısı
      - by_user   : {username: count}
      - last_24h  : son 24 saatteki aksiyon sayısı
      - by_action : {action: count}
    """
    try:
        since_24h = int(time.time()) - 86400
        with _lock:
            conn = sqlite3.connect(DB_PATH)

            total = conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0]

            by_user = {r[0]: r[1] for r in conn.execute(
                "SELECT username, COUNT(*) FROM audit_entries GROUP BY username"
            ).fetchall()}

            last_24h = conn.execute(
                "SELECT COUNT(*) FROM audit_entries WHERE ts >= ?", (since_24h,)
            ).fetchone()[0]

            by_action = {r[0]: r[1] for r in conn.execute(
                "SELECT action, COUNT(*) FROM audit_entries GROUP BY action"
            ).fetchall()}

            conn.close()

        return {
            "total":     total,
            "by_user":   by_user,
            "last_24h":  last_24h,
            "by_action": by_action,
        }
    except Exception as e:
        log.error("get_stats hatası: %s", e)
        return {"total": 0, "by_user": {}, "last_24h": 0, "by_action": {}}


# ---------------------------------------------------------------------------
# CSV dışa aktarım
# ---------------------------------------------------------------------------

def export_csv(username=None, since=None, until=None):
    """
    Kayıtları CSV string olarak döndürür.
    """
    try:
        rows = get_logs(username=username, since=since, until=until, limit=100000)

        output = io.StringIO()
        fieldnames = ["id", "ts", "username", "role", "action", "resource_type",
                      "resource_id", "details", "ip_address", "user_agent", "result"]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            if isinstance(row.get("details"), (dict, list)):
                row = dict(row)
                row["details"] = json.dumps(row["details"], ensure_ascii=False)
            writer.writerow(row)

        return output.getvalue()
    except Exception as e:
        log.error("export_csv hatası: %s", e)
        return ""


# ---------------------------------------------------------------------------
# Modül yüklendiğinde DB'yi hazırla
# ---------------------------------------------------------------------------
init_db()
