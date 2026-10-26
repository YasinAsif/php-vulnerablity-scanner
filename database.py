import sqlite3
import json
import uuid
import time
from typing import Optional, Dict, Any, List

DB_PATH = "phpscanner.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_reports (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            resolved_ip TEXT,
            status TEXT NOT NULL,
            vulnerable INTEGER NOT NULL,
            vulnerability_type TEXT,
            server_banner TEXT,
            php_detected INTEGER,
            cvss TEXT,
            logs_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_domain ON scan_reports(domain)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_created ON scan_reports(created_at)")
    conn.commit()
    conn.close()

def save_scan_report(data: Dict[str, Any]) -> str:
    scan_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    url = data.get("url", "")
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    
    cursor.execute("""
        INSERT INTO scan_reports (
            id, url, domain, resolved_ip, status, vulnerable, 
            vulnerability_type, server_banner, php_detected, cvss, logs_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        url,
        domain,
        data.get("resolved_ip", ""),
        data.get("status", "completed"),
        1 if data.get("vulnerable") else 0,
        data.get("vulnerability_type", ""),
        data.get("server_banner", ""),
        1 if data.get("php_detected") else 0,
        data.get("cvss", "9.2 CRITICAL"),
        json.dumps(data.get("logs", []))
    ))
    conn.commit()
    conn.close()
    return scan_id

def get_scan_report(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_reports WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None
        
    return {
        "id": row[0],
        "url": row[1],
        "domain": row[2],
        "resolved_ip": row[3],
        "status": row[4],
        "vulnerable": bool(row[5]),
        "vulnerability_type": row[6],
        "server_banner": row[7],
        "php_detected": bool(row[8]),
        "cvss": row[9],
        "logs": json.loads(row[10]) if row[10] else [],
        "created_at": row[11]
    }

def get_recent_scans(limit: int = 6) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, domain, status, vulnerable, created_at 
        FROM scan_reports 
        ORDER BY created_at DESC 
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0],
            "domain": r[1],
            "status": r[2],
            "vulnerable": bool(r[3]),
            "created_at": r[4]
        }
        for r in rows
    ]

def get_latest_domain_status(domain: str) -> str:
    """Returns 'protected', 'exposed', 'inconclusive', or 'unverified' based on real SQLite scan history."""
    clean_domain = domain.lower().strip()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT vulnerable, status FROM scan_reports 
            WHERE LOWER(domain) = ? 
            ORDER BY created_at DESC LIMIT 1
            """,
            (clean_domain,)
        )
        row = cursor.fetchone()
        if not row:
            return "unverified"
        vulnerable, status = row
        if vulnerable:
            return "exposed"
        if status == "inconclusive":
            return "inconclusive"
        return "protected"
