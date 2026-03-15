import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "/home/pitrap/pitrap/pitrap.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT NOT NULL,
            source_port INTEGER,
            username TEXT,
            password TEXT,
            client_version TEXT,
            country TEXT,
            city TEXT,
            isp TEXT,
            latitude REAL,
            longitude REAL,
            abuse_score INTEGER DEFAULT 0,
            attacker_type TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_attempts INTEGER DEFAULT 0,
            unique_ips INTEGER DEFAULT 0,
            top_username TEXT,
            top_password TEXT
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Database initialized")

def insert_attempt(data: dict) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO attempts
        (source_ip, source_port, username, password, client_version,
         country, city, isp, latitude, longitude, abuse_score, attacker_type)
        VALUES
        (:source_ip, :source_port, :username, :password, :client_version,
         :country, :city, :isp, :latitude, :longitude, :abuse_score, :attacker_type)
    """, data)
    conn.commit()
    attempt_id = cursor.lastrowid
    conn.close()
    return attempt_id

def get_recent_attempts(limit: int = 50) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM attempts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_stats() -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total FROM attempts")
    total = cursor.fetchone()["total"]
    cursor.execute("SELECT COUNT(DISTINCT source_ip) as unique_ips FROM attempts")
    unique_ips = cursor.fetchone()["unique_ips"]
    cursor.execute("""
        SELECT username, COUNT(*) as cnt FROM attempts
        GROUP BY username ORDER BY cnt DESC LIMIT 5
    """)
    top_usernames = [dict(r) for r in cursor.fetchall()]
    cursor.execute("""
        SELECT password, COUNT(*) as cnt FROM attempts
        GROUP BY password ORDER BY cnt DESC LIMIT 5
    """)
    top_passwords = [dict(r) for r in cursor.fetchall()]
    cursor.execute("""
        SELECT country, COUNT(*) as cnt FROM attempts
        GROUP BY country ORDER BY cnt DESC LIMIT 5
    """)
    top_countries = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return {
        "total_attempts": total,
        "unique_ips": unique_ips,
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
        "top_countries": top_countries
    }

def get_attempts_by_ip(ip: str) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM attempts WHERE source_ip = ?
        ORDER BY timestamp DESC
    """, (ip,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def create_session_tables():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shell_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attempt_id INTEGER,
            source_ip TEXT NOT NULL,
            username TEXT,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ended_at DATETIME,
            total_commands INTEGER DEFAULT 0,
            malware_urls TEXT,
            mitre_techniques TEXT,
            risk_level TEXT DEFAULT 'low'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS shell_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            command TEXT,
            response TEXT,
            technique_id TEXT,
            technique_name TEXT,
            flagged INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    print("[DB] Shell session tables created")

def create_shell_session(data: dict) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO shell_sessions (attempt_id, source_ip, username)
        VALUES (:attempt_id, :source_ip, :username)
    """, data)
    conn.commit()
    session_id = cursor.lastrowid
    conn.close()
    return session_id

def log_shell_command(session_id: int, command: str,
                      response: str, technique_id: str = None,
                      technique_name: str = None, flagged: int = 0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO shell_commands
        (session_id, command, response, technique_id, technique_name, flagged)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, command, response, technique_id, technique_name, flagged))
    cursor.execute("""
        UPDATE shell_sessions
        SET total_commands = total_commands + 1
        WHERE id = ?
    """, (session_id,))
    conn.commit()
    conn.close()

def close_shell_session(session_id: int, mitre_techniques: str,
                        malware_urls: str, risk_level: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE shell_sessions
        SET ended_at = CURRENT_TIMESTAMP,
            mitre_techniques = ?,
            malware_urls = ?,
            risk_level = ?
        WHERE id = ?
    """, (mitre_techniques, malware_urls, risk_level, session_id))
    conn.commit()
    conn.close()

def get_recent_sessions(limit: int = 20) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM shell_sessions
        ORDER BY started_at DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_session_commands(session_id: int) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM shell_commands
        WHERE session_id = ?
        ORDER BY timestamp ASC
    """, (session_id,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows
