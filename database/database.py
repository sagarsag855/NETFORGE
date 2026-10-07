import sqlite3
import os
from datetime import datetime


# ============================================================
# DATABASE PATH
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_DIR = os.path.join(
    PROJECT_ROOT,
    "database"
)

DATABASE_PATH = os.path.join(
    DATABASE_DIR,
    "netforge.db"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target TEXT NOT NULL,

            scan_date TEXT NOT NULL,

            risk_score INTEGER DEFAULT 0,

            security_level TEXT DEFAULT 'LOW',

            high_count INTEGER DEFAULT 0,

            medium_count INTEGER DEFAULT 0,

            low_count INTEGER DEFAULT 0,

            info_count INTEGER DEFAULT 0,

            dns_status TEXT,

            traffic_status TEXT,

            packet_count INTEGER DEFAULT 0

        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    target,
    assessment
):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans (

            target,
            scan_date,
            risk_score,
            security_level,
            high_count,
            medium_count,
            low_count,
            info_count,
            dns_status,
            traffic_status,
            packet_count

        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        target,

        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        assessment.get(
            "score",
            0
        ),

        assessment.get(
            "security_level",
            "LOW"
        ),

        assessment.get(
            "high_count",
            0
        ),

        assessment.get(
            "medium_count",
            0
        ),

        assessment.get(
            "low_count",
            0
        ),

        assessment.get(
            "info_count",
            0
        ),

        assessment.get(
            "dns_status",
            "UNKNOWN"
        ),

        assessment.get(
            "traffic_status",
            "UNKNOWN"
        ),

        assessment.get(
            "packet_count",
            0
        )

    ))

    scan_id = cursor.lastrowid

    connection.commit()

    connection.close()

    return scan_id


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_scan_history():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *

        FROM scans

        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# GET SINGLE SCAN
# ============================================================

def get_scan(scan_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *

        FROM scans

        WHERE id = ?
    """, (
        scan_id,
    ))

    row = cursor.fetchone()

    connection.close()

    if row:

        return dict(row)

    return None


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    initialize_database()

    print("=" * 60)
    print("NETFORGE DATABASE")
    print("=" * 60)

    print(
        "\nDatabase:",
        DATABASE_PATH
    )

    print(
        "\nDatabase initialized successfully."
    )
