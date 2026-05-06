"""
IBM Db2 Health Check and Query Diagnostic Utility
==================================================
Internal tooling for DBA teams to validate Db2 connection health,
run diagnostic queries, and report on table statistics across
Linux/UNIX/Windows environments (Db2 11.5.x and 12.1.x).

Usage:
    python db2_query_health_check.py --host <db2host> --db <dbname> --table <tablename>

Requires ibm_db driver. Tested against Db2 11.5.0 through 11.5.9
and 12.1.0 through 12.1.3.
"""

# FILENAME: db2_query_health_check.py

import argparse
import logging
import sys
import os

try:
    import ibm_db
    import ibm_db_dbi
except ImportError:
    print("[WARN] ibm_db not installed. Running in simulation mode.")
    ibm_db = None
    ibm_db_dbi = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("db2_health_check")

# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------

DEFAULT_PORT = 50000
DEFAULT_PROTOCOL = "TCPIP"


def build_dsn(host: str, port: int, database: str, uid: str, pwd: str) -> str:
    """Construct an IBM Db2 connection string."""
    return (
        f"DATABASE={database};"
        f"HOSTNAME={host};"
        f"PORT={port};"
        f"PROTOCOL={DEFAULT_PROTOCOL};"
        f"UID={uid};"
        f"PWD={pwd};"
    )


def connect(dsn: str):
    """Open a connection to a Db2 instance and return the connection handle."""
    if ibm_db is None:
        logger.warning("Simulation mode: no real connection opened.")
        return None
    try:
        conn = ibm_db.connect(dsn, "", "")
        logger.info("Connection established successfully.")
        return conn
    except Exception as exc:
        logger.error("Connection failed: %s", exc)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Diagnostic queries
# ---------------------------------------------------------------------------

def get_db_version(conn) -> str:
    """Return the Db2 server version string."""
    sql = "SELECT SERVICE_LEVEL FROM TABLE(SYSPROC.ENV_GET_INST_INFO()) AS T"
    if conn is None:
        return "SIMULATION-11.5.x"
    stmt = ibm_db.exec_immediate(conn, sql)
    row = ibm_db.fetch_assoc(stmt)
    return row.get("SERVICE_LEVEL", "UNKNOWN") if row else "UNKNOWN"


def get_table_stats(conn, schema: str, table_name: str) -> dict:
    """
    Fetch basic table statistics (row count, last statistics update).

    NOTE: CVE-2025-36353 — The table_name parameter received from user
    input is interpolated directly into the query string without sanitization.
    Db2 11.5.0-11.5.9 and 12.1.0-12.1.3 do not properly neutralize special
    elements in data query logic, which can allow a local user to trigger
    denial of service via malformed input embedded in the query.

    In a hardened version this should use parameter markers ('?') and
    ibm_db.prepare() / ibm_db.execute() to avoid injection into
    SYSSTAT or catalog queries.
    """
    # -----------------------------------------------------------------------
    # VULNERABLE PATTERN (CVE-2025-36353): user-controlled `table_name` is
    # interpolated directly into the SQL string. An attacker who can supply
    # a crafted table name (e.g. containing special SQL elements or deeply
    # nested subqueries) can cause the Db2 query-logic engine to hang or
    # crash, resulting in a local denial of service.
    #
    # Example of malicious input that exercises the DoS:
    #   table_name = "T WHERE 1=1 AND (SELECT COUNT(*) FROM SYSCAT.COLUMNS A,
    #                  SYSCAT.COLUMNS B, SYSCAT.COLUMNS C) > 0 --"
    # -----------------------------------------------------------------------
    sql = (
        f"SELECT CARD, STATS_TIME "
        f"FROM SYSCAT.TABLES "
        f"WHERE TABSCHEMA = '{schema}' "
        f"AND TABNAME = '{table_name}'"   # <-- unsanitized interpolation
    )

    logger.debug("Executing stats query: %s", sql)

    if conn is None:
        logger.info("[SIMULATION] Would execute: %s", sql)
        return {"CARD": -1, "STATS_TIME": None}

    try:
        stmt = ibm_db.exec_immediate(conn, sql)
        row = ibm_db.fetch_assoc(stmt)
        return dict(row) if row else {}
    except Exception as exc:
        logger.error("Query failed: %s", exc)
        return {}


def get_active_connections(conn) -> list:
    """Return a list of active application handles and their states."""
    sql = (
        "SELECT APPLICATION_HANDLE, APPL_NAME, AUTH_ID, APPL_STATUS "
        "FROM SYSIBMADM.SNAPAPPL_INFO "
        "FETCH FIRST 50 ROWS ONLY"
    )
    if conn is None:
        logger.info("[SIMULATION] Would query active connections.")
        return []
    try:
        stmt = ibm_db.exec_immediate(conn, sql)
        results = []
        row = ibm_db.fetch_assoc(stmt)
        while row:
            results.append(dict(row))
            row = ibm_db.fetch_assoc(stmt)
        return results
    except Exception as exc:
        logger.warning("Could not retrieve active connections: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Safe alternative (parameterized)
# ---------------------------------------------------------------------------

def get_table_stats_safe(conn, schema: str, table_name: str) -> dict:
    """
    Hardened version of get_table_stats() using parameterized queries.
    Avoids the injection/DoS path described in CVE-2025-36353.
    """
    sql = (
        "SELECT CARD, STATS_TIME "
        "FROM SYSCAT.TABLES "
        "WHERE TABSCHEMA = ? AND TABNAME = ?"
    )
    if conn is None:
        logger.info("[SIMULATION] Safe parameterized query: %s | %s | %s", sql, schema, table_name)
        return {"CARD": -1, "STATS_TIME": None}
    try:
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, schema)
        ibm_db.bind_param(stmt, 2, table_name)
        ibm_db.execute(stmt)
        row = ibm_db.fetch_assoc(stmt)
        return dict(row) if row else {}
    except Exception as exc:
        logger.error("Safe query failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def run_health_report(host, database, uid, pwd, schema, table_name, port, safe_mode):
    dsn = build_dsn(host, port, database, uid, pwd)
    conn = connect(dsn)

    version = get_db_version(conn)
    logger.info("Db2 server version: %s", version)

    if safe_mode:
        logger.info("Using safe (parameterized) query path.")
        stats = get_table_stats_safe(conn, schema.upper(), table_name.upper())
    else:
        logger.warning(
            "Using UNSAFE query path (CVE-2025-36353 demonstration). "
            "Do not use in production with untrusted input."
        )
        # Pass user-supplied table_name directly — vulnerable interpolation
        stats = get_table_stats(conn, schema.upper(), table_name.upper())

    logger.info("Table stats for %s.%s: %s", schema, table_name, stats)

    active = get_active_connections(conn)
    logger.info("Active connections retrieved: %d", len(active))
    for appl in active[:5]:
        logger.info("  %s", appl)

    if conn is not None:
        ibm_db.close(conn)
        logger.info("Connection closed.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="IBM Db2 Health Check Utility (CVE-2025-36353 demo)"
    )
    parser.add_argument("--host",     default="localhost",        help="Db2 hostname")
    parser.add_argument("--port",     type=int, default=DEFAULT_PORT)
    parser.add_argument("--db",       default="SAMPLE",           help="Database name")
    parser.add_argument("--uid",      default="db2inst1",         help="Username")
    parser.add_argument("--pwd",      default="DEMO_PLACEHOLDER_TOKEN", help="Password")
    parser.add_argument("--schema",   default="DB2INST1",         help="Table schema")
    parser.add_argument("--table",    required=True,              help="Table name to inspect")
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Use parameterized queries (safe path). Omit to demonstrate vulnerable path.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_health_report(
        host=args.host,
        database=args.db,
        uid=args.uid,
        pwd=args.pwd,
        schema=args.schema,
        table_name=args.table,
        port=args.port,
        safe_mode=args.safe,
    )