from typing import List, Dict
import urllib.parse

# Common SQL error patterns from various databases
SQL_ERROR_PATTERNS = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    # Oracle
    "ora-",
    "oracle error",
    # MSSQL
    "microsoft ole db provider for sql server",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "mssql_query",
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    # Generic
    "sql syntax",
    "sql error",
    "sql command",
    "database error",
    "db error",
    "unrecognized token",
    "quoted string not properly terminated",
]

def check_sql_injection(url: str, body: str) -> List[Dict]:
    """
    Passively detects potential SQL injection vulnerabilities by looking
    for database error patterns in the response body when query params exist.
    """
    findings = []

    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # Only flag if there are query params (more likely to be user input)
    if not query_params:
        return findings

    body_lower = body.lower()

    for pattern in SQL_ERROR_PATTERNS:
        if pattern in body_lower:
            findings.append({
                "type": "sql_injection_indicator",
                "msg": f"Possible SQL error pattern detected in response: '{pattern}'",
                "details": {
                    "pattern": pattern,
                    "url": url
                }
            })
            break  # One finding per page is enough to avoid noise

    return findings
