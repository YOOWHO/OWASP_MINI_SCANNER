from typing import List, Dict
from datetime import datetime, timezone
import re

# Threshold: cookies lasting more than this many days are flagged
MAX_SAFE_DAYS = 90

# Common session cookie name patterns (these should NEVER have long expiry)
SESSION_COOKIE_PATTERNS = [
    "session", "sess", "sid", "auth", "token", "login",
    "phpsessid", "jsessionid", "asp.net_sessionid"
]

def _parse_max_age(attributes: list) -> int | None:
    """Extracts Max-Age value from cookie attributes list."""
    for attr in attributes:
        if attr.lower().startswith("max-age="):
            try:
                return int(attr.split("=", 1)[1].strip())
            except ValueError:
                pass
    return None

def _parse_expires(attributes: list) -> datetime | None:
    """Extracts and parses Expires value from cookie attributes list."""
    for attr in attributes:
        if attr.lower().startswith("expires="):
            date_str = attr.split("=", 1)[1].strip()
            for fmt in [
                "%a, %d %b %Y %H:%M:%S %Z",
                "%a, %d-%b-%Y %H:%M:%S %Z",
                "%a, %d %b %Y %H:%M:%S",
            ]:
                try:
                    return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return None

def check_cookie_expiry(cookies: List[str]) -> List[Dict]:
    """
    Flags cookies with excessively long or no expiry (persistent session cookies).
    Session cookies should expire when the browser closes (no Max-Age / Expires).
    Persistent cookies should not last more than MAX_SAFE_DAYS days.
    """
    findings = []
    now = datetime.now(timezone.utc)

    for cookie_header in cookies:
        parts = cookie_header.split(";")
        if not parts:
            continue

        name_part = parts[0].strip()
        if "=" not in name_part:
            continue

        cookie_name = name_part.split("=", 1)[0].strip()
        attributes = [p.strip() for p in parts[1:]]

        is_session_cookie = any(
            pattern in cookie_name.lower() for pattern in SESSION_COOKIE_PATTERNS
        )

        max_age = _parse_max_age(attributes)
        expires = _parse_expires(attributes)

        # Case 1: Max-Age is 0 or negative — cookie deletion, skip
        if max_age is not None and max_age <= 0:
            continue

        # Case 2: Session-like cookie with a persistent expiry
        if is_session_cookie and (max_age is not None or expires is not None):
            findings.append({
                "type": "session_cookie_persistent",
                "cookie": cookie_name,
                "msg": f"Session cookie '{cookie_name}' has a persistent expiry set. "
                       "Session cookies should expire when the browser closes (no Max-Age or Expires).",
                "details": {
                    "max_age": max_age,
                    "expires": str(expires) if expires else None
                }
            })
            continue

        # Case 3: Max-Age too long
        if max_age is not None:
            days = max_age / 86400
            if days > MAX_SAFE_DAYS:
                findings.append({
                    "type": "cookie_excessive_expiry",
                    "cookie": cookie_name,
                    "msg": f"Cookie '{cookie_name}' has Max-Age of {int(days)} days (>{MAX_SAFE_DAYS} day threshold).",
                    "details": {
                        "max_age_seconds": max_age,
                        "max_age_days": round(days, 1)
                    }
                })

        # Case 4: Expires too far in the future
        if expires is not None:
            delta = expires - now
            days = delta.total_seconds() / 86400
            if days > MAX_SAFE_DAYS:
                findings.append({
                    "type": "cookie_excessive_expiry",
                    "cookie": cookie_name,
                    "msg": f"Cookie '{cookie_name}' expires in {int(days)} days (>{MAX_SAFE_DAYS} day threshold).",
                    "details": {
                        "expires": str(expires),
                        "days_until_expiry": round(days, 1)
                    }
                })

    return findings
