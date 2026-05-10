from typing import List, Dict
import urllib.parse
import re

# Common session ID parameter names in URLs
SESSION_PARAM_PATTERNS = [
    "phpsessid",
    "jsessionid",
    "aspsessionid",
    "asp.net_sessionid",
    "sid",
    "sessionid",
    "session_id",
    "sessid",
    "token",
    "auth_token",
    "access_token",
]

# Regex to detect long alphanumeric strings (typical session tokens)
TOKEN_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{16,}$')

def check_session_fixation(url: str, body: str) -> List[Dict]:
    """
    Detects session IDs exposed in the URL query string.
    Session IDs in URLs are vulnerable to:
    - Browser history leakage
    - Referer header leakage to third-party sites
    - Server log exposure
    - Session fixation attacks via crafted links
    """
    findings = []

    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    for param_name, values in query_params.items():
        param_lower = param_name.lower()

        is_session_param = any(pattern in param_lower for pattern in SESSION_PARAM_PATTERNS)

        if is_session_param:
            for value in values:
                findings.append({
                    "type": "session_id_in_url",
                    "msg": f"Session identifier '{param_name}' found in URL. "
                           "Session IDs should never be transmitted via URL query parameters.",
                    "details": {
                        "parameter": param_name,
                        "url": url
                    }
                })
            break  # One finding per URL is enough

    # Also check if HTML body contains links with session params (common in legacy apps)
    if body:
        for pattern in SESSION_PARAM_PATTERNS:
            # Look for href/action/src containing session params
            link_pattern = re.compile(
                rf'(?:href|action|src)=["\'][^"\']*[?&]{re.escape(pattern)}=[a-zA-Z0-9_\-]{{8,}}',
                re.IGNORECASE
            )
            matches = link_pattern.findall(body)
            if matches:
                findings.append({
                    "type": "session_id_in_links",
                    "msg": f"Session parameter '{pattern}' found embedded in page links/forms. "
                           "This can leak session tokens via Referer headers or browser history.",
                    "details": {
                        "parameter": pattern,
                        "occurrences": len(matches)
                    }
                })
                break

    return findings
