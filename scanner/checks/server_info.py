from typing import List, Dict
import re

# Headers that commonly leak server/framework version info
INFO_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-version",
]

# Regex to detect version numbers (e.g., Apache/2.4.51, PHP/7.4.3)
VERSION_PATTERN = re.compile(r'\d+\.\d+(\.\d+)*')

# HTML comment patterns that may leak debug info
HTML_COMMENT_PATTERNS = [
    re.compile(r'<!--.*?(version|debug|todo|fixme|hack|password|secret|api.?key).*?-->', re.IGNORECASE | re.DOTALL),
]

def check_server_info(headers: Dict[str, str], body: str = "") -> List[Dict]:
    """
    Detects server/technology version disclosure via response headers and HTML comments.
    """
    findings = []

    lowercase_headers = {k.lower(): v for k, v in headers.items()}

    for header in INFO_DISCLOSURE_HEADERS:
        value = lowercase_headers.get(header)
        if value:
            has_version = bool(VERSION_PATTERN.search(value))
            findings.append({
                "type": "server_info_disclosure",
                "msg": f"Header '{header}' exposes server information: '{value}'" +
                       (" (includes version number)" if has_version else ""),
                "details": {
                    "header": header,
                    "value": value,
                    "has_version": has_version
                }
            })

    # Check HTML body for leaky comments
    if body:
        for pattern in HTML_COMMENT_PATTERNS:
            matches = pattern.findall(body)
            if matches:
                findings.append({
                    "type": "html_comment_disclosure",
                    "msg": "HTML comments may contain sensitive information (version, debug, credentials, etc.)",
                    "details": {
                        "pattern": pattern.pattern,
                        "match_count": len(matches)
                    }
                })
                break  # One finding per pattern type is enough

    return findings
