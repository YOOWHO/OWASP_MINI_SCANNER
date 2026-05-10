from typing import List, Dict
import requests

# Methods considered dangerous if enabled on production servers
DANGEROUS_METHODS = {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}

# Methods that are expected/normal — won't be flagged
SAFE_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}

def check_http_methods(url: str, timeout: int = 5) -> List[Dict]:
    """
    Sends an OPTIONS request to discover allowed HTTP methods.
    Flags dangerous methods like TRACE, PUT, DELETE if they are enabled.

    TRACE enables Cross-Site Tracing (XST) attacks.
    PUT/DELETE can allow unauthorized file operations if misconfigured.
    """
    findings = []

    try:
        response = requests.options(
            url,
            timeout=timeout,
            headers={"User-Agent": "OWASP Mini-Scanner/0.1"},
            allow_redirects=False
        )

        # The Allow header lists supported methods
        allow_header = response.headers.get("Allow", "")
        if not allow_header:
            # Some servers use Access-Control-Allow-Methods instead
            allow_header = response.headers.get("Access-Control-Allow-Methods", "")

        if not allow_header:
            return findings  # Can't determine methods; skip

        allowed_methods = {m.strip().upper() for m in allow_header.split(",")}
        dangerous_found = allowed_methods & DANGEROUS_METHODS

        if dangerous_found:
            findings.append({
                "type": "dangerous_http_methods",
                "msg": f"Dangerous HTTP methods enabled: {', '.join(sorted(dangerous_found))}",
                "details": {
                    "dangerous_methods": sorted(dangerous_found),
                    "all_allowed_methods": sorted(allowed_methods),
                    "allow_header_value": allow_header
                }
            })

        # Special case: TRACE should always be flagged separately
        if "TRACE" in allowed_methods:
            findings.append({
                "type": "http_trace_enabled",
                "msg": "HTTP TRACE method is enabled. This can facilitate Cross-Site Tracing (XST) attacks.",
                "details": {
                    "method": "TRACE",
                    "url": url
                }
            })

    except requests.exceptions.RequestException:
        pass  # Can't reach server for OPTIONS — silently skip

    return findings
