from typing import List, Dict

# Headers that are deprecated, removed from browsers, or actively harmful
DEPRECATED_HEADERS = {
    "x-xss-protection": (
        "X-XSS-Protection is deprecated and removed in modern browsers. "
        "It can even introduce XSS vulnerabilities in older browsers. Use CSP instead."
    ),
    "public-key-pins": (
        "HTTP Public Key Pinning (HPKP) is deprecated and removed from all modern browsers. "
        "It caused many sites to become inaccessible when misconfigured."
    ),
    "public-key-pins-report-only": (
        "HPKP Report-Only is also deprecated. Remove this header."
    ),
    "expect-ct": (
        "Expect-CT is deprecated as of 2022. Certificate Transparency is now enforced by browsers natively."
    ),
    "p3p": (
        "P3P (Platform for Privacy Preferences) is an obsolete standard. "
        "It is ignored by all modern browsers."
    ),
    "pragma": (
        "The 'Pragma' header is an HTTP/1.0 remnant. Use 'Cache-Control' instead for caching directives."
    ),
    "warning": (
        "The 'Warning' HTTP header is deprecated since RFC 9111 (HTTP Caching). It should be removed."
    ),
}

def check_deprecated_headers(headers: Dict[str, str]) -> List[Dict]:
    """
    Detects the presence of deprecated or removed HTTP response headers.
    """
    findings = []

    lowercase_headers = {k.lower(): v for k, v in headers.items()}

    for header, reason in DEPRECATED_HEADERS.items():
        if header in lowercase_headers:
            findings.append({
                "type": "deprecated_header",
                "msg": f"Deprecated header '{header}' is present. {reason}",
                "details": {
                    "header": header,
                    "value": lowercase_headers[header],
                    "reason": reason
                }
            })

    return findings
