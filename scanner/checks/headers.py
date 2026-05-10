from typing import List, Dict

def check_headers(headers: Dict[str, str]) -> List[Dict]:
    """
    Checks for missing security headers in HTTP response.
    """
    findings = []
    
    security_headers = {
        "Content-Security-Policy": "CSP is missing",
        "X-Frame-Options": "X-Frame-Options is missing",
        "Strict-Transport-Security": "Strict-Transport-Security is missing",
        "X-Content-Type-Options": "X-Content-Type-Options is missing"
    }
    
    # Case-insensitive header matching
    lowercase_headers = {k.lower(): v for k, v in headers.items()}
    
    for header, msg in security_headers.items():
        if header.lower() not in lowercase_headers:
            findings.append({
                "type": "missing_header",
                "header": header,
                "msg": msg
            })
            
    return findings
