from typing import List, Dict

def check_cookies(cookies: List[str]) -> List[Dict]:
    """
    Analyzes Set-Cookie headers for missing security attributes.
    """
    findings = []
    
    for cookie_header in cookies:
        parts = cookie_header.split(';')
        if not parts:
            continue
            
        cookie_name_part = parts[0].strip()
        if '=' not in cookie_name_part:
            continue
            
        cookie_name = cookie_name_part.split('=', 1)[0]
        
        attributes = [p.strip().lower() for p in parts[1:]]
        
        # Check Secure attribute
        if 'secure' not in attributes:
            findings.append({
                "type": "cookie_missing_secure",
                "cookie": cookie_name,
                "msg": f"Cookie '{cookie_name}' missing Secure attribute"
            })
            
        # Check HttpOnly attribute
        if 'httponly' not in attributes:
            findings.append({
                "type": "cookie_missing_httponly",
                "cookie": cookie_name,
                "msg": f"Cookie '{cookie_name}' missing HttpOnly attribute"
            })
            
        # Check SameSite attribute
        samesite_found = any(attr.startswith('samesite=') for attr in attributes)
        if not samesite_found:
             findings.append({
                "type": "cookie_missing_samesite",
                "cookie": cookie_name,
                "msg": f"Cookie '{cookie_name}' missing SameSite attribute"
            })
            
    return findings
