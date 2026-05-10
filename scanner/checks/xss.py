from typing import List, Dict
import urllib.parse
import html

def check_xss(url: str, body: str) -> List[Dict]:
    """
    Detects potential passive XSS reflection points by searching for 
    unencoded query parameters in the response body.
    """
    findings = []
    
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    for param_name, param_values in query_params.items():
        for value in param_values:
            # Skip empty or very short values to reduce noise
            if len(value) < 3:
                continue
                
            # Check if the exact raw value is in the body
            if value in body:
                # Basic check to see if it might be securely encoded
                # Note: this is a weak check, as it doesn't understand context (HTML vs JS vs Attribute)
                encoded_value = html.escape(value)
                
                findings.append({
                    "type": "reflection",
                    "msg": f"Query parameter '{param_name}' value appears to be reflected in response",
                    "details": {
                        "parameter": param_name,
                        "reflected_value": value
                    }
                })
                
    return findings
