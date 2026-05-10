from typing import List, Dict

def check_cors(headers: Dict[str, str]) -> List[Dict]:
    """
    Checks for CORS misconfigurations in HTTP response headers.
    Flags overly permissive Access-Control-Allow-Origin and related headers.
    """
    findings = []

    lowercase_headers = {k.lower(): v for k, v in headers.items()}

    acao = lowercase_headers.get("access-control-allow-origin", "")
    acac = lowercase_headers.get("access-control-allow-credentials", "")

    # Wildcard origin is dangerous on its own
    if acao == "*":
        findings.append({
            "type": "cors_wildcard_origin",
            "msg": "Access-Control-Allow-Origin is set to '*', allowing any origin to read responses.",
            "details": {
                "header": "Access-Control-Allow-Origin",
                "value": acao
            }
        })

    # Wildcard + credentials is a critical misconfiguration
    if acao == "*" and acac.lower() == "true":
        findings.append({
            "type": "cors_wildcard_with_credentials",
            "msg": "Critical: Access-Control-Allow-Origin '*' combined with Allow-Credentials 'true'. "
                   "Browsers block this, but it signals a broken CORS policy.",
            "details": {
                "allow_origin": acao,
                "allow_credentials": acac
            }
        })

    # Credentials allowed — check origin is not too permissive
    if acac.lower() == "true" and acao not in ("", "*"):
        findings.append({
            "type": "cors_credentials_allowed",
            "msg": f"Access-Control-Allow-Credentials is 'true' with origin '{acao}'. "
                   "Ensure this origin is strictly validated server-side.",
            "details": {
                "allow_origin": acao,
                "allow_credentials": acac
            }
        })

    return findings
