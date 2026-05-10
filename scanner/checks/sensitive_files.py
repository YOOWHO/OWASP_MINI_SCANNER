from typing import List, Dict
import urllib.parse
import requests

# Common sensitive files/paths to probe
SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/config.php",
    "/config.yml",
    "/config.yaml",
    "/wp-config.php",
    "/web.config",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/phpinfo.php",
    "/admin",
    "/admin/",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/.DS_Store",
    "/server-status",
    "/actuator",           # Spring Boot
    "/actuator/env",
    "/actuator/health",
]

# Signatures that confirm a file is genuinely exposed (not a 200 soft-404)
SENSITIVE_SIGNATURES = {
    "/.env": ["APP_KEY", "DB_PASSWORD", "SECRET"],
    "/.git/HEAD": ["ref: refs/"],
    "/.git/config": ["[core]"],
    "/phpinfo.php": ["PHP Version", "phpinfo()"],
    "/actuator/env": ["activeProfiles", "propertySources"],
    "/db.sql": ["CREATE TABLE", "INSERT INTO", "-- MySQL", "DROP TABLE"],
    "/backup.sql": ["CREATE TABLE", "INSERT INTO", "-- MySQL"],
}

def check_sensitive_files(base_url: str, timeout: int = 5) -> List[Dict]:
    """
    Probes common sensitive file paths on the target server.
    Flags paths that return a 200 status and optionally match known signatures.
    """
    findings = []

    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        target_url = base + path
        try:
            response = requests.get(
                target_url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "OWASP Mini-Scanner/0.1"}
            )

            if response.status_code == 200:
                body = response.text

                # Try to confirm with known signatures
                signatures = SENSITIVE_SIGNATURES.get(path, [])
                confirmed = any(sig in body for sig in signatures) if signatures else True

                if confirmed:
                    findings.append({
                        "type": "sensitive_file_exposed",
                        "msg": f"Sensitive file/path accessible: {target_url}",
                        "details": {
                            "path": path,
                            "url": target_url,
                            "status_code": response.status_code,
                            "confirmed": bool(signatures)
                        }
                    })

        except requests.exceptions.RequestException:
            # Silently skip paths that fail to connect
            continue

    return findings
