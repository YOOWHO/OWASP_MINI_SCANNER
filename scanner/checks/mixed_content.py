from typing import List, Dict
from bs4 import BeautifulSoup
import urllib.parse

# Tags and their attributes that load external resources
RESOURCE_TAGS = {
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
    "audio": "src",
    "video": "src",
    "source": "src",
    "form": "action",
    "object": "data",
    "embed": "src",
}

def check_mixed_content(url: str, body: str) -> List[Dict]:
    """
    Detects mixed content: HTTP resources loaded on an HTTPS page.
    Mixed content degrades security by allowing MITM attacks on sub-resources.
    """
    findings = []

    parsed = urllib.parse.urlparse(url)

    # Only relevant for HTTPS pages
    if parsed.scheme != "https":
        return findings

    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return findings

    seen = set()

    for tag_name, attr in RESOURCE_TAGS.items():
        for tag in soup.find_all(tag_name):
            resource_url = tag.get(attr, "").strip()

            if not resource_url or resource_url in seen:
                continue

            seen.add(resource_url)

            # Flag explicit http:// resources
            if resource_url.lower().startswith("http://"):
                findings.append({
                    "type": "mixed_content",
                    "msg": f"Mixed content: <{tag_name}> loads resource over HTTP on an HTTPS page.",
                    "details": {
                        "tag": tag_name,
                        "attribute": attr,
                        "resource_url": resource_url
                    }
                })

    return findings
