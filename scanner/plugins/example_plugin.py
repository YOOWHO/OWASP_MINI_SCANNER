from typing import List, Dict
from scanner.plugins import PluginBase

class InformationDisclosurePlugin(PluginBase):
    """
    Example plugin that checks for common information disclosure headers.
    """
    def run(self, report_data: dict) -> List[Dict]:
        findings = []
        headers = report_data.get('headers', {})
        
        # Case-insensitive header matching
        lowercase_headers = {k.lower(): v for k, v in headers.items()}
        
        info_disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version']
        
        for header in info_disclosure_headers:
            if header in lowercase_headers:
                findings.append({
                    "type": "info_disclosure",
                    "plugin": "InformationDisclosurePlugin",
                    "header": header,
                    "msg": f"Information disclosure via '{header}' header: {lowercase_headers[header]}",
                    "details": {
                        "value": lowercase_headers[header]
                    }
                })
                
        return findings
