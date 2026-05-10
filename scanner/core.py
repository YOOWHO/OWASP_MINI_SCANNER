from dataclasses import dataclass, field
from typing import List, Dict, Optional
import logging

from scanner.fetcher import Fetcher
from scanner.parsers.forms import extract_forms, Form
from scanner.checks.headers import check_headers
from scanner.checks.cookies import check_cookies
from scanner.checks.csrf import check_csrf
from scanner.checks.xss import check_xss
from scanner.checks.sql_injection import check_sql_injection
from scanner.checks.cors import check_cors
from scanner.checks.server_info import check_server_info
from scanner.checks.sensitive_files import check_sensitive_files
from scanner.checks.mixed_content import check_mixed_content
from scanner.checks.deprecated_headers import check_deprecated_headers
from scanner.checks.http_methods import check_http_methods
from scanner.checks.session_fixation import check_session_fixation
from scanner.checks.cookie_expiry import check_cookie_expiry
from scanner.plugins import load_plugins

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class Report:
    url: str
    status_code: Optional[int] = None
    findings: List[Dict] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self):
         return {
             "url": self.url,
             "status_code": self.status_code,
             "findings": self.findings,
             "forms": self.forms,
             "headers": self.headers,
             "error": self.error
         }

class Scanner:
    """Orchestrates the complete scanning workflow."""
    
    def __init__(self, timeout: int = 10):
        self.fetcher = Fetcher(timeout=timeout)
        self.plugins = load_plugins()
        logger.debug(f"Loaded {len(self.plugins)} plugins.")

    def scan(self, url: str) -> Report:
        """Runs the complete scan against the target URL."""
        report = Report(url=url)
        logger.info(f"Starting scan on {url}")
        
        # 1. Fetch URL
        fetch_result = self.fetcher.fetch(url)
        
        if fetch_result.error:
            report.error = fetch_result.error
            logger.error(f"Fetch failed: {fetch_result.error}")
            return report
            
        report.status_code = fetch_result.status_code
        report.headers = fetch_result.headers
        
        # We only proceed to parse and check if we got a response body
        if fetch_result.body:
            # 2. Parse forms
            forms = extract_forms(fetch_result.body, url)
            report.forms = [f.to_dict() for f in forms]
            
            # 3. Run built-in checks
            logger.debug("Running header checks...")
            report.findings.extend(check_headers(fetch_result.headers))
            
            logger.debug("Running cookie checks...")
            report.findings.extend(check_cookies(fetch_result.cookies))
            
            logger.debug("Running CSRF checks...")
            report.findings.extend(check_csrf(forms))
            
            logger.debug("Running passive XSS checks...")
            report.findings.extend(check_xss(url, fetch_result.body))

            logger.debug("Running SQL injection indicator checks...")
            report.findings.extend(check_sql_injection(url, fetch_result.body))

            logger.debug("Running CORS checks...")
            report.findings.extend(check_cors(fetch_result.headers))

            logger.debug("Running server info disclosure checks...")
            report.findings.extend(check_server_info(fetch_result.headers, fetch_result.body))

            logger.debug("Running sensitive files checks...")
            report.findings.extend(check_sensitive_files(url, timeout=self.fetcher.timeout))

            logger.debug("Running mixed content checks...")
            report.findings.extend(check_mixed_content(url, fetch_result.body))

            logger.debug("Running deprecated headers checks...")
            report.findings.extend(check_deprecated_headers(fetch_result.headers))

            logger.debug("Running HTTP methods checks...")
            report.findings.extend(check_http_methods(url, timeout=self.fetcher.timeout))

            logger.debug("Running session fixation checks...")
            report.findings.extend(check_session_fixation(url, fetch_result.body))

            logger.debug("Running cookie expiry checks...")
            report.findings.extend(check_cookie_expiry(fetch_result.cookies))

            # 4. Run plugins
            report_data = {
                "url": url,
                "status_code": fetch_result.status_code,
                "headers": fetch_result.headers,
                "body": fetch_result.body,
                "cookies": fetch_result.cookies,
                "forms": forms  # pass actual Form objects in case plugins need them
            }
            
            logger.debug("Running plugins...")
            for plugin in self.plugins:
                try:
                    plugin_findings = plugin.run(report_data)
                    report.findings.extend(plugin_findings)
                except Exception as e:
                    logger.error(f"Plugin {plugin.__class__.__name__} failed: {e}")
                    report.findings.append({
                        "type": "plugin_error",
                        "plugin": plugin.__class__.__name__,
                        "msg": f"Plugin crashed during execution: {str(e)}"
                    })
                    
        logger.info(f"Scan complete. Found {len(report.findings)} issues.")
        return report
