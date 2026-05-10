🛡️ OWASP Mini-Scanner
A lightweight, modular, and extensible web application security scanner built in Python. Designed for developers, security students, and practitioners who need fast, accessible vulnerability assessment without heavyweight tooling or complex configuration.

📋 Table of Contents

Features
Architecture
Installation
Usage
Check Modules
Plugin System
Project Structure
Known Limitations


✨ Features

12 independent security check modules covering OWASP top vulnerability categories
Severity classification — Critical, High, Medium, and Informational tiers
Expandable finding cards with full technical metadata per vulnerability
Per-finding web search integration — click to instantly research any vulnerability
Scan history persisted in browser localStorage across sessions
Dual-format report export — styled HTML and structured JSON
Extensible plugin system — add custom checks without touching core code
Async scanning — non-blocking background thread execution with real-time progress
CLI support — headless execution for pipeline integration
Zero external service dependencies — runs entirely on your local machine


🏗️ Architecture
The scanner is built around a four-stage pipeline:
Fetcher → Form Parser → Check Engine (12 modules) → Report
                                ↑
                          Plugin System
ComponentResponsibilityFetcherHTTP requests, header/cookie/body capture, error handlingForm ParserBeautifulSoup HTML form extractionCheck Engine12 independent vulnerability check modulesPlugin SystemDynamic runtime loading of user-defined checksFlask Web AppAsync job manager + browser dashboardReport GeneratorHTML and JSON export

⚙️ Installation
Requirements: Python 3.8 or later
bash# Clone the repository
git clone https://github.com/your-username/owasp-scanner.git
cd owasp-scanner

# Install dependencies
pip install -r requirements.txt
Dependencies:
requests
beautifulsoup4
flask
jinja2
pytest

🚀 Usage
Web Interface
bashpython web_app.py
Then open your browser at http://127.0.0.1:5000 and enter a target URL.

⚠️ Flask runs in development mode by default. Do not expose this to a public network.

Command Line Interface
bashpython -m scanner.cli --url https://target.com
Optional flags:
bash--output json        # Export findings as JSON
--output html        # Export findings as HTML report
--timeout 10         # Set request timeout in seconds
Good targets for testing
URLNoteshttps://demo.testfire.netIBM Altoro Mutual — stable vulnerable banking demohttps://httpbin.orgReliable for header/cookie checkshttps://ginandjuice.shopPortSwigger deliberately vulnerable apphttps://public-firing-range.appspot.comGoogle's security test app

🔒 Only scan applications you own or have explicit permission to test.


🔍 Check Modules
ModuleSeverityWhat it detectsheaders.pyMediumMissing HSTS, CSP, X-Frame-Options, X-Content-Type-Optionscookies.pyMediumMissing HttpOnly, Secure, SameSite attributescsrf.pyHighPOST forms lacking CSRF token fieldsxss.pyHighQuery parameter values reflected in response bodysql_injection.pyCriticalDatabase error patterns in responsescors.pyHigh / CriticalWildcard origins, credentials misconfigurationsserver_info.pyInfoVersion disclosure in headers, sensitive HTML commentssensitive_files.pyCriticalExposed .env, .git, phpinfo.php, /actuator etc.mixed_content.pyMediumHTTP resources loaded on HTTPS pagesdeprecated_headers.pyInfoX-XSS-Protection, HPKP, Expect-CT, P3Phttp_methods.pyCritical / HighTRACE, PUT, DELETE enabled via OPTIONSsession_fixation.pyMediumSession IDs in URL query parameters or page linkscookie_expiry.pyMediumSession cookies with persistent expiry, excessive Max-Age

🔌 Plugin System
Add custom checks by creating a Python file in scanner/plugins/:
pythonfrom scanner.plugins import PluginBase

class MyCustomCheck(PluginBase):
    def run(self, report_data: dict) -> list:
        findings = []
        # your logic here
        findings.append({
            "type": "my_custom_finding",
            "msg": "Description of the issue",
            "details": { "key": "value" }
        })
        return findings
The plugin is automatically discovered and executed at runtime — no registration needed.

📁 Project Structure
owasp-scanner/
├── scanner/
│   ├── core.py               # Scanner orchestrator + Report dataclass
│   ├── fetcher.py            # HTTP fetching + error handling
│   ├── cli.py                # Command-line interface
│   ├── checks/
│   │   ├── headers.py
│   │   ├── cookies.py
│   │   ├── csrf.py
│   │   ├── xss.py
│   │   ├── sql_injection.py
│   │   ├── cors.py
│   │   ├── server_info.py
│   │   ├── sensitive_files.py
│   │   ├── mixed_content.py
│   │   ├── deprecated_headers.py
│   │   ├── http_methods.py
│   │   ├── session_fixation.py
│   │   └── cookie_expiry.py
│   ├── parsers/
│   │   └── forms.py          # HTML form extraction
│   └── plugins/
│       ├── __init__.py       # Plugin loader
│       └── example_plugin.py
├── templates/
│   └── index.html            # Web dashboard
├── static/
│   ├── style.css
│   └── script.js
├── web_app.py                # Flask app + async job manager
├── requirements.txt
└── setup.py

⚠️ Known Limitations

No JavaScript rendering — single-page applications built with React/Angular/Vue return minimal HTML; form detection and body-based checks are limited on such targets
Passive detection only — the scanner analyses responses without active fuzzing or payload injection
No authentication support — pages behind login walls cannot be scanned in their authenticated state
Soft-404 false positives — servers returning HTTP 200 for all paths may trigger false positives in sensitive file checks for paths without defined signatures
In-memory job store — restarting the Flask server clears all active scan jobs


📄 License
For authorized and ethical security testing only. Do not use this tool against systems you do not own or have explicit permission to test.
