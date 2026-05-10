import argparse
import sys
import os

from scanner.core import Scanner
from scanner.reporter.json_reporter import JSONReporter
from scanner.reporter.html_reporter import HTMLReporter

def main():
    parser = argparse.ArgumentParser(description="OWASP Mini-Scanner: A passive web vulnerability scanner.")
    parser.add_argument("url", help="Target URL to scan (e.g., https://example.com)")
    parser.add_argument("--json", help="Path to output JSON report", metavar="FILE")
    parser.add_argument("--html", help="Path to output HTML report", metavar="FILE")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout in seconds")
    
    args = parser.parse_args()
    
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
        
    print(f"[*] Starting scan for: {args.url}")
    
    scanner = Scanner(timeout=args.timeout)
    report = scanner.scan(args.url)
    
    # Process output
    if report.error:
        print(f"[!] Scan failed: {report.error}")
        # Always output failure reports if requested
        if args.json:
            JSONReporter.write(report, args.json)
            print(f"[*] JSON error report saved to {args.json}")
        sys.exit(1)
        
    print(f"[*] Scan complete! Found {len(report.findings)} issues.")
    
    # Save reports
    if args.json:
        JSONReporter.write(report, args.json)
        print(f"[*] JSON report saved to {args.json}")
        
    if args.html:
        reporter = HTMLReporter()
        reporter.write(report, args.html)
        print(f"[*] HTML report saved to {args.html}")
        
    # If no output files specified, print a quick summary
    if not args.json and not args.html:
        print("\n--- Summary ---")
        print(f"Status Code: {report.status_code}")
        print(f"Forms Found: {len(report.forms)}")
        
        if report.findings:
            print("\nFindings:")
            for f in report.findings:
                print(f"  - [{f.get('type')}] {f.get('msg')}")
        else:
             print("\nNo vulnerabilities found.")
             
        print("\nTip: Use --html report.html for a detailed view.")
        
if __name__ == "__main__":
    main()
