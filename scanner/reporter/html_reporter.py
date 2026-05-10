import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from scanner.core import Report

class HTMLReporter:
    """Generates human-readable HTML reports using Jinja2 templates."""
    
    def __init__(self):
        # Set up Jinja environment pointing to the templates directory
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def render(self, report: Report) -> str:
        """Renders the report using the report.html template."""
        try:
            template = self.env.get_template('report.html')
        except Exception as e:
            return f"<h1>Error loading template: {e}</h1>"
        
        # Prepare data for the template
        findings_by_type = {}
        for finding in report.findings:
            f_type = finding.get('type', 'unknown')
            if f_type not in findings_by_type:
                findings_by_type[f_type] = []
            findings_by_type[f_type].append(finding)
            
        render_data = {
            "report": report.to_dict(),
            "findings_by_type": findings_by_type,
            "total_findings": len(report.findings),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return template.render(**render_data)
        
    def write(self, report: Report, path: str) -> None:
        """Writes the rendered HTML report to a file."""
        # Ensure directory exists
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        
        html_content = self.render(report)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)
