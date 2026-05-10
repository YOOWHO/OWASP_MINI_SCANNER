import json
import os
from scanner.core import Report

class JSONReporter:
    """Serializes scanner Report objects to JSON format."""
    
    @staticmethod
    def to_json(report: Report) -> str:
        """Returns the report as a JSON string."""
        return json.dumps(report.to_dict(), indent=2)

    @staticmethod
    def write(report: Report, path: str) -> None:
        """Writes the report to a JSON file."""
        # Ensure directory exists
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(JSONReporter.to_json(report))
