from flask import Flask, render_template, request, jsonify
from scanner.core import Scanner
import threading
import uuid
import time

app = Flask(__name__)

# Very basic in-memory "database" for scan jobs
# In a real app we'd use Redis + Celery
scan_jobs = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
        
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
        
    job_id = str(uuid.uuid4())
    
    scan_jobs[job_id] = {
        "status": "running",
        "url": url,
        "report": None,
        "error": None
    }
    
    # Run scan in a background thread
    def run_scan():
        try:
            scanner = Scanner()
            report = scanner.scan(url)
            
            scan_jobs[job_id]["status"] = "completed"
            scan_jobs[job_id]["report"] = report.to_dict()
        except Exception as e:
            scan_jobs[job_id]["status"] = "failed"
            scan_jobs[job_id]["error"] = str(e)
            
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({"job_id": job_id, "status": "started"})
    
@app.route('/api/scan/<job_id>', methods=['GET'])
def get_scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
        
    return jsonify(job)

def main():
    print("Starting OWASP Mini-Scanner Web Interface...")
    print("Access the dashboard at http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)

if __name__ == '__main__':
    main()
