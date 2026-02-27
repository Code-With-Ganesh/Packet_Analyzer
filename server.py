"""
DPI Engine — Real-time Dashboard Server
========================================
Flask + SocketIO backend for dynamic packet analysis.

Features:
  - REST API: /api/stats, /api/flows, /api/threats, /api/bandwidth, /api/rules
  - WebSocket: real-time push updates to dashboard
  - Rule Management: add/remove rules from browser (no recompile!)
  - Analysis Trigger: run C++ DPI engine from dashboard UI
  - File Watcher: auto-detects report.json changes
"""

import os
import json
import time
import glob
import subprocess
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# ===========================================================================
# Configuration
# ===========================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(BASE_DIR, 'rules.json')
REPORT_FILE = os.path.join(BASE_DIR, 'report.json')
CSV_FILE = os.path.join(BASE_DIR, 'report.csv')
ENGINE_EXE = os.path.join(BASE_DIR, 'dpi_engine.exe')
OUTPUT_PCAP = os.path.join(BASE_DIR, 'my_output.pcap')

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'dpi-engine-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Track analysis state
analysis_running = False
report_mtime = 0

# ===========================================================================
# Helper Functions
# ===========================================================================
def load_rules():
    """Load rules from rules.json (create default if not exists)"""
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        "blocked_apps": [],
        "blocked_ips": [],
        "blocked_domains": [],
        "threat_thresholds": {
            "port_scan_ports": 20,
            "conn_flood_per_sec": 500,
            "udp_flood_packets": 1000
        }
    }


def save_rules(rules):
    """Save rules to rules.json"""
    with open(RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=2)


def load_report():
    """Load latest analysis report from report.json"""
    if os.path.exists(REPORT_FILE):
        try:
            with open(REPORT_FILE, 'r') as f:
                return json.load(f)
        except:
            return None
    return None


def find_pcap_files():
    """Find all .pcap files in the project directory"""
    pcaps = []
    for pattern in ['*.pcap', 'include/*.pcap']:
        for f in glob.glob(os.path.join(BASE_DIR, pattern)):
            rel = os.path.relpath(f, BASE_DIR).replace('\\', '/')
            size_mb = os.path.getsize(f) / (1024 * 1024)
            pcaps.append({'path': rel, 'size': f'{size_mb:.1f} MB'})
    return pcaps


def human_bytes(b):
    """Convert bytes to human readable string"""
    if b >= 1073741824: return f'{b / 1073741824:.1f} GB'
    if b >= 1048576: return f'{b / 1048576:.1f} MB'
    if b >= 1024: return f'{b / 1024:.1f} KB'
    return f'{b} B'


# ===========================================================================
# Dashboard Route
# ===========================================================================
@app.route('/')
def index():
    return render_template('index.html')


# ===========================================================================
# REST API — Statistics
# ===========================================================================
@app.route('/api/stats')
def api_stats():
    report = load_report()
    if not report:
        return jsonify({"error": "No report available. Run an analysis first."}), 404
    summary = report.get('summary', {})
    summary['total_flows'] = len(report.get('flows', []))
    summary['total_threats'] = len(report.get('threat_alerts', []))
    summary['total_bytes_human'] = human_bytes(summary.get('total_bytes', 0))
    return jsonify(summary)


@app.route('/api/flows')
def api_flows():
    report = load_report()
    if not report:
        return jsonify({"total": 0, "page": 1, "flows": []})

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 100, type=int)
    search = request.args.get('search', '').lower().strip()
    sort_by = request.args.get('sort', 'bytes')
    order = request.args.get('order', 'desc')

    flows = report.get('flows', [])

    # Search filter
    if search:
        flows = [f for f in flows if search in json.dumps(f).lower()]

    # Sort
    reverse = (order == 'desc')
    if sort_by in ('bytes', 'pkts'):
        flows = sorted(flows, key=lambda f: f.get(sort_by, 0), reverse=reverse)
    elif sort_by == 'app':
        flows = sorted(flows, key=lambda f: f.get('app', ''), reverse=reverse)

    total = len(flows)
    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page,
        "flows": flows[start:end]
    })


@app.route('/api/threats')
def api_threats():
    report = load_report()
    if not report:
        return jsonify([])
    return jsonify(report.get('threat_alerts', []))


@app.route('/api/bandwidth')
def api_bandwidth():
    report = load_report()
    if not report:
        return jsonify({})
    bw = report.get('bandwidth', {})
    # Add human-readable versions
    result = {}
    for app_name, bytes_val in bw.items():
        result[app_name] = {
            'bytes': bytes_val,
            'human': human_bytes(bytes_val)
        }
    return jsonify(result)


@app.route('/api/pcap-files')
def api_pcap_files():
    return jsonify(find_pcap_files())


@app.route('/api/upload-pcap', methods=['POST'])
def upload_pcap():
    """Upload a new PCAP file"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    # Only allow .pcap and .pcapng files
    if not file.filename.lower().endswith(('.pcap', '.pcapng')):
        return jsonify({"error": "Only .pcap and .pcapng files allowed"}), 400

    # Save to include/ directory (where MY_Traffic.pcap is)
    save_dir = os.path.join(BASE_DIR, 'include')
    os.makedirs(save_dir, exist_ok=True)
    save_path = os.path.join(save_dir, file.filename)
    file.save(save_path)

    size_mb = os.path.getsize(save_path) / (1024 * 1024)
    pcaps = find_pcap_files()
    socketio.emit('pcap_list', pcaps)

    return jsonify({
        "success": True,
        "filename": file.filename,
        "path": f'include/{file.filename}',
        "size": f'{size_mb:.1f} MB',
        "pcap_files": pcaps
    })


# ===========================================================================
# REST API — Rules Management
# ===========================================================================
@app.route('/api/rules', methods=['GET'])
def get_rules():
    return jsonify(load_rules())


@app.route('/api/rules', methods=['POST'])
def update_rules():
    data = request.json
    rules = load_rules()

    # Add rules
    if 'add_app' in data:
        name = data['add_app'].strip()
        if name and name not in rules['blocked_apps']:
            rules['blocked_apps'].append(name)
    if 'add_ip' in data:
        ip = data['add_ip'].strip()
        if ip and ip not in rules['blocked_ips']:
            rules['blocked_ips'].append(ip)
    if 'add_domain' in data:
        dom = data['add_domain'].strip()
        if dom and dom not in rules['blocked_domains']:
            rules['blocked_domains'].append(dom)

    # Remove rules
    if 'remove_app' in data:
        rules['blocked_apps'] = [a for a in rules['blocked_apps'] if a != data['remove_app']]
    if 'remove_ip' in data:
        rules['blocked_ips'] = [i for i in rules['blocked_ips'] if i != data['remove_ip']]
    if 'remove_domain' in data:
        rules['blocked_domains'] = [d for d in rules['blocked_domains'] if d != data['remove_domain']]

    # Update thresholds
    if 'thresholds' in data:
        rules['threat_thresholds'].update(data['thresholds'])

    save_rules(rules)
    socketio.emit('rules_updated', rules)
    return jsonify(rules)


# ===========================================================================
# REST API — Analysis Engine
# ===========================================================================
@app.route('/api/analyze', methods=['POST'])
def analyze():
    global analysis_running
    if analysis_running:
        return jsonify({"error": "Analysis already running"}), 409

    data = request.json or {}
    pcap_file = data.get('pcap_file', 'include/MY_Traffic.pcap')
    pcap_path = os.path.join(BASE_DIR, pcap_file)

    if not os.path.exists(pcap_path):
        return jsonify({"error": f"PCAP file not found: {pcap_file}"}), 404

    if not os.path.exists(ENGINE_EXE):
        return jsonify({"error": "DPI engine not compiled. Run: g++ -std=c++17 -O2 -I include -o dpi_engine.exe src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp"}), 500

    # Build command from rules
    rules = load_rules()
    cmd = [
        ENGINE_EXE,
        pcap_file,
        'my_output.pcap',
        '--export-json', 'report.json',
        '--export-csv', 'report.csv'
    ]
    for app_name in rules.get('blocked_apps', []):
        cmd.extend(['--block-app', app_name])
    for ip in rules.get('blocked_ips', []):
        cmd.extend(['--block-ip', ip])
    for dom in rules.get('blocked_domains', []):
        cmd.extend(['--block-domain', dom])

    analysis_running = True
    socketio.emit('analysis_started', {
        'pcap': pcap_file,
        'rules': rules,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

    def run_engine():
        global analysis_running
        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=BASE_DIR,
                timeout=120
            )
            elapsed = time.time() - start_time
            report = load_report()

            socketio.emit('analysis_complete', {
                'success': result.returncode == 0,
                'elapsed': f'{elapsed:.1f}s',
                'output': result.stdout[-3000:] if result.stdout else '',
                'stderr': result.stderr[-1000:] if result.stderr else '',
                'report': report
            })
        except subprocess.TimeoutExpired:
            socketio.emit('analysis_complete', {
                'success': False,
                'error': 'Analysis timed out (120s limit)'
            })
        except Exception as e:
            socketio.emit('analysis_complete', {
                'success': False,
                'error': str(e)
            })
        finally:
            analysis_running = False

    threading.Thread(target=run_engine, daemon=True).start()
    return jsonify({"status": "running", "pcap": pcap_file})


# ===========================================================================
# WebSocket Events
# ===========================================================================
@socketio.on('connect')
def handle_connect():
    """Send initial data when client connects"""
    report = load_report()
    rules = load_rules()
    pcaps = find_pcap_files()
    emit('initial_data', {
        'report': report,
        'rules': rules,
        'pcap_files': pcaps,
        'engine_exists': os.path.exists(ENGINE_EXE),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@socketio.on('request_update')
def handle_update_request():
    """Client requests fresh data"""
    report = load_report()
    emit('data_update', report)


@socketio.on('request_pcap_list')
def handle_pcap_list():
    """Client requests PCAP file list"""
    emit('pcap_list', find_pcap_files())


# ===========================================================================
# Background File Watcher
# ===========================================================================
def watch_report_file():
    """Watch report.json for changes and push updates via WebSocket"""
    global report_mtime
    while True:
        try:
            if os.path.exists(REPORT_FILE):
                mtime = os.path.getmtime(REPORT_FILE)
                if mtime != report_mtime:
                    report_mtime = mtime
                    time.sleep(0.5)  # Wait for file write to complete
                    report = load_report()
                    if report:
                        socketio.emit('data_update', report)
        except Exception:
            pass
        time.sleep(2)


# ===========================================================================
# Main Entry Point
# ===========================================================================
if __name__ == '__main__':
    # Ensure rules.json exists
    if not os.path.exists(RULES_FILE):
        save_rules(load_rules())

    # Create templates dir if needed
    templates_dir = os.path.join(BASE_DIR, 'templates')
    if not os.path.exists(templates_dir):
        os.makedirs(templates_dir)

    # Start file watcher
    watcher = threading.Thread(target=watch_report_file, daemon=True)
    watcher.start()

    # Banner
    print()
    print('=' * 62)
    print('  DPI Engine — Real-time Dashboard Server')
    print('=' * 62)
    print(f'  Dashboard:  http://localhost:5000')
    print(f'  API Base:   http://localhost:5000/api')
    print(f'  Rules:      {RULES_FILE}')
    print(f'  Engine:     {ENGINE_EXE} {"✓" if os.path.exists(ENGINE_EXE) else "✗ (not compiled)"}')
    print(f'  Report:     {REPORT_FILE} {"✓" if os.path.exists(REPORT_FILE) else "✗ (run analysis)"}')
    print('=' * 62)
    print()

    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
