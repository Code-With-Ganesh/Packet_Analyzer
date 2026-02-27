"""
DPI Engine Web Dashboard
========================
report.json padh ke ek beautiful HTML dashboard banata hai.
Browser mein open karo — koi server ki zaroorat nahi!

Usage:
    python dashboard.py                    # report.json use karta hai (default)
    python dashboard.py my_report.json     # custom file
"""

import json
import sys
import os
from datetime import datetime

def load_report(path="report.json"):
    if not os.path.exists(path):
        print(f"[Error] File nahi mila: {path}")
        print("Pehle run karo: .\\dpi_engine.exe input.pcap output.pcap --export-json report.json")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def human_bytes(b):
    b = int(b)
    if b >= 1073741824: return f"{b/1073741824:.1f} GB"
    if b >= 1048576:    return f"{b/1048576:.1f} MB"
    if b >= 1024:       return f"{b/1024:.1f} KB"
    return f"{b} B"

def generate_html(data, output="dashboard.html"):
    summary   = data.get("summary", {})
    bandwidth = data.get("bandwidth", {})
    threats   = data.get("threat_alerts", [])
    flows     = data.get("flows", [])

    # Sort bandwidth by bytes
    bw_sorted  = sorted(bandwidth.items(), key=lambda x: int(x[1]), reverse=True)
    bw_labels  = [x[0] for x in bw_sorted]
    bw_values  = [int(x[1]) for x in bw_sorted]
    bw_display = [human_bytes(x[1]) for x in bw_sorted]

    # App packet counts from flows
    app_counts = {}
    for f in flows:
        app = f.get("app", "Unknown")
        app_counts[app] = app_counts.get(app, 0) + 1
    app_sorted = sorted(app_counts.items(), key=lambda x: x[1], reverse=True)
    app_labels = [x[0] for x in app_sorted]
    app_values = [x[1] for x in app_sorted]

    # Threat type counts
    threat_types = {}
    for t in threats:
        tt = t.get("type", "Unknown")
        threat_types[tt] = threat_types.get(tt, 0) + 1

    # Top domains from flows
    domain_counts = {}
    for f in flows:
        d = f.get("domain", "")
        if d and not d.startswith("["):
            domain_counts[d] = domain_counts.get(d, 0) + f.get("bytes", 0)
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Colors for charts
    COLORS = [
        "#4e79a7","#f28e2b","#e15759","#76b7b2","#59a14f",
        "#edc948","#b07aa1","#ff9da7","#9c755f","#bab0ac",
        "#d37295","#fabfd2","#8cd17d","#b6992d","#499894"
    ]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DPI Engine Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; }}
  header {{ background: linear-gradient(135deg, #1a1f2e, #0d1b2a); padding: 24px 32px; border-bottom: 2px solid #3a7bd5; }}
  header h1 {{ font-size: 28px; color: #3a7bd5; letter-spacing: 1px; }}
  header p  {{ color: #888; font-size: 13px; margin-top: 4px; }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }}
  .stat-card {{ background: #1a1f2e; border-radius: 12px; padding: 20px 24px; border-left: 4px solid #3a7bd5; }}
  .stat-card .label {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
  .stat-card .value {{ font-size: 28px; font-weight: 700; color: #fff; margin-top: 6px; }}
  .stat-card .sub   {{ font-size: 12px; color: #3a7bd5; margin-top: 2px; }}
  .charts-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 28px; }}
  .chart-card {{ background: #1a1f2e; border-radius: 12px; padding: 20px; }}
  .chart-card h3 {{ font-size: 15px; color: #aaa; margin-bottom: 16px; border-bottom: 1px solid #2a2f3e; padding-bottom: 10px; }}
  .full-width {{ grid-column: 1 / -1; }}
  .threats-section {{ background: #1a1f2e; border-radius: 12px; padding: 20px; margin-bottom: 28px; border-left: 4px solid #e15759; }}
  .threats-section h3 {{ color: #e15759; margin-bottom: 16px; font-size: 16px; }}
  .threat-item {{ display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid #2a2f3e; }}
  .threat-item:last-child {{ border-bottom: none; }}
  .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
  .badge-scan   {{ background: #e1575920; color: #e15759; border: 1px solid #e15759; }}
  .badge-flood  {{ background: #f28e2b20; color: #f28e2b; border: 1px solid #f28e2b; }}
  .badge-udp    {{ background: #edc94820; color: #edc948; border: 1px solid #edc948; }}
  .threat-detail {{ color: #888; font-size: 13px; }}
  .flows-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .flows-table th {{ background: #0d1b2a; color: #3a7bd5; padding: 10px 14px; text-align: left; font-weight: 600; }}
  .flows-table td {{ padding: 8px 14px; border-bottom: 1px solid #2a2f3e; color: #ccc; }}
  .flows-table tr:hover td {{ background: #22283a; }}
  .status-blocked   {{ color: #e15759; font-weight: 700; }}
  .status-forwarded {{ color: #59a14f; }}
  @media (max-width: 900px) {{ .charts-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header>
  <h1>⚡ DPI Engine Dashboard</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; Deep Packet Inspection Report</p>
</header>
<div class="container">

  <!-- Summary Cards -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="label">Total Packets</div>
      <div class="value">{int(summary.get('total_packets', 0)):,}</div>
    </div>
    <div class="stat-card">
      <div class="label">Total Data</div>
      <div class="value">{human_bytes(summary.get('total_bytes', 0))}</div>
    </div>
    <div class="stat-card" style="border-left-color:#59a14f">
      <div class="label">Forwarded</div>
      <div class="value" style="color:#59a14f">{int(summary.get('forwarded', 0)):,}</div>
    </div>
    <div class="stat-card" style="border-left-color:#e15759">
      <div class="label">Dropped / Blocked</div>
      <div class="value" style="color:#e15759">{int(summary.get('dropped', 0)):,}</div>
    </div>
    <div class="stat-card" style="border-left-color:#f28e2b">
      <div class="label">Threat Alerts</div>
      <div class="value" style="color:#f28e2b">{len(threats)}</div>
    </div>
    <div class="stat-card" style="border-left-color:#b07aa1">
      <div class="label">Unique Flows</div>
      <div class="value">{len(flows):,}</div>
    </div>
  </div>

  <!-- Charts Row 1 -->
  <div class="charts-grid">
    <div class="chart-card">
      <h3>📱 App Distribution (by flows)</h3>
      <canvas id="appPie" height="260"></canvas>
    </div>
    <div class="chart-card">
      <h3>📶 Bandwidth per App</h3>
      <canvas id="bwBar" height="260"></canvas>
    </div>
  </div>

  <!-- Threat Alerts -->
  {'<div class="threats-section"><h3>🚨 Threat Alerts (' + str(len(threats)) + ')</h3>' + ''.join([
    f'<div class="threat-item"><span class="badge badge-{"scan" if t["type"]=="PORT_SCAN" else "flood" if t["type"]=="CONN_FLOOD" else "udp"}">{t["type"]}</span><span style="color:#fff;font-size:13px;">{t["src_ip"]}</span><span class="threat-detail">{t["detail"]}</span></div>'
    for t in threats
  ]) + '</div>' if threats else '<div class="threats-section" style="border-left-color:#59a14f"><h3 style="color:#59a14f">✅ No Threats Detected</h3></div>'}

  <!-- Top Flows Table -->
  <div class="chart-card">
    <h3>🔍 Top 50 Flows (by bytes)</h3>
    <div style="overflow-x:auto">
    <table class="flows-table">
      <thead><tr>
        <th>Source IP</th><th>Destination IP</th><th>Protocol</th>
        <th>App</th><th>Domain</th><th>Packets</th><th>Bytes</th><th>Status</th>
      </tr></thead>
      <tbody>
        {''.join([
          f'<tr>'
          f'<td>{f["src"]}</td><td>{f["dst"]}</td>'
          f'<td>{f["proto"]}</td>'
          f'<td><b>{f["app"]}</b></td>'
          f'<td style="color:#aaa;max-width:200px;overflow:hidden;text-overflow:ellipsis">{f.get("domain","")}</td>'
          f'<td>{f["pkts"]:,}</td>'
          f'<td>{human_bytes(f["bytes"])}</td>'
          f'<td class="status-{f["status"].lower()}">{f["status"]}</td>'
          f'</tr>'
          for f in sorted(flows, key=lambda x: x.get("bytes",0), reverse=True)[:50]
        ])}
      </tbody>
    </table>
    </div>
  </div>

</div>

<script>
// App Pie Chart
new Chart(document.getElementById('appPie'), {{
  type: 'doughnut',
  data: {{
    labels: {app_labels},
    datasets: [{{ data: {app_values}, backgroundColor: {COLORS[:len(app_labels)]}, borderWidth: 2, borderColor: '#0f1117' }}]
  }},
  options: {{ plugins: {{ legend: {{ position: 'right', labels: {{ color: '#ccc', font: {{ size: 12 }} }} }} }}, cutout: '60%' }}
}});

// Bandwidth Bar Chart
new Chart(document.getElementById('bwBar'), {{
  type: 'bar',
  data: {{
    labels: {bw_labels},
    datasets: [{{
      label: 'Bytes',
      data: {bw_values},
      backgroundColor: {COLORS[:len(bw_labels)]},
      borderRadius: 6
    }}]
  }},
  options: {{
    plugins: {{ legend: {{ display: false }},
      tooltip: {{ callbacks: {{ label: function(ctx) {{
        var b = ctx.raw;
        if(b>=1073741824) return (b/1073741824).toFixed(1)+' GB';
        if(b>=1048576) return (b/1048576).toFixed(1)+' MB';
        if(b>=1024) return (b/1024).toFixed(1)+' KB';
        return b+' B';
      }}}}}}
    }},
    scales: {{
      x: {{ ticks: {{ color: '#ccc' }}, grid: {{ color: '#2a2f3e' }} }},
      y: {{ ticks: {{ color: '#ccc', callback: function(v) {{
        if(v>=1048576) return (v/1048576).toFixed(0)+'MB';
        if(v>=1024) return (v/1024).toFixed(0)+'KB';
        return v+'B';
      }}}}, grid: {{ color: '#2a2f3e' }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[Dashboard] Generated: {output}")
    print(f"[Dashboard] Browser mein open karo: file://{os.path.abspath(output)}")

if __name__ == "__main__":
    json_file = sys.argv[1] if len(sys.argv) > 1 else "report.json"
    data = load_report(json_file)
    generate_html(data)
