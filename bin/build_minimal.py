#!/usr/bin/env python3
"""
MINIMAL EMERGENCY BUILD - Only builds latest report
Use this if full build.py is timing out
"""

import os
import sys
import json
import datetime
import shutil
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = SCRIPT_DIR.parent
TEMPLATE_DIR = ROOT_DIR / "templates"
OUTPUT_DIR = ROOT_DIR / "public"
REPORTS_DIR = ROOT_DIR / "nightly_reports"

OUTPUT_DIR.mkdir(exist_ok=True)

def get_latest_report():
    """Get the absolute latest report file"""
    json_files = sorted(
        REPORTS_DIR.glob("clickgrab_report_*.json"),
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )
    return json_files[0] if json_files else None

def build_minimal():
    """Build only the absolute minimum - index and latest report"""
    print("🚀 MINIMAL BUILD - Latest report only", flush=True)
    
    # Setup Jinja2
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    base_url = "/ClickGrab"
    
    # Get latest report
    latest_file = get_latest_report()
    if not latest_file:
        print("❌ No reports found")
        return
    
    print(f"📄 Loading {latest_file.name}", flush=True)
    with open(latest_file, 'r') as f:
        report_data = json.load(f)
    
    # Extract date
    date = latest_file.stem.split('_')[2]
    
    # Build simple index
    print("📝 Building index...", flush=True)
    template = env.get_template("index.html")
    stats = {
        'total_sites': report_data.get('total_sites_analyzed', 0),
        'malicious_sites': report_data.get('summary', {}).get('suspicious_sites', 0),
        'total_indicators': 0,
        'powershell_attacks': report_data.get('summary', {}).get('powershell_commands', 0),
        'clipboard_attacks': report_data.get('summary', {}).get('clipboard_manipulation', 0),
        'high_risk_commands': report_data.get('summary', {}).get('high_risk_commands', 0),
        'latest_date': date
    }
    
    html = template.render(
        stats=stats,
        recent_reports=[],
        base_url=base_url,
        active_page='home'
    )
    
    with open(OUTPUT_DIR / "index.html", 'w') as f:
        f.write(html)
    
    # Copy to docs using rsync
    print("📦 Syncing to docs...", flush=True)
    docs_dir = ROOT_DIR / "docs"
    docs_dir.mkdir(exist_ok=True)
    
    try:
        import subprocess
        subprocess.run([
            'rsync', '-a', '--delete',
            f'{OUTPUT_DIR}/',
            f'{docs_dir}/'
        ], check=True)
        print("✅ Synced with rsync", flush=True)
    except:
        # Fallback to copy
        shutil.copy2(OUTPUT_DIR / "index.html", docs_dir / "index.html")
        print("✅ Copied index.html", flush=True)
    
    print("✨ Minimal build complete!", flush=True)

if __name__ == "__main__":
    build_minimal()

