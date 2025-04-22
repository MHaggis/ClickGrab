#!/usr/bin/env python3
"""
ClickGrab HTML Generator
Builds HTML files from Jinja2 templates using analysis data
"""

import os
import sys
import json
import datetime
import shutil
import markdown
import re
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = SCRIPT_DIR.parent
TEMPLATE_DIR = ROOT_DIR / "templates"
OUTPUT_DIR = ROOT_DIR / "public"
REPORTS_DIR = ROOT_DIR / "nightly_reports"
ANALYSIS_DIR = ROOT_DIR / "analysis"
ASSETS_DIR = ROOT_DIR / "assets"
CSS_DIR = TEMPLATE_DIR / "css"

OUTPUT_DIR.mkdir(exist_ok=True)

def copy_static_files():
    """Copy CSS and static assets to output directory"""
    assets_output_dir = OUTPUT_DIR / "assets"
    assets_output_dir.mkdir(exist_ok=True)
    
    css_output_dir = assets_output_dir / "css"
    css_output_dir.mkdir(exist_ok=True)
    
    # Copy CSS files if they exist
    css_source_file = CSS_DIR / "styles.css"
    if css_source_file.exists():
        # Read and write with explicit encoding to avoid Windows encoding issues
        with open(css_source_file, 'r', encoding='utf-8') as src:
            css_content = src.read()
            with open(css_output_dir / "styles.css", 'w', encoding='utf-8') as dst:
                dst.write(css_content)
        print(f"✅ Copied styles.css from {css_source_file}")
    else:
        # Try alternate filename
        css_source_file = CSS_DIR / "style.css"
        if css_source_file.exists():
            # Read and write with explicit encoding to avoid Windows encoding issues
            with open(css_source_file, 'r', encoding='utf-8') as src:
                css_content = src.read()
                with open(css_output_dir / "styles.css", 'w', encoding='utf-8') as dst:
                    dst.write(css_content)
            print(f"✅ Copied style.css to styles.css")
        else:
            print("⚠️ No CSS file found in templates/css/")
    
    # Create images directory
    images_output_dir = assets_output_dir / "images"
    images_output_dir.mkdir(exist_ok=True)
    
    # Look for logo.png in various possible locations
    logo_found = False
    logo_paths = [
        ROOT_DIR / "assets" / "images" / "logo.png",
        ROOT_DIR / "assets" / "logo.png",
        ROOT_DIR / "logo.png"
    ]
    
    for logo_path in logo_paths:
        if logo_path.exists():
            # Copy the PNG logo file
            with open(logo_path, 'rb') as src:
                with open(images_output_dir / "logo.png", 'wb') as dst:
                    dst.write(src.read())
            print(f"✅ Copied logo.png from {logo_path}")
            logo_found = True
            break
    
    # If no PNG logo was found, try to use SVG or create placeholders
    if not logo_found:
        print("⚠️ No logo.png found, using text-based logo instead")
        # We won't create any placeholder images - the template will handle this with text
    
    # Create empty main.js file
    js_output_dir = assets_output_dir / "js"
    js_output_dir.mkdir(exist_ok=True)
    
    js_file = js_output_dir / "main.js"
    if not js_file.exists():
        with open(js_file, "w", encoding='utf-8') as f:
            f.write("// ClickGrab main JavaScript file\n")

def get_latest_report_date():
    report_files = list(REPORTS_DIR.glob("clickgrab_report_*.json"))
    if not report_files:
        return datetime.datetime.now().strftime("%Y-%m-%d")
    
    dates = []
    for file in report_files:
        try:
            date_str = file.name.split("_")[2].split(".")[0]
            dates.append(date_str)
        except (IndexError, ValueError):
            continue
    
    if not dates:
        return datetime.datetime.now().strftime("%Y-%m-%d")
    
    return sorted(dates)[-1]

def load_report_data(date_str=None):
    if not date_str:
        date_str = get_latest_report_date()
    
    report_file = REPORTS_DIR / f"clickgrab_report_{date_str}.json"
    if not report_file.exists():
        print(f"Warning: Report file for {date_str} not found")
        return None
    
    try:
        with open(report_file, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {report_file}")
        return None

def load_analysis_markdown(date_str=None):
    if not date_str:
        date_str = get_latest_report_date()
    
    analysis_file = ANALYSIS_DIR / f"report_{date_str}.md"
    if not analysis_file.exists():
        analysis_file = ANALYSIS_DIR / "latest.md"
        if not analysis_file.exists():
            print(f"Warning: Analysis markdown file not found")
            return None
    
    try:
        with open(analysis_file, "r") as f:
            return f.read()
    except Exception as e:
        print(f"Error: Could not read markdown from {analysis_file}: {e}")
        return None

def get_all_report_dates():
    report_files = list(REPORTS_DIR.glob("clickgrab_report_*.json"))
    dates = []
    
    for file in report_files:
        try:
            date_str = file.name.split("_")[2].split(".")[0]
            dates.append(date_str)
        except (IndexError, ValueError):
            continue
    
    return sorted(dates, reverse=True)

def convert_markdown_to_html(markdown_text):
    if not markdown_text:
        return ""
    return markdown.markdown(markdown_text, extensions=['tables', 'fenced_code'])

def build_index_page(env, base_url):
    template = env.get_template("index.html")
    latest_date = get_latest_report_date()
    report_data = load_report_data(latest_date)
    
    total_sites = 0
    total_malicious_urls = 0
    sites_with_attacks = 0
    powershell_command_count = 0
    clipboard_manipulation_count = 0
    
    if report_data:
        print(f"Processing report data for {latest_date}, found {len(report_data.get('Sites', []))} sites")
        total_sites = len(report_data.get("Sites", []))
        for site in report_data.get("Sites", []):
            # Skip None values in the Sites array
            if site is None:
                continue
                
            has_attacks = False
            urls = site.get("Urls", [])
            if isinstance(urls, list) and urls:
                total_malicious_urls += len(urls)
                has_attacks = True
            elif isinstance(urls, str) and urls:
                total_malicious_urls += 1
                has_attacks = True
            
            if has_attacks:
                sites_with_attacks += 1
            
            # Count PowerShell commands
            ps_commands = site.get("PowerShellCommands", [])
            if ps_commands:
                if isinstance(ps_commands, list):
                    powershell_command_count += len(ps_commands)
                else:
                    powershell_command_count += 1
            
            # Count clipboard manipulations
            clipboard_manip = site.get("ClipboardManipulation", [])
            if clipboard_manip and isinstance(clipboard_manip, list):
                clipboard_manipulation_count += len(clipboard_manip)
    
    # Log stats info for debugging
    print(f"Index page stats: scanned={total_sites}, malicious={sites_with_attacks}, patterns={total_malicious_urls}")
    print(f"Command count: {powershell_command_count}, Clipboard count: {clipboard_manipulation_count}")
    
    # Make sure we don't display empty reports section
    report_dates = get_all_report_dates()[:5]
    if not report_dates:
        print("Warning: No report dates found")
        report_dates = [latest_date]
        
    recent_reports = []
    for date in report_dates:
        recent_reports.append({
            "date": date,
            "url": f"{base_url}/reports/{date}.html"
        })
    
    # For the statistics cards on index.html:
    # - sites_scanned is the total number of sites analyzed
    # - sites_with_attacks is the number of malicious URLs found
    # - total_attacks is the total number of attack patterns found
    
    html = template.render(
        sites_scanned=total_sites,
        sites_with_attacks=sites_with_attacks,
        total_attacks=total_malicious_urls,
        latest_report_date=latest_date,
        latest_sites_scanned=total_sites,
        latest_sites_with_attacks=sites_with_attacks,
        latest_new_attacks=0,
        latest_crypto_attacks=powershell_command_count,
        latest_url_attacks=clipboard_manipulation_count,
        recent_reports=recent_reports,
        active_page='home',
        base_url=base_url
    )
    
    with open(OUTPUT_DIR / "index.html", "w", encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Generated index.html")

def build_report_pages(env, base_url):
    template = env.get_template("report.html")
    report_dates = get_all_report_dates()
    
    reports_dir = OUTPUT_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    if report_dates:
        latest_date = report_dates[0]
        with open(OUTPUT_DIR / "latest_report.html", "w", encoding='utf-8') as f:
            f.write(f'<meta http-equiv="refresh" content="0;url={base_url}/reports/{latest_date}.html">')
    
    for date in report_dates:
        report_data = load_report_data(date)
        analysis_markdown = load_analysis_markdown(date)
        
        if not report_data:
            continue
        
        total_sites = len(report_data.get("Sites", []))
        total_malicious_urls = 0
        sites_with_attacks = 0
        
        site_list = []
        url_details = []
        
        for site in report_data.get("Sites", []):
            # Skip None values in the Sites array
            if site is None:
                continue
                
            site_url = site.get("URL", site.get("Url", "Unknown"))
            urls = site.get("Urls", [])
            url_count = 0
            has_attack = False
            
            if isinstance(urls, list) and urls:
                url_count = len(urls)
                has_attack = True
            elif isinstance(urls, str) and urls:
                url_count = 1
                has_attack = True
            
            if has_attack:
                total_malicious_urls += url_count
                sites_with_attacks += 1
            
            domain = site_url
            try:
                from urllib.parse import urlparse
                domain = urlparse(site_url).netloc
            except:
                pass
            
            attack_type = "Unknown"
            attack_type_class = "secondary"
            if "PowerShellDownloads" in site or "PowerShellCommands" in site:
                attack_type = "PowerShell Execution"
                attack_type_class = "danger"
            elif "ClipboardManipulation" in site:
                attack_type = "Clipboard Manipulation"
                attack_type_class = "warning"
            elif url_count > 0:
                attack_type = "URL Redirection"
                attack_type_class = "info"
            
            site_list.append({
                "domain": domain,
                "attack_type": attack_type,
                "attack_type_class": attack_type_class,
                "patterns": url_count,
                "first_seen": date,
                "has_attack": has_attack
            })
            
            # Extract detailed URL analysis for each site with malicious content
            if has_attack:
                # Extract PowerShell commands
                ps_commands = []
                if "PowerShellCommands" in site:
                    if isinstance(site["PowerShellCommands"], list):
                        ps_commands = [cmd for cmd in site["PowerShellCommands"] if cmd is not None]
                    else:
                        if site["PowerShellCommands"] is not None:
                            ps_commands = [site["PowerShellCommands"]]
                
                # Extract malicious code snippets
                malicious_code = None
                if ps_commands:
                    malicious_code = "\n".join(ps_commands)
                elif "PowerShellDownloads" in site:
                    downloads = site["PowerShellDownloads"]
                    if isinstance(downloads, list) and downloads:
                        for download in downloads:
                            if isinstance(download, dict) and "Context" in download:
                                if not malicious_code:
                                    malicious_code = download["Context"]
                                    break
                    elif isinstance(downloads, dict) and "Context" in downloads:
                        malicious_code = downloads["Context"]
                
                # Extract IOCs (Indicators of Compromise)
                iocs = []
                
                # URLs as IOCs
                if isinstance(urls, list):
                    for url in urls:
                        if url and isinstance(url, str) and "http" in url:
                            iocs.append({"type": "URL", "value": url})
                elif isinstance(urls, str) and "http" in urls:
                    iocs.append({"type": "URL", "value": urls})
                
                # Extract techniques
                techniques = []
                if attack_type == "PowerShell Execution":
                    techniques.append("PowerShell Command Execution")
                    if "PowerShellDownloads" in site:
                        techniques.append("Remote Script Download")
                
                if "ClipboardManipulation" in site:
                    techniques.append("Clipboard Hijacking")
                    techniques.append("FakeCAPTCHA Social Engineering")
                
                if "SuspiciousKeywords" in site:
                    keywords = site.get("SuspiciousKeywords", [])
                    if isinstance(keywords, list):
                        for kw in keywords:
                            if "robot" in kw.lower() or "captcha" in kw.lower() or "verification" in kw.lower():
                                if "FakeCAPTCHA Social Engineering" not in techniques:
                                    techniques.append("FakeCAPTCHA Social Engineering")
                                break
                
                # Create detailed URL entry
                safe_json = {}
                try:
                    # Create a sanitized dictionary for JSON serialization
                    for key, value in site.items():
                        if value is not None:
                            if isinstance(value, (str, int, float, bool)):
                                safe_json[key] = value
                            elif isinstance(value, list):
                                safe_json[key] = [v for v in value if v is not None]
                            elif isinstance(value, dict):
                                safe_json[key] = {k: v for k, v in value.items() if v is not None}
                            else:
                                safe_json[key] = str(value)
                except Exception as e:
                    print(f"Error sanitizing JSON for {site_url}: {e}")
                    safe_json = {"error": "Could not serialize site data"}
                
                url_details.append({
                    "url": site_url,
                    "findings_count": url_count,
                    "attack_type": attack_type,
                    "attack_type_class": attack_type_class,
                    "malicious_code": malicious_code,
                    "techniques": techniques,
                    "iocs": iocs,
                    "json_analysis": json.dumps(safe_json, indent=2, default=str),
                    "raw_html": site.get("HTML", "No HTML content available"),
                    "text_summary": f"Analysis for {site_url} found {len(techniques)} techniques and {len(iocs)} indicators of compromise."
                })
        
        # Calculate percentages
        captcha_percent = 30
        command_percent = 50
        other_percent = 20
        
        # Initialize attack counts to prevent UnboundLocalError
        command_attacks = 0
        captcha_attacks = 0
        other_attacks = 0
        
        if total_malicious_urls > 0:
            # Count attack types
            captcha_attacks = 0
            command_attacks = 0
            other_attacks = 0
            
            for site in site_list:
                if site["attack_type"] == "PowerShell Execution":
                    command_attacks += site["patterns"]
                elif site["attack_type"] == "Clipboard Manipulation":
                    captcha_attacks += site["patterns"]
                else:
                    other_attacks += site["patterns"]
            
            # Calculate percentages if we have meaningful data
            if captcha_attacks + command_attacks + other_attacks > 0:
                total = captcha_attacks + command_attacks + other_attacks
                captcha_percent = round((captcha_attacks / total) * 100)
                command_percent = round((command_attacks / total) * 100)
                other_percent = 100 - captcha_percent - command_percent
                # Ensure we always have at least 1% if there are any attacks of this type
                if captcha_attacks > 0 and captcha_percent == 0:
                    captcha_percent = 1
                    other_percent -= 1
                if command_attacks > 0 and command_percent == 0:
                    command_percent = 1
                    other_percent -= 1
        
        report = {
            "date": date,
            "sites_scanned": total_sites,
            "sites_attacked": sites_with_attacks,
            "attacks_detected": total_malicious_urls,
            "total_attacks": total_malicious_urls,
            "new_patterns": 0,
            "powershell_percent": command_percent,
            "captcha_percent": captcha_percent,
            "other_percent": other_percent,
            "powershell_attacks": command_attacks,  # Command execution - using actual count
            "captcha_attacks": captcha_attacks,     # FakeCAPTCHA - using actual count
            "other_attacks": other_attacks,         # Other attack types - using actual count
            "sites": site_list,
            "url_details": url_details,  # Add the detailed URL analysis
            "analysis_html": convert_markdown_to_html(analysis_markdown)
        }
        
        html = template.render(
            report=report,
            active_page='reports',
            base_url=base_url
        )
        
        with open(reports_dir / f"{date}.html", "w", encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ Generated report page for {date}")

def build_reports_list_page(env, base_url):
    template = env.get_template("reports.html")
    report_dates = get_all_report_dates()
    
    reports = []
    for date in report_dates:
        report_data = load_report_data(date)
        if not report_data:
            continue
        
        total_sites = len(report_data.get("Sites", []))
        total_malicious_urls = 0
        sites_with_attacks = 0
        
        for site in report_data.get("Sites", []):
            # Skip None values in the Sites array
            if site is None:
                continue
                
            urls = site.get("Urls", [])
            has_attack = False
            
            if isinstance(urls, list) and urls:
                total_malicious_urls += len(urls)
                has_attack = True
            elif isinstance(urls, str) and urls:
                total_malicious_urls += 1
                has_attack = True
            
            if has_attack:
                sites_with_attacks += 1
        
        try:
            dt = datetime.datetime.strptime(date, "%Y-%m-%d")
            year = dt.strftime("%Y")
            month = dt.strftime("%B")
        except:
            year = date.split("-")[0]
            month = "Unknown"
        
        reports.append({
            "date": date,
            "year": year,
            "month": month,
            "sites_scanned": total_sites,
            "sites_attacked": sites_with_attacks,
            "total_attacks": total_malicious_urls,
            "new_patterns": 0
        })
    
    html = template.render(
        reports=reports,
        active_page='reports',
        base_url=base_url
    )
    
    with open(OUTPUT_DIR / "reports.html", "w", encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Generated reports.html")

def copy_to_docs():
    """Copy the generated site from public/ to docs/ for GitHub Pages"""
    docs_dir = ROOT_DIR / "docs"
    docs_dir.mkdir(exist_ok=True)
    
    # Copy all files from public to docs
    for item in OUTPUT_DIR.glob('**/*'):
        if item.is_file():
            # Create relative path
            rel_path = item.relative_to(OUTPUT_DIR)
            # Create target path in docs
            target_path = docs_dir / rel_path
            # Create parent directories if they don't exist
            target_path.parent.mkdir(parents=True, exist_ok=True)
            # Copy the file
            with open(item, 'rb') as src:
                with open(target_path, 'wb') as dst:
                    dst.write(src.read())
    
    print(f"✅ Copied generated site to docs/ for GitHub Pages")

def build_site():
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True
    )
    
    # Base URL for GitHub Pages (empty string for local development)
    base_url = "/ClickGrab"  # For GitHub Pages: username.github.io/ClickGrab
    
    def dateformat(value, format="%B %d, %Y"):
        try:
            return datetime.datetime.strptime(value, "%Y-%m-%d").strftime(format)
        except ValueError:
            return value
    
    env.filters['dateformat'] = dateformat
    
    copy_static_files()
    
    build_index_page(env, base_url)
    build_report_pages(env, base_url)
    build_reports_list_page(env, base_url)
    
    # Copy to docs/ directory for GitHub Pages
    copy_to_docs()
    
    print("\n🚀 Site generation complete!")
    print(f"Files have been written to {OUTPUT_DIR} and docs/")

if __name__ == "__main__":
    build_site() 