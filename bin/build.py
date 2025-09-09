#!/usr/bin/env python3
"""
ClickGrab HTML Generator
Builds beautiful HTML files from Jinja2 templates using analysis data from the Python version
"""

import os
import sys
import json
import datetime
import shutil
import markdown
import yaml
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Dict, List, Optional, Any

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = SCRIPT_DIR.parent
TEMPLATE_DIR = ROOT_DIR / "templates"
OUTPUT_DIR = ROOT_DIR / "public"
REPORTS_DIR = ROOT_DIR / "nightly_reports"
ANALYSIS_DIR = ROOT_DIR / "analysis"
ASSETS_DIR = ROOT_DIR / "assets"
TECHNIQUES_DIR = ROOT_DIR / "techniques"

OUTPUT_DIR.mkdir(exist_ok=True)

def copy_static_files():
    """Copy CSS and static assets to output directory"""
    assets_output_dir = OUTPUT_DIR / "assets"
    assets_output_dir.mkdir(exist_ok=True)
    
    # Copy CSS
    css_output_dir = assets_output_dir / "css"
    css_output_dir.mkdir(exist_ok=True)
    
    css_files = list((TEMPLATE_DIR / "css").glob("*.css"))
    for css_file in css_files:
        with open(css_file, 'r', encoding='utf-8') as src:
            with open(css_output_dir / css_file.name, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
    
    # Copy images
    images_output_dir = assets_output_dir / "images"
    images_output_dir.mkdir(exist_ok=True)
    
    # Copy logo if exists
    logo_paths = [
        ROOT_DIR / "assets" / "images" / "logo.png",
        ROOT_DIR / "assets" / "images" / "logo.svg",
        ROOT_DIR / "assets" / "logo.png",
    ]
    
    for logo_path in logo_paths:
        if logo_path.exists():
            ext = logo_path.suffix
            with open(logo_path, 'rb') as src:
                with open(images_output_dir / f"logo{ext}", 'wb') as dst:
                    dst.write(src.read())
    
    # Copy JavaScript
    js_output_dir = assets_output_dir / "js"
    js_output_dir.mkdir(exist_ok=True)
    
    # Create main.js with interactive features
    js_content = """
// ClickGrab interactive features
document.addEventListener('DOMContentLoaded', function() {
    // Add fade-in animation to cards
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
            }
        });
    }, { threshold: 0.1 });
    
    document.querySelectorAll('.analysis-card, .report-card, .stat-card').forEach(card => {
        observer.observe(card);
    });
    
    // Add copy functionality to code blocks
    document.querySelectorAll('pre code').forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-btn';
        button.textContent = '📋 Copy';
        button.onclick = () => {
            navigator.clipboard.writeText(block.textContent);
            button.textContent = '✅ Copied!';
            setTimeout(() => button.textContent = '📋 Copy', 2000);
        };
        block.parentElement.style.position = 'relative';
        block.parentElement.appendChild(button);
    });
});
"""
    
    with open(js_output_dir / "main.js", 'w', encoding='utf-8') as f:
        f.write(js_content)

def get_latest_report_date() -> str:
    """Get the date of the latest report"""
    json_files = list(REPORTS_DIR.glob("clickgrab_report_*.json"))
    if not json_files:
        return datetime.datetime.now().strftime("%Y-%m-%d")
    
    latest_file = max(json_files, key=lambda f: f.stat().st_mtime)
    
    # Extract date from filename
    filename = latest_file.stem
    parts = filename.split('_')
    
    if len(parts) >= 3:
        date_part = parts[2]
        if '-' in date_part:  # YYYY-MM-DD format
            return date_part
        elif len(date_part) == 8:  # YYYYMMDD format
            return f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
    
    return datetime.datetime.now().strftime("%Y-%m-%d")

def get_all_report_dates() -> List[str]:
    """Get all available report dates"""
    dates = set()
    
    # Check nightly_reports directory
    for json_file in REPORTS_DIR.glob("clickgrab_report_*.json"):
        filename = json_file.stem
        parts = filename.split('_')
        
        if len(parts) >= 3:
            date_part = parts[2]
            # Handle different date formats
            if '-' in date_part:
                # Already in YYYY-MM-DD format
                dates.add(date_part)
            elif len(date_part) == 8 and date_part.isdigit():
                # YYYYMMDD format
                dates.add(f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}")
        elif len(parts) == 3 and '-' in filename:
            # Handle clickgrab_report_2025-04-22.json format
            date_match = filename.split('report_')[1]
            if len(date_match) == 10 and date_match[4] == '-' and date_match[7] == '-':
                dates.add(date_match)
    
    # Also check old reports directory
    old_reports_dir = ROOT_DIR / "reports"
    if old_reports_dir.exists():
        for json_file in old_reports_dir.glob("clickgrab_report_*.json"):
            filename = json_file.stem
            parts = filename.split('_')
            
            if len(parts) >= 3:
                date_part = parts[2]
                if '-' in date_part:
                    dates.add(date_part)
                elif len(date_part) == 8 and date_part.isdigit():
                    dates.add(f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}")
            elif len(parts) == 3 and '-' in filename:
                # Handle clickgrab_report_2025-04-22.json format
                date_match = filename.split('report_')[1]
                if len(date_match) == 10 and date_match[4] == '-' and date_match[7] == '-':
                    dates.add(date_match)
    
    return sorted(list(dates), reverse=True)

def convert_old_format_to_new(old_data: Dict) -> Dict:
    """Convert old report format to new format with proper fields"""
    # Handle different field names between old and new formats
    if 'Sites' in old_data:
        old_data['sites'] = old_data.pop('Sites')
    
    if 'TotalSites' in old_data:
        old_data['total_sites_analyzed'] = old_data.pop('TotalSites')
    
    if 'ReportTime' in old_data:
        old_data['timestamp'] = old_data.pop('ReportTime')
    
    # Initialize summary if it doesn't exist
    if 'summary' not in old_data:
        old_data['summary'] = {
            'suspicious_sites': 0,
            'powershell_commands': 0,
            'base64_strings': 0,
            'clipboard_manipulation': 0,
            'captcha_elements': 0
        }
    
    # Ensure sites have all required fields
    for site in old_data.get('sites', []):
        # Handle URL/Url field name variations
        if 'Url' in site and 'URL' not in site:
            site['URL'] = site.pop('Url')
        
        # Handle IpAddresses/IPAddresses field name variations
        if 'IpAddresses' in site:
            site['IPAddresses'] = site.pop('IpAddresses')
            
        # Handle PowerShell commands - could be a list or a single string
        ps_commands = site.get('PowerShellCommands', [])
        if isinstance(ps_commands, str):
            site['PowerShellCommands'] = [ps_commands] if ps_commands else []
        elif ps_commands is None:
            site['PowerShellCommands'] = []
            
        # Handle ClipboardCommands - could be a string
        clipboard_cmds = site.get('ClipboardCommands', [])
        if isinstance(clipboard_cmds, str):
            site['ClipboardCommands'] = [clipboard_cmds] if clipboard_cmds else []
        elif clipboard_cmds is None:
            site['ClipboardCommands'] = []
            
        # Handle URLs/Urls field variations
        urls = site.get('URLs', site.get('Urls', []))
        if isinstance(urls, str):
            site['URLs'] = [urls] if urls else []
        elif urls is None:
            site['URLs'] = []
        else:
            site['URLs'] = urls
            
        # Handle Base64Strings - can be dict or None
        base64_strings = site.get('Base64Strings')
        if isinstance(base64_strings, dict):
            site['Base64Strings'] = [base64_strings]
        elif base64_strings is None:
            site['Base64Strings'] = []
            
        # Ensure all list fields are actual lists, not None
        list_fields = ['PowerShellCommands', 'EncodedPowerShell', 'ClipboardManipulation',
                      'ClipboardCommands', 'Base64Strings', 'ObfuscatedJavaScript',
                      'CaptchaElements', 'SuspiciousKeywords', 'JavaScriptRedirects']
        
        for field in list_fields:
            if site.get(field) is None:
                site[field] = []
            elif isinstance(site.get(field), str):
                # Convert single strings to lists
                site[field] = [site[field]] if site[field] else []
                
        # Calculate indicators count
        indicators_count = (
            len(site.get('PowerShellCommands', [])) +
            len(site.get('EncodedPowerShell', [])) +
            len(site.get('ClipboardManipulation', [])) +
            len(site.get('ClipboardCommands', [])) +
            len(site.get('Base64Strings', [])) +
            len(site.get('ObfuscatedJavaScript', [])) +
            len(site.get('CaptchaElements', [])) +
            len(site.get('SuspiciousKeywords', []))
        )
        
        # Add missing fields if not present
        if 'TotalIndicators' not in site:
            site['TotalIndicators'] = indicators_count
        
        if 'Verdict' not in site:
            site['Verdict'] = 'Suspicious' if indicators_count > 0 else 'Clean'
        
        if 'ThreatScore' not in site:
            # Check if there's a ThreatLevel field from old format
            threat_level = site.get('ThreatLevel', '')
            if threat_level == 'High':
                site['ThreatScore'] = 90
            elif threat_level == 'Medium':
                site['ThreatScore'] = 60
            elif threat_level == 'Low':
                site['ThreatScore'] = 30
            elif threat_level == 'None':
                site['ThreatScore'] = 0
            else:
                # Calculate threat score based on indicators
                threat_score = 0
                if len(site.get('PowerShellCommands', [])) > 0:
                    threat_score += 30
                if len(site.get('EncodedPowerShell', [])) > 0:
                    threat_score += 40
                if len(site.get('ClipboardManipulation', [])) > 0:
                    threat_score += 35
                if len(site.get('ObfuscatedJavaScript', [])) > 0:
                    threat_score += 25
                if len(site.get('PowerShellDownloads', [])) > 0:
                    threat_score += 45
                if len(site.get('CaptchaElements', [])) > 0:
                    threat_score += 20
                
                # Cap at 100
                site['ThreatScore'] = min(threat_score, 100)
        
        # Handle PowerShellDownloads - can be dict, list, or None
        ps_downloads = site.get('PowerShellDownloads')
        if isinstance(ps_downloads, dict):
            site['PowerShellDownloads'] = [ps_downloads]
        elif ps_downloads is None:
            site['PowerShellDownloads'] = []
            
        if 'HighRiskCommands' not in site:
            # Extract high risk commands from PowerShell commands
            high_risk_keywords = ['Invoke-', 'Download', 'Execute', 'Bypass', 'Hidden', 'EncodedCommand', 'iex', 'iwr']
            high_risk = []
            
            # Check PowerShell commands
            for cmd in site.get('PowerShellCommands', []):
                if any(keyword.lower() in str(cmd).lower() for keyword in high_risk_keywords):
                    high_risk.append(cmd)
            
            # Check PowerShell downloads
            for dl in site.get('PowerShellDownloads', []):
                if isinstance(dl, dict) and 'Context' in dl:
                    high_risk.append(dl['Context'])
                    
            site['HighRiskCommands'] = high_risk
        
        if 'JavaScriptRedirects' not in site:
            site['JavaScriptRedirects'] = []
    
    # Update summary with new fields if missing
    if 'summary' in old_data:
        summary = old_data['summary']
        sites = old_data.get('sites', [])
        
        # Recalculate summary stats from sites data
        summary['suspicious_sites'] = len([s for s in sites if s.get('Verdict') == 'Suspicious'])
        
        # Count PowerShell commands - handle various formats
        ps_count = 0
        for site in sites:
            ps_cmds = site.get('PowerShellCommands', [])
            if isinstance(ps_cmds, list):
                ps_count += len(ps_cmds)
            elif ps_cmds:
                ps_count += 1
                
            enc_ps = site.get('EncodedPowerShell', [])
            if isinstance(enc_ps, list):
                ps_count += len(enc_ps)
            elif enc_ps:
                ps_count += 1
        summary['powershell_commands'] = ps_count
        
        # Count base64 strings
        b64_count = 0
        for site in sites:
            b64 = site.get('Base64Strings')
            if isinstance(b64, list):
                b64_count += len(b64)
            elif isinstance(b64, dict):
                b64_count += 1
            elif b64:
                b64_count += 1
        summary['base64_strings'] = b64_count
        
        # Count clipboard manipulation
        clip_count = 0
        for site in sites:
            clip_manip = site.get('ClipboardManipulation', [])
            if isinstance(clip_manip, list):
                clip_count += len(clip_manip)
            elif clip_manip:
                clip_count += 1
                
            clip_cmds = site.get('ClipboardCommands', [])
            if isinstance(clip_cmds, list):
                clip_count += len(clip_cmds)
            elif clip_cmds:
                clip_count += 1
        summary['clipboard_manipulation'] = clip_count
        
        # Count captcha elements
        captcha_count = 0
        for site in sites:
            captcha = site.get('CaptchaElements', [])
            if isinstance(captcha, list):
                captcha_count += len(captcha)
            elif captcha:
                captcha_count += 1
        summary['captcha_elements'] = captcha_count
        
        if 'high_risk_commands' not in summary:
            high_risk_count = sum(len(site.get('HighRiskCommands', [])) for site in sites)
            summary['high_risk_commands'] = high_risk_count
        
        if 'obfuscated_js' not in summary:
            summary['obfuscated_js'] = sum(len(site.get('ObfuscatedJavaScript', [])) for site in sites)
        
        if 'obfuscated_javascript' not in summary:
            summary['obfuscated_javascript'] = summary.get('obfuscated_js', 0)
        
        if 'total_indicators' not in summary:
            summary['total_indicators'] = sum(site.get('TotalIndicators', 0) for site in sites)
        
        if 'javascript_redirects' not in summary:
            summary['javascript_redirects'] = sum(len(site.get('JavaScriptRedirects', [])) for site in sites)
    
    return old_data

def load_report_data(date: str) -> Optional[Dict]:
    """Load report data from both new Python and old PowerShell JSON formats"""
    patterns = [
        f"clickgrab_report_{date}.json",
        f"clickgrab_report_{date.replace('-', '')}.json",
        f"clickgrab_report_{date.replace('-', '')}_*.json"
    ]
    
    # First check nightly_reports directory
    for pattern in patterns:
        files = list(REPORTS_DIR.glob(pattern))
        if files:
            report_file = max(files, key=lambda f: f.stat().st_mtime)
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Convert old format to new if necessary
                    return convert_old_format_to_new(data)
            except Exception as e:
                print(f"Error loading {report_file}: {e}")
    
    # Check reports directory for older data
    old_reports_dir = ROOT_DIR / "reports"
    if old_reports_dir.exists():
        date_no_dash = date.replace('-', '')
        
        for pattern in [f"clickgrab_report_{date_no_dash}_*.json", f"clickgrab_report_{date_no_dash}.json", f"*{date}*.json"]:
            files = list(old_reports_dir.glob(pattern))
            if files:
                report_file = max(files, key=lambda f: f.stat().st_mtime)
                try:
                    with open(report_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # Convert old format to new
                        return convert_old_format_to_new(data)
                except Exception as e:
                    print(f"Error loading {report_file}: {e}")
    
    return None

def calculate_summary_stats(sites: List[Dict]) -> Dict[str, int]:
    """Calculate summary statistics from site data"""
    stats = {
        'total_sites': len(sites),
        'suspicious_sites': 0,
        'powershell_commands': 0,
        'clipboard_manipulation': 0,
        'high_risk_commands': 0,
        'obfuscated_js': 0,
        'captcha_elements': 0,
        'total_indicators': 0
    }
    
    for site in sites:
        if site.get('Verdict') == 'Suspicious':
            stats['suspicious_sites'] += 1
        
        stats['powershell_commands'] += len(site.get('PowerShellCommands', [])) + len(site.get('EncodedPowerShell', []))
        stats['clipboard_manipulation'] += len(site.get('ClipboardManipulation', [])) + len(site.get('ClipboardCommands', []))
        stats['high_risk_commands'] += len(site.get('HighRiskCommands', []))
        stats['obfuscated_js'] += len(site.get('ObfuscatedJavaScript', []))
        stats['captcha_elements'] += len(site.get('CaptchaElements', []))
        stats['total_indicators'] += site.get('TotalIndicators', 0)
    
    return stats

def process_site_data(site: Dict) -> Dict:
    """Process a single site's data for template rendering"""
    # Calculate threat indicators
    indicators = {
        'powershell': len(site.get('PowerShellCommands', [])) + len(site.get('EncodedPowerShell', [])),
        'clipboard': len(site.get('ClipboardManipulation', [])) + len(site.get('ClipboardCommands', [])),
        'downloads': len(site.get('PowerShellDownloads', [])),
        'obfuscation': len(site.get('ObfuscatedJavaScript', [])),
        'captcha': len(site.get('CaptchaElements', [])),
        'base64': len(site.get('Base64Strings', [])),
        'redirects': len(site.get('JavaScriptRedirects', [])),
        'high_risk_commands': len(site.get('HighRiskCommands', []))
    }
    
    # Determine primary attack type
    attack_types = []
    if indicators['powershell'] > 0:
        attack_types.append('PowerShell')
    if indicators['clipboard'] > 0:
        attack_types.append('Clipboard Hijacking')
    if indicators['downloads'] > 0:
        attack_types.append('Remote Payload')
    if indicators['captcha'] > 0:
        attack_types.append('Fake CAPTCHA')
    
    return {
        'url': site.get('URL', ''),
        'verdict': site.get('Verdict', 'Unknown'),
        'threat_score': site.get('ThreatScore', 0),
        'total_indicators': site.get('TotalIndicators', 0),
        'indicators': indicators,
        'attack_types': attack_types,
        'primary_attack': attack_types[0] if attack_types else 'Unknown',
        'is_malicious': site.get('Verdict') == 'Suspicious',
        'details': site  # Include full details for detailed view
    }

def build_index_page(env: Environment, base_url: str):
    """Build the stunning index page"""
    template = env.get_template("index.html")
    latest_date = get_latest_report_date()
    report_data = load_report_data(latest_date)
    
    stats = {
        'total_sites': 0,
        'malicious_sites': 0,
        'total_indicators': 0,
        'powershell_attacks': 0,
        'clipboard_attacks': 0,
        'high_risk_commands': 0,
        'latest_date': latest_date
    }
    
    if report_data:
        stats['total_sites'] = report_data.get('total_sites_analyzed', 0)
        
        summary = report_data.get('summary', {})
        stats['malicious_sites'] = summary.get('suspicious_sites', 0)
        stats['powershell_attacks'] = summary.get('powershell_commands', 0)
        stats['clipboard_attacks'] = summary.get('clipboard_manipulation', 0)
        stats['high_risk_commands'] = summary.get('high_risk_commands', 0)
        
        # Calculate total indicators
        for site in report_data.get('sites', []):
            stats['total_indicators'] += site.get('TotalIndicators', 0)
    
    # Get recent reports
    recent_dates = get_all_report_dates()[:5]
    recent_reports = []
    
    for date in recent_dates:
        report_summary = load_report_data(date)
        if report_summary:
            summary = report_summary.get('summary', {})
            recent_reports.append({
                'date': date,
                'malicious_count': summary.get('suspicious_sites', 0),
                'total_sites': report_summary.get('total_sites_analyzed', 0)
            })
    
    html = template.render(
        stats=stats,
        recent_reports=recent_reports,
        base_url=base_url,
        active_page='home'
    )
    
    with open(OUTPUT_DIR / "index.html", 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✨ Generated stunning index.html")

def build_report_pages(env: Environment, base_url: str):
    """Build individual report pages with detailed analysis"""
    template = env.get_template("report.html")
    report_dates = get_all_report_dates()
    
    reports_dir = OUTPUT_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    for date in report_dates:
        report_data = load_report_data(date)
        if not report_data:
            continue
        
        # Ensure report_data has sites field for template compatibility
        if 'sites' not in report_data and 'SiteReports' in report_data:
            report_data['sites'] = report_data['SiteReports']
        
        # Process sites for rendering
        processed_sites = []
        for site in report_data.get('sites', []):
            if site.get('Verdict') == 'Suspicious':
                processed_sites.append(process_site_data(site))
        
        # Sort by threat score
        processed_sites.sort(key=lambda x: x['threat_score'], reverse=True)
        
        # Calculate average threat score if not present
        if 'summary' in report_data and 'average_threat_score' not in report_data['summary']:
            if processed_sites:
                avg_score = sum(s['threat_score'] for s in processed_sites) / len(processed_sites)
                report_data['summary']['average_threat_score'] = round(avg_score)
            else:
                report_data['summary']['average_threat_score'] = 0
        
        # Load analysis markdown if available
        analysis_file = ANALYSIS_DIR / f"report_{date}.md"
        analysis_html = ""
        if analysis_file.exists():
            with open(analysis_file, 'r', encoding='utf-8') as f:
                analysis_html = markdown.markdown(
                    f.read(), 
                    extensions=['tables', 'fenced_code', 'codehilite']
                )
        
        html = template.render(
            date=date,
            report_data=report_data,
            summary=report_data.get('summary', {}),
            sites=processed_sites[:50],  # Limit to top 50 sites
            analysis_html=analysis_html,
            base_url=base_url,
            active_page='reports'
        )
        
        with open(reports_dir / f"{date}.html", 'w', encoding='utf-8') as f:
            f.write(html)
    
    # Create latest report redirect
    if report_dates:
        with open(OUTPUT_DIR / "latest_report.html", 'w', encoding='utf-8') as f:
            f.write(f'<meta http-equiv="refresh" content="0;url={base_url}/reports/{report_dates[0]}.html">')
    
    print(f"✨ Generated {len(report_dates)} beautiful report pages")

def build_reports_list_page(env: Environment, base_url: str):
    """Build the reports archive page"""
    template = env.get_template("reports.html")
    report_dates = get_all_report_dates()
    
    reports_by_month = {}
    
    for date in report_dates:
        report_data = load_report_data(date)
        if not report_data:
            continue
        
        dt = datetime.datetime.strptime(date, "%Y-%m-%d")
        month_key = dt.strftime("%Y-%m")
        month_name = dt.strftime("%B %Y")
        
        if month_key not in reports_by_month:
            reports_by_month[month_key] = {
                'name': month_name,
                'reports': []
            }
        
        summary = report_data.get('summary', {})
        threat_score_avg = 0
        if report_data.get('sites'):
            scores = [s.get('ThreatScore', 0) for s in report_data['sites'] if s.get('Verdict') == 'Suspicious']
            threat_score_avg = sum(scores) / len(scores) if scores else 0
        
        reports_by_month[month_key]['reports'].append({
            'date': date,
            'total_sites': report_data.get('total_sites_analyzed', 0),
            'malicious_sites': summary.get('suspicious_sites', 0),
            'powershell_count': summary.get('powershell_commands', 0),
            'high_risk_count': summary.get('high_risk_commands', 0),
            'avg_threat_score': round(threat_score_avg)
        })
    
    # Sort months and reports within months
    sorted_months = sorted(reports_by_month.items(), reverse=True)
    
    html = template.render(
        months=sorted_months,
        total_reports=len(report_dates),
        base_url=base_url,
        active_page='reports'
    )
    
    with open(OUTPUT_DIR / "reports.html", 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✨ Generated reports archive page")

def build_analysis_page(env: Environment, base_url: str):
    """Build the threat intelligence analysis page"""
    template = env.get_template("analysis.html")
    
    # Get all blog data
    blog_files = list(ANALYSIS_DIR.glob("blog_data_*.json"))
    analysis_posts = []
    
    for blog_file in blog_files:
        try:
            with open(blog_file, 'r', encoding='utf-8') as f:
                blog_data = json.load(f)
                analysis_posts.append(blog_data)
        except Exception as e:
            print(f"Error loading blog data from {blog_file}: {e}")
            continue
    
    # Sort by date
    analysis_posts.sort(key=lambda x: x.get('date', ''), reverse=True)
    
    html = template.render(
        analysis_posts=analysis_posts[:10],  # Show latest 10
        base_url=base_url,
        active_page='analysis'
    )
    
    with open(OUTPUT_DIR / "analysis.html", 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✨ Generated analysis page with {len(analysis_posts)} posts")

def build_blog_post_pages(env: Environment, base_url: str):
    """Build individual blog post pages"""
    template = env.get_template("blog_post.html")
    
    analysis_dir = OUTPUT_DIR / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    
    blog_files = list(ANALYSIS_DIR.glob("blog_data_*.json"))
    
    for blog_file in blog_files:
        try:
            with open(blog_file, 'r', encoding='utf-8') as f:
                blog_data = json.load(f)
            
            date_str = blog_data.get('date')
            if not date_str:
                continue
            
            # Load markdown content
            md_file = ANALYSIS_DIR / f"report_{date_str}.md"
            if md_file.exists():
                with open(md_file, 'r', encoding='utf-8') as f:
                    content_html = markdown.markdown(
                        f.read(), 
                        extensions=['tables', 'fenced_code', 'codehilite', 'toc']
                    )
                
                # Enhance with stats visualization
                if blog_data.get('stats'):
                    stats_html = generate_stats_visualization(blog_data['stats'])
                    content_html = stats_html + content_html
                
                # Add content to blog_data so template can access it as post.content
                blog_data['content'] = content_html
                
                html = template.render(
                    post=blog_data,
                    base_url=base_url,
                    active_page='analysis'
                )
                
                slug = blog_data.get('slug', f'analysis-{date_str}')
                with open(analysis_dir / f"{slug}.html", 'w', encoding='utf-8') as f:
                    f.write(html)
                    
        except Exception as e:
            print(f"Error building blog post from {blog_file}: {e}")
    
    print(f"✨ Generated {len(blog_files)} blog post pages")

def generate_stats_visualization(stats: Dict) -> str:
    """Generate beautiful stats visualization HTML"""
    return f"""
    <div class="analysis-stats-hero">
        <div class="stats-grid">
            <div class="stat-card gradient-1">
                <div class="stat-icon">🔍</div>
                <div class="stat-value">{stats.get('sites_analyzed', 0)}</div>
                <div class="stat-label">Sites Analyzed</div>
            </div>
            <div class="stat-card gradient-2">
                <div class="stat-icon">⚠️</div>
                <div class="stat-value">{stats.get('malicious_rate', 0)}%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
            <div class="stat-card gradient-3">
                <div class="stat-icon">🛡️</div>
                <div class="stat-value">{stats.get('powershell_downloads', 0)}</div>
                <div class="stat-label">PowerShell Attacks</div>
            </div>
            <div class="stat-card gradient-4">
                <div class="stat-icon">📋</div>
                <div class="stat-value">{stats.get('clipboard_manipulations', 0)}</div>
                <div class="stat-label">Clipboard Hijacks</div>
            </div>
        </div>
    </div>
    """

def load_techniques() -> List[Dict[str, Any]]:
    """Load all technique YAML files"""
    techniques = []
    
    if not TECHNIQUES_DIR.exists():
        print("⚠️ Techniques directory not found")
        return techniques
    
    for yaml_file in TECHNIQUES_DIR.glob("*.yml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                technique_data = yaml.safe_load(f)
                
            # Process the technique data
            technique = {
                'id': yaml_file.stem,
                'name': technique_data.get('name', yaml_file.stem),
                'platform': technique_data.get('platform', ''),
                'presentation': technique_data.get('presentation', ''),
                'info': technique_data.get('info', ''),
                'added_at': technique_data.get('added_at', ''),
                'lures': technique_data.get('lures', []),
                'lure_count': len(technique_data.get('lures', []))
            }
            
            # Collect all capabilities from all lures
            all_capabilities = set()
            for lure in technique['lures']:
                if 'capabilities' in lure:
                    all_capabilities.update(lure['capabilities'])
            technique['capabilities'] = sorted(list(all_capabilities))
            
            techniques.append(technique)
            
        except Exception as e:
            print(f"Error loading technique {yaml_file}: {e}")
            continue
    
    return techniques

def build_techniques_page(env: Environment, base_url: str):
    """Build the techniques overview page"""
    template = env.get_template("techniques.html")
    techniques = load_techniques()
    
    html = template.render(
        techniques=techniques,
        base_url=base_url,
        active_page='techniques'
    )
    
    with open(OUTPUT_DIR / "techniques.html", 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"✨ Generated techniques page with {len(techniques)} techniques")

def build_technique_detail_pages(env: Environment, base_url: str):
    """Build individual technique detail pages"""
    template = env.get_template("technique_detail.html")
    techniques = load_techniques()
    
    techniques_output_dir = OUTPUT_DIR / "techniques"
    techniques_output_dir.mkdir(exist_ok=True)
    
    for technique in techniques:
        html = template.render(
            technique=technique,
            base_url=base_url,
            active_page='techniques'
        )
        
        with open(techniques_output_dir / f"{technique['id']}.html", 'w', encoding='utf-8') as f:
            f.write(html)
    
    print(f"✨ Generated {len(techniques)} technique detail pages")

def build_mitigations_page(env: Environment, base_url: str):
    """Build the mitigations page"""
    template = env.get_template("mitigations.html")
    html = template.render(
        base_url=base_url,
        active_page='mitigations'
    )
    
    with open(OUTPUT_DIR / "mitigations.html", 'w', encoding='utf-8') as f:
        f.write(html)
    
    print("✨ Generated mitigations page")

def build_technique_examples(env: Environment, base_url: str):
    """Build interactive example pages for each technique"""
    template = env.get_template("technique_example_simple.html")
    techniques = load_techniques()
    
    examples_output_dir = OUTPUT_DIR / "examples"
    examples_output_dir.mkdir(exist_ok=True)
    
    example_count = 0
    
    for technique in techniques:
        for lure in technique.get('lures', []):
            # Generate example data
            example_title = "Are you a human?"
            example_description = lure.get('preamble', 'Click the button below to confirm you are human.')
            
            # Extract command - use the technique name directly
            command_to_copy = technique['name']
            
            # Create example filename
            lure_slug = lure.get('nickname', 'example').lower().replace(' ', '-').replace('"', '').replace("'", '')
            example_filename = f"{technique['id']}-{lure_slug}.html"
            
            html = template.render(
                technique_id=technique['id'],
                technique_name=technique['name'],
                example_title=example_title,
                example_description=example_description,
                command_to_copy=command_to_copy,
                base_url=base_url
            )
            
            with open(examples_output_dir / example_filename, 'w', encoding='utf-8') as f:
                f.write(html)
            
            example_count += 1
    
    print(f"✨ Generated {example_count} simple ClickFix examples")

def copy_to_docs():
    """Copy generated site to docs/ for GitHub Pages"""
    docs_dir = ROOT_DIR / "docs"
    
    # Clean docs directory first
    if docs_dir.exists():
        shutil.rmtree(docs_dir)
    docs_dir.mkdir()
    
    # Copy all files
    for item in OUTPUT_DIR.rglob('*'):
        if item.is_file():
            rel_path = item.relative_to(OUTPUT_DIR)
            target_path = docs_dir / rel_path
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target_path)
    
    print(f"✅ Copied site to docs/ for GitHub Pages")

def build_site():
    """Main build function"""
    print("🚀 Building ClickGrab site from Python analysis data...")
    
    # Setup Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Add custom filters
    env.filters['dateformat'] = lambda x: datetime.datetime.strptime(x, "%Y-%m-%d").strftime("%B %d, %Y")
    env.filters['percentage'] = lambda x: f"{round(x)}%"
    env.filters['markdown'] = lambda x: markdown.markdown(x, extensions=['fenced_code', 'codehilite', 'tables'])
    
    # Base URL for GitHub Pages
    base_url = "/ClickGrab"
    
    # Copy static assets
    copy_static_files()
    
    # Build all pages
    build_index_page(env, base_url)
    build_report_pages(env, base_url)
    build_reports_list_page(env, base_url)
    build_analysis_page(env, base_url)
    build_blog_post_pages(env, base_url)
    build_techniques_page(env, base_url)
    build_technique_detail_pages(env, base_url)
    build_technique_examples(env, base_url)
    build_mitigations_page(env, base_url)
    
    # Copy to docs
    copy_to_docs()
    
    print("\n✨ Site generation complete! Check out your amazing new site!")

if __name__ == "__main__":
    build_site() 