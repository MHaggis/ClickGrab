#!/usr/bin/env python3
"""
ClickGrab HTML Generator - FAST version
Builds HTML files from Jinja2 templates. Optimized for CI speed.
"""

import os
import sys
import json
import datetime
import shutil
import markdown
import yaml
import re
from html import escape
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from typing import Dict, List, Optional, Any
from collections import Counter

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

def log(msg):
    """Flush output immediately for CI visibility"""
    print(msg, flush=True)
    sys.stdout.flush()

def copy_static_files():
    """Copy CSS and static assets to output directory"""
    assets_output_dir = OUTPUT_DIR / "assets"
    assets_output_dir.mkdir(exist_ok=True)
    
    # Copy CSS
    css_output_dir = assets_output_dir / "css"
    css_output_dir.mkdir(exist_ok=True)
    
    css_dir = TEMPLATE_DIR / "css"
    if css_dir.exists():
        for css_file in css_dir.glob("*.css"):
            shutil.copy2(css_file, css_output_dir / css_file.name)
    
    # Copy images
    images_output_dir = assets_output_dir / "images"
    images_output_dir.mkdir(exist_ok=True)
    
    # Copy logo if exists
    for logo_path in [
        ROOT_DIR / "assets" / "images" / "logo.png",
        ROOT_DIR / "assets" / "images" / "logo.svg",
        ROOT_DIR / "assets" / "logo.png",
    ]:
        if logo_path.exists():
            shutil.copy2(logo_path, images_output_dir / f"logo{logo_path.suffix}")
            break
    
    # Copy JavaScript
    js_output_dir = assets_output_dir / "js"
    js_output_dir.mkdir(exist_ok=True)
    
    js_content = """
// ClickGrab interactive features
document.addEventListener('DOMContentLoaded', function() {
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
    (js_output_dir / "main.js").write_text(js_content, encoding='utf-8')

def get_recent_report_files(limit: int = 10) -> List[Path]:
    """Get the N most recent report JSON files, deduplicated by date"""
    if not REPORTS_DIR.exists():
        return []
    
    json_files = list(REPORTS_DIR.glob("clickgrab_report_*.json"))
    # Sort by mtime descending
    json_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    
    # Dedupe by date (keep most recent file for each date)
    seen_dates = set()
    result = []
    for f in json_files:
        date = extract_date_from_filename(f.name)
        if date and date not in seen_dates:
            seen_dates.add(date)
            result.append(f)
            if len(result) >= limit:
                break
    
    return result

def extract_date_from_filename(filename: str) -> Optional[str]:
    """Extract date from report filename"""
    # Handle: clickgrab_report_2025-05-29.json or clickgrab_report_20250529.json
    parts = filename.replace('.json', '').split('_')
    if len(parts) >= 3:
        date_part = parts[2]
        if '-' in date_part and len(date_part) == 10:
            return date_part
        elif len(date_part) == 8 and date_part.isdigit():
            return f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]}"
    return None

def load_report_json(file_path: Path) -> Optional[Dict]:
    """Load a report JSON file with minimal processing"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Quick normalization
        if 'Sites' in data and 'sites' not in data:
            data['sites'] = data.pop('Sites')
        if 'TotalSites' in data:
            data['total_sites_analyzed'] = data.pop('TotalSites')
        
        # Ensure summary exists
        if 'summary' not in data:
            sites = data.get('sites', [])
            data['summary'] = {
                'suspicious_sites': len([s for s in sites if s.get('Verdict') == 'Suspicious']),
                'powershell_commands': sum(len(s.get('PowerShellCommands', [])) for s in sites),
                'clipboard_manipulation': sum(len(s.get('ClipboardManipulation', [])) for s in sites),
                'high_risk_commands': 0,
                'total_indicators': sum(s.get('TotalIndicators', 0) for s in sites)
            }
        
        return data
    except Exception as e:
        log(f"⚠️  Error loading {file_path.name}: {e}")
        return None

def build_index_page(env: Environment, base_url: str):
    """Build the index page with stats from the latest report"""
    template = env.get_template("index.html")
    
    recent_files = get_recent_report_files(5)
    
    stats = {
        'total_sites': 0,
        'malicious_sites': 0,
        'total_indicators': 0,
        'powershell_attacks': 0,
        'clipboard_attacks': 0,
        'high_risk_commands': 0,
        'latest_date': datetime.datetime.now().strftime("%Y-%m-%d")
    }
    
    recent_reports = []
    
    for i, report_file in enumerate(recent_files):
        date = extract_date_from_filename(report_file.name)
        if not date:
            continue
        
        data = load_report_json(report_file)
        if not data:
            continue
        
        summary = data.get('summary', {})
        
        # Use first report for main stats
        if i == 0:
            stats['latest_date'] = date
            stats['total_sites'] = data.get('total_sites_analyzed', 0)
            stats['malicious_sites'] = summary.get('suspicious_sites', 0)
            stats['powershell_attacks'] = summary.get('powershell_commands', 0)
            stats['clipboard_attacks'] = summary.get('clipboard_manipulation', 0)
            stats['high_risk_commands'] = summary.get('high_risk_commands', 0)
            stats['total_indicators'] = summary.get('total_indicators', 0)
        
        recent_reports.append({
            'date': date,
            'malicious_count': summary.get('suspicious_sites', 0),
            'total_sites': data.get('total_sites_analyzed', 0)
        })
    
    html = template.render(
        stats=stats,
        recent_reports=recent_reports,
        base_url=base_url,
        active_page='home'
    )
    
    (OUTPUT_DIR / "index.html").write_text(html, encoding='utf-8')
    log("✅ index.html")

def process_site_for_template(site: Dict) -> Dict:
    """Process a site dict for the full report template"""
    url = site.get('URL', site.get('Url', ''))
    
    # Calculate indicators
    indicators = {
        'powershell': len(site.get('PowerShellCommands', [])) + len(site.get('EncodedPowerShell', [])),
        'clipboard': len(site.get('ClipboardManipulation', [])) + len(site.get('ClipboardCommands', [])),
        'downloads': len(site.get('PowerShellDownloads', [])),
        'obfuscation': len(site.get('ObfuscatedJavaScript', [])),
        'captcha': len(site.get('CaptchaElements', [])),
        'base64': len(site.get('Base64Strings', [])),
        'redirects': len(site.get('JavaScriptRedirects', [])),
        'redirect_chains': len(site.get('JavaScriptRedirectChains', [])),
        'redirect_follows': len(site.get('RedirectFollows', [])),
        'suspicious_keywords': len(site.get('SuspiciousKeywords', [])),
        'high_risk': len(site.get('HighRiskCommands', []))
    }
    
    # Determine attack types
    attack_types = []
    if indicators['powershell'] > 0:
        attack_types.append('PowerShell')
    if indicators['clipboard'] > 0:
        attack_types.append('Clipboard Hijack')
    if indicators['downloads'] > 0:
        attack_types.append('Remote Payload')
    if indicators['captcha'] > 0:
        attack_types.append('Fake CAPTCHA')
    if indicators['obfuscation'] > 0:
        attack_types.append('Obfuscated JS')
    if indicators['redirect_chains'] > 0 or indicators['redirect_follows'] > 0:
        attack_types.append('Redirect Chain')
    
    total_indicators = site.get('TotalIndicators', sum(indicators.values()))
    
    return {
        'url': url,
        'verdict': site.get('Verdict', 'Unknown'),
        'threat_score': site.get('ThreatScore', 0),
        'total_indicators': total_indicators,
        'indicators': indicators,
        'attack_types': attack_types,
        'details': site  # Full site data for detailed tabs
    }

def build_report_pages(env: Environment, base_url: str):
    """Build FULL detailed report pages for the 5 most recent reports"""
    template = env.get_template("report.html")
    
    reports_dir = OUTPUT_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    recent_files = get_recent_report_files(5)
    
    for report_file in recent_files:
        date = extract_date_from_filename(report_file.name)
        if not date:
            continue
        
        data = load_report_json(report_file)
        if not data:
            continue
        
        # Process ALL suspicious sites (up to 50 for performance)
        sites = []
        for site in data.get('sites', []):
            if site.get('Verdict') == 'Suspicious':
                sites.append(process_site_for_template(site))
        
        # Sort by threat score
        sites.sort(key=lambda x: x['threat_score'], reverse=True)
        sites = sites[:50]  # Cap at 50 for page performance
        
        # Build aggregates for the chart
        summary = data.get('summary', {})
        aggregates = {
            'PowerShell Commands': summary.get('powershell_commands', 0),
            'Clipboard Hijacks': summary.get('clipboard_manipulation', 0),
            'Base64 Encoded': summary.get('base64_strings', 0),
            'CAPTCHA Elements': summary.get('captcha_elements', 0),
            'High Risk Commands': summary.get('high_risk_commands', 0),
            'JS Redirects': summary.get('javascript_redirects', 0),
        }
        
        # Get top keywords from all sites
        all_keywords = []
        for site in data.get('sites', [])[:20]:
            all_keywords.extend(site.get('SuspiciousKeywords', []))
        
        # Count keyword frequency
        keyword_counts = Counter(all_keywords)
        top_keywords = keyword_counts.most_common(15)
        
        html = template.render(
            date=date,
            report_data=data,
            summary=summary,
            sites=sites,
            aggregates=aggregates,
            top_keywords=top_keywords,
            analysis_html="",
            base_url=base_url,
            active_page='reports'
        )
        
        (reports_dir / f"{date}.html").write_text(html, encoding='utf-8')
        log(f"   ✅ reports/{date}.html ({len(sites)} threats)")
    
    # Create latest redirect
    if recent_files:
        latest_date = extract_date_from_filename(recent_files[0].name)
        if latest_date:
            redirect_html = f'<meta http-equiv="refresh" content="0;url={base_url}/reports/{latest_date}.html">'
            (OUTPUT_DIR / "latest_report.html").write_text(redirect_html, encoding='utf-8')

def build_reports_list_page(env: Environment, base_url: str):
    """Build the reports archive page"""
    template = env.get_template("reports.html")
    
    recent_files = get_recent_report_files(30)
    
    reports_by_month = {}
    
    for report_file in recent_files:
        date = extract_date_from_filename(report_file.name)
        if not date:
            continue
        
        data = load_report_json(report_file)
        if not data:
            continue
        
        try:
            dt = datetime.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            continue
        
        month_key = dt.strftime("%Y-%m")
        month_name = dt.strftime("%B %Y")
        
        if month_key not in reports_by_month:
            reports_by_month[month_key] = {'name': month_name, 'reports': []}
        
        summary = data.get('summary', {})
        reports_by_month[month_key]['reports'].append({
            'date': date,
            'total_sites': data.get('total_sites_analyzed', 0),
            'malicious_sites': summary.get('suspicious_sites', 0),
            'powershell_count': summary.get('powershell_commands', 0),
            'high_risk_count': summary.get('high_risk_commands', 0),
            'avg_threat_score': 0
        })
    
    sorted_months = sorted(reports_by_month.items(), reverse=True)
    
    html = template.render(
        months=sorted_months,
        total_reports=len(recent_files),
        base_url=base_url,
        active_page='reports'
    )
    
    (OUTPUT_DIR / "reports.html").write_text(html, encoding='utf-8')
    log("✅ reports.html")

def build_analysis_page(env: Environment, base_url: str):
    """Build the threat intelligence analysis page"""
    template = env.get_template("analysis.html")
    
    analysis_posts = []
    
    # Get recent blog data files
    if ANALYSIS_DIR.exists():
        blog_files = sorted(ANALYSIS_DIR.glob("blog_data_*.json"), reverse=True)[:10]
        
        for blog_file in blog_files:
            try:
                with open(blog_file, 'r', encoding='utf-8') as f:
                    analysis_posts.append(json.load(f))
            except Exception:
                continue
    
    html = template.render(
        analysis_posts=analysis_posts,
        base_url=base_url,
        active_page='analysis'
    )
    
    (OUTPUT_DIR / "analysis.html").write_text(html, encoding='utf-8')
    log("✅ analysis.html")

def build_blog_post_pages(env: Environment, base_url: str):
    """Build the most recent blog post page"""
    template = env.get_template("blog_post.html")
    
    analysis_dir = OUTPUT_DIR / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    
    if not ANALYSIS_DIR.exists():
        return
    
    blog_files = sorted(ANALYSIS_DIR.glob("blog_data_*.json"), reverse=True)[:1]
    
    for blog_file in blog_files:
        try:
            with open(blog_file, 'r', encoding='utf-8') as f:
                blog_data = json.load(f)
            
            date_str = blog_data.get('date')
            if not date_str:
                continue
            
            md_file = ANALYSIS_DIR / f"report_{date_str}.md"
            if md_file.exists():
                content = md_file.read_text(encoding='utf-8')
                
                # Truncate very large files to avoid slow markdown parsing
                # Files with embedded HTML from scraped pages can be huge
                MAX_CHARS = 50000
                if len(content) > MAX_CHARS:
                    # Find a good cutoff point (end of a section)
                    cutoff = content.rfind('\n## ', 0, MAX_CHARS)
                    if cutoff == -1:
                        cutoff = MAX_CHARS
                    content = content[:cutoff] + "\n\n---\n*Report truncated for web display. Full data available in JSON.*"
                    log(f"   ⚠️  Truncated large markdown file")
                
                content_html = markdown.markdown(
                    content,
                    extensions=['tables', 'fenced_code']
                )
                blog_data['content'] = content_html
                
                html = template.render(
                    post=blog_data,
                    base_url=base_url,
                    active_page='analysis'
                )
                
                slug = blog_data.get('slug', f'analysis-{date_str}')
                (analysis_dir / f"{slug}.html").write_text(html, encoding='utf-8')
                log(f"   ✅ analysis/{slug}.html")
                
        except Exception as e:
            log(f"⚠️  Error building blog post: {e}")

def load_techniques() -> List[Dict[str, Any]]:
    """Load all technique YAML files"""
    techniques = []
    
    if not TECHNIQUES_DIR.exists():
        return techniques
    
    for yaml_file in TECHNIQUES_DIR.glob("*.yml"):
        try:
            with open(yaml_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            technique = {
                'id': yaml_file.stem,
                'name': data.get('name', yaml_file.stem),
                'platform': data.get('platform', ''),
                'presentation': data.get('presentation', ''),
                'info': data.get('info', ''),
                'added_at': data.get('added_at', ''),
                'lures': data.get('lures', []),
                'lure_count': len(data.get('lures', []))
            }
            
            all_capabilities = set()
            for lure in technique['lures']:
                if 'capabilities' in lure:
                    all_capabilities.update(lure['capabilities'])
            technique['capabilities'] = sorted(list(all_capabilities))
            
            techniques.append(technique)
            
        except Exception as e:
            log(f"⚠️  Error loading technique {yaml_file}: {e}")
    
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
    
    (OUTPUT_DIR / "techniques.html").write_text(html, encoding='utf-8')
    log(f"✅ techniques.html ({len(techniques)} techniques)")

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
        
        (techniques_output_dir / f"{technique['id']}.html").write_text(html, encoding='utf-8')
    
    log(f"✅ {len(techniques)} technique detail pages")

def build_mitigations_page(env: Environment, base_url: str):
    """Build the mitigations page"""
    template = env.get_template("mitigations.html")
    mitigations_file = ROOT_DIR / "mitigations" / "mitigations.yml"
    mitigations_data = {}

    if mitigations_file.exists():
        with open(mitigations_file, 'r', encoding='utf-8') as f:
            mitigations_data = yaml.safe_load(f)

    html = template.render(
        mitigations=mitigations_data,
        base_url=base_url,
        active_page='mitigations'
    )

    (OUTPUT_DIR / "mitigations.html").write_text(html, encoding='utf-8')
    log("✅ mitigations.html")

def build_technique_examples(env: Environment, base_url: str):
    """Build interactive example pages for techniques (limited for speed)"""
    template = env.get_template("technique_example.html")
    techniques = load_techniques()
    
    examples_output_dir = OUTPUT_DIR / "examples"
    examples_output_dir.mkdir(exist_ok=True)
    
    example_count = 0
    
    # Only build examples for first 10 techniques to save time
    for technique in techniques[:10]:
        for lure in technique.get('lures', []):
            example_title = lure.get('nickname', 'ClickFix Example')
            example_description = lure.get('preamble', 'Follow these steps.')
            steps = lure.get('steps', [])
            
            lure_slug = lure.get('nickname', 'example').lower()
            lure_slug = re.sub(r'[^a-z0-9-]', '-', lure_slug)
            lure_slug = re.sub(r'-+', '-', lure_slug).strip('-')
            example_filename = f"{technique['id']}-{lure_slug}.html"
            
            html = template.render(
                technique_id=technique['id'],
                technique_name=technique['name'],
                example_title=example_title,
                example_description=example_description,
                steps=steps,
                action_button_text="Next Step" if steps else "Copy Command",
                command_to_copy=technique['name'],
                base_url=base_url
            )
            
            (examples_output_dir / example_filename).write_text(html, encoding='utf-8')
            example_count += 1
    
    log(f"✅ {example_count} example pages")

def copy_to_docs():
    """Copy generated site to docs/ for GitHub Pages"""
    docs_dir = ROOT_DIR / "docs"
    docs_dir.mkdir(exist_ok=True)
    
    # Copy public/ to docs/
    for item in OUTPUT_DIR.rglob('*'):
        if item.is_file():
            rel_path = item.relative_to(OUTPUT_DIR)
            target_path = docs_dir / rel_path
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target_path)
    
    # Copy recent JSON reports so they're accessible
    reports_target = docs_dir / "nightly_reports"
    reports_target.mkdir(exist_ok=True)
    
    for report_file in get_recent_report_files(30):
        shutil.copy2(report_file, reports_target / report_file.name)
    
    log("✅ Synced to docs/")

def build_site():
    """Main build function - fast and focused"""
    import time
    start_time = time.time()
    
    def timed(name, func, *args, **kwargs):
        t = time.time()
        result = func(*args, **kwargs)
        log(f"   [{time.time()-t:.1f}s] {name}")
        return result
    
    log("🚀 Building ClickGrab site...")
    
    # Setup Jinja2
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(['html', 'xml'])
    )
    
    # Add filters
    env.filters['dateformat'] = lambda x: datetime.datetime.strptime(x, "%Y-%m-%d").strftime("%B %d, %Y") if x else ""
    env.filters['percentage'] = lambda x: f"{round(x)}%"
    env.filters['markdown'] = lambda x: markdown.markdown(x, extensions=['fenced_code', 'tables'])
    
    base_url = "/ClickGrab"
    
    # Build everything with timing
    timed("Static files", copy_static_files)
    timed("Index page", build_index_page, env, base_url)
    timed("Report pages", build_report_pages, env, base_url)
    timed("Reports list", build_reports_list_page, env, base_url)
    timed("Analysis page", build_analysis_page, env, base_url)
    timed("Blog posts", build_blog_post_pages, env, base_url)
    timed("Techniques page", build_techniques_page, env, base_url)
    timed("Technique details", build_technique_detail_pages, env, base_url)
    timed("Technique examples", build_technique_examples, env, base_url)
    timed("Mitigations", build_mitigations_page, env, base_url)
    timed("Copy to docs", copy_to_docs)
    
    elapsed = time.time() - start_time
    log(f"\n✨ Done in {elapsed:.1f}s!")

if __name__ == "__main__":
    build_site()
