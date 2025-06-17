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
    """Get the date of the latest report."""
    # First try to find reports with date-only pattern
    report_files = list(REPORTS_DIR.glob("clickgrab_report_????-??-??.json"))
    
    # Also look for timestamped reports
    timestamped_files = list(REPORTS_DIR.glob("clickgrab_report_????????_??????.json"))
    
    # Combine both types
    all_files = report_files + timestamped_files
    
    if not all_files:
        print(f"Warning: No report files found in {REPORTS_DIR}")
        return datetime.now().strftime("%Y-%m-%d")
    
    # Sort by modification time, newest first
    latest_file = max(all_files, key=lambda f: f.stat().st_mtime)
    
    # Extract date from the filename
    filename = latest_file.name
    
    # Try to extract date from date-only format (clickgrab_report_YYYY-MM-DD.json)
    date_pattern = r"clickgrab_report_(\d{4}-\d{2}-\d{2})\.json"
    match = re.match(date_pattern, filename)
    if match:
        return match.group(1)
    
    # Try to extract date from timestamped format (clickgrab_report_YYYYMMDD_HHMMSS.json)
    timestamp_pattern = r"clickgrab_report_(\d{8})_\d{6}\.json"
    match = re.match(timestamp_pattern, filename)
    if match:
        # Convert YYYYMMDD to YYYY-MM-DD
        date_str = match.group(1)
        return f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
    
    print(f"Warning: Could not extract date from filename: {filename}")
    return datetime.now().strftime("%Y-%m-%d")

def load_report_data(date):
    """Load report data for a specific date."""
    # Try different filename patterns
    patterns = [
        f"clickgrab_report_{date}.json",
        f"clickgrab_report_{date.replace('-', '')}*.json"
    ]
    
    for pattern in patterns:
        files = list(REPORTS_DIR.glob(pattern))
        if files:
            # Use the most recent file if multiple matches
            report_file = max(files, key=lambda f: f.stat().st_mtime)
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                    # Handle both legacy uppercase and new lowercase formats
                    # Legacy PowerShell format uses uppercase keys
                    if 'Sites' in data:
                        # Convert legacy format to new format
                        converted_data = {
                            'sites': data.get('Sites', []),
                            'total_sites': data.get('TotalSites', len(data.get('Sites', []))),
                            'report_time': data.get('ReportTime', date)
                        }
                        # Add summary for legacy format
                        sites = converted_data['sites']
                        converted_data['summary'] = {
                            'total_sites': len(sites),
                            'suspicious_sites': sum(1 for site in sites if site),
                            'total_urls_extracted': sum(len(site.get('ExtractedUrls', [])) if isinstance(site, dict) else 0 for site in sites if site)
                        }
                        return converted_data
                    else:
                        # New format already has lowercase keys
                        return data
            except Exception as e:
                print(f"Error loading {report_file}: {e}")
                continue
    
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
    # Get both date-only and timestamped files
    date_only_files = list(REPORTS_DIR.glob("clickgrab_report_????-??-??.json"))
    timestamped_files = list(REPORTS_DIR.glob("clickgrab_report_????????_??????.json"))
    
    dates = set()  # Use set to avoid duplicates
    
    # Process date-only files
    for file in date_only_files:
        try:
            date_str = file.name.split("_")[2].split(".")[0]
            dates.add(date_str)
        except (IndexError, ValueError):
            continue
    
    # Process timestamped files
    for file in timestamped_files:
        try:
            # Extract YYYYMMDD part
            timestamp_part = file.name.split("_")[2]
            if len(timestamp_part) == 8 and timestamp_part.isdigit():
                # Convert to YYYY-MM-DD format
                date_str = f"{timestamp_part[:4]}-{timestamp_part[4:6]}-{timestamp_part[6:8]}"
                dates.add(date_str)
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
        # Handle new AnalysisReport format
        sites = report_data.get("sites", [])
        total_sites = report_data.get("total_sites", len(sites))
        
        # Get summary data if available (from AnalysisReport model)
        summary = report_data.get("summary", {})
        if summary:
            # Use summary data if available for quick stats
            sites_with_attacks = summary.get("suspicious_sites", 0)
            total_malicious_urls = summary.get("total_urls_extracted", 0)
        else:
            # Calculate from sites array
            for site in sites:
                if isinstance(site, dict):
                    # Count malicious sites
                    is_malicious = False
                    
                    # Check for legacy PowerShell format
                    if site.get("IsMalicious", False):
                        is_malicious = True
                        sites_with_attacks += 1
                    
                    # Check for detection results
                    detections = site.get("DetectionResults", {})
                    if any(detections.values()):
                        is_malicious = True
                        if not site.get("IsMalicious", False):  # Avoid double counting
                            sites_with_attacks += 1
                    
                    # Count URLs
                    urls = site.get("ExtractedUrls", site.get("URLs", site.get("Urls", [])))
                    if isinstance(urls, list):
                        total_malicious_urls += len(urls)
                    
                    # Count specific attack types
                    if detections.get("PowerShellExecution"):
                        powershell_command_count += 1
                    if detections.get("ClipboardManipulation"):
                        clipboard_manipulation_count += 1
                    
                    # Also check legacy fields
                    if site.get("PowerShellCommands") or site.get("PowerShellDownloads"):
                        powershell_command_count += 1
                    if site.get("ClipboardManipulation"):
                        clipboard_manipulation_count += 1
                
                elif isinstance(site, str):
                    # Legacy format might have sites as strings
                    sites_with_attacks += 1
                    total_malicious_urls += 1
    
    # Calculate attack patterns
    attack_patterns = 0
    if powershell_command_count > 0:
        attack_patterns += 1
    if clipboard_manipulation_count > 0:
        attack_patterns += 1
    if sites_with_attacks > powershell_command_count + clipboard_manipulation_count:
        attack_patterns += 1  # Other patterns
    
    # Get recent reports for the sidebar
    report_dates = get_all_report_dates()[:5]
    recent_reports = []
    for date in report_dates:
        recent_reports.append({
            "date": date,
            "url": f"{base_url}/reports/{date}.html"
        })
    
    html = template.render(
        latest_date=latest_date,
        total_sites=total_sites,
        total_malicious_urls=total_malicious_urls,
        sites_with_attacks=sites_with_attacks,
        attack_patterns=attack_patterns,
        # Additional template variables for compatibility
        sites_scanned=total_sites,
        total_attacks=total_malicious_urls,
        latest_report_date=latest_date,
        latest_sites_scanned=total_sites,
        latest_sites_with_attacks=sites_with_attacks,
        latest_new_attacks=0,  # We don't track new vs old
        latest_crypto_attacks=powershell_command_count,
        latest_url_attacks=clipboard_manipulation_count,
        recent_reports=recent_reports,
        active_page='home',
        base_url=base_url
    )
    
    with open(OUTPUT_DIR / "index.html", "w", encoding='utf-8') as f:
        f.write(html)
    
    print(f"Generated index.html with stats: {total_sites} sites, {sites_with_attacks} malicious")

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
        
        # Handle new AnalysisReport format
        sites = report_data.get("sites", [])
        total_sites = report_data.get("total_sites", len(sites))
        
        # Get summary data
        summary = report_data.get("summary", {})
        
        # Count attack patterns across all sites
        attack_patterns = set()
        malicious_urls = 0
        sites_with_attacks = 0
        
        for site in sites:
            if isinstance(site, dict):
                # Site might be a string in very old formats or a dict in newer formats
                site_patterns = site.get("attack_patterns", [])
                site_urls = site.get("malicious_urls", site.get("ExtractedUrls", []))
                
                if site_patterns:
                    attack_patterns.update(site_patterns)
                    sites_with_attacks += 1
                    
                if isinstance(site_urls, list):
                    malicious_urls += len(site_urls)
                
                # Also check for legacy PowerShell fields
                if site.get("IsMalicious", False) or site.get("DetectionResults"):
                    sites_with_attacks += 1
                    
                    # Add detection types as patterns
                    detections = site.get("DetectionResults", {})
                    for detection_type, detected in detections.items():
                        if detected:
                            attack_patterns.add(detection_type)
        
        # Use summary data if available (from new format)
        if summary:
            sites_with_attacks = max(sites_with_attacks, summary.get("suspicious_sites", 0))
            malicious_urls = max(malicious_urls, summary.get("total_urls_extracted", 0))
        
        html = template.render(
            date=date,
            base_url=base_url,
            report={
                "sites_scanned": total_sites,
                "sites_attacked": sites_with_attacks,
                "attacks_detected": len(attack_patterns),
                "sites": sites[:20],  # Show first 20 sites
                "new_patterns": 0  # We don't track new vs old patterns
            },
            analysis_html=markdown.markdown(analysis_markdown) if analysis_markdown else None
        )
        
        with open(reports_dir / f"{date}.html", "w", encoding='utf-8') as f:
            f.write(html)
    
    print(f"Generated {len(report_dates)} report pages")

def build_reports_list_page(env, base_url):
    template = env.get_template("reports.html")
    report_dates = get_all_report_dates()
    
    reports = []
    for date in report_dates:
        report_data = load_report_data(date)
        if report_data:
            sites = report_data.get("sites", [])
            total_sites = report_data.get("total_sites", len(sites))
            
            # Calculate attacks for both formats
            attacks = 0
            for site in sites:
                if isinstance(site, dict):
                    # Check legacy format
                    if site.get("IsMalicious", False):
                        attacks += 1
                    # Check detection results
                    elif site.get("DetectionResults", {}):
                        if any(site.get("DetectionResults", {}).values()):
                            attacks += 1
                    # Check for any extracted URLs
                    elif site.get("ExtractedUrls") or site.get("URLs"):
                        attacks += 1
                elif isinstance(site, str):
                    attacks += 1  # Legacy format with sites as strings
            
            # Use summary if available
            summary = report_data.get("summary", {})
            if summary:
                attacks = max(attacks, summary.get("suspicious_sites", 0))
            
            # Parse date for year and month
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
                "attacks_detected": attacks,
                "new_patterns": 0  # We don't track new vs old patterns
            })
    
    html = template.render(
        reports=reports,
        base_url=base_url
    )
    
    with open(OUTPUT_DIR / "reports.html", "w", encoding='utf-8') as f:
        f.write(html)
    
    print(f"Generated reports list page with {len(reports)} reports")

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
    
    # Build analysis pages
    build_analysis_page(env, base_url)
    build_blog_post_pages(env, base_url)
    
    # Copy to docs/ directory for GitHub Pages
    copy_to_docs()
    
    print("\n🚀 Site generation complete!")
    print(f"Files have been written to {OUTPUT_DIR} and docs/")

def load_blog_data(date_str=None):
    """Load blog data for a specific date."""
    if not date_str:
        date_str = get_latest_report_date()
    
    # Look for blog data file
    blog_data_file = ANALYSIS_DIR / f"blog_data_{date_str}.json"
    
    if not blog_data_file.exists():
        # Try to find the latest blog data file
        blog_files = list(ANALYSIS_DIR.glob("blog_data_*.json"))
        if blog_files:
            blog_data_file = max(blog_files, key=lambda f: f.stat().st_mtime)
        else:
            print(f"Warning: No blog data file found for {date_str}")
            return None
    
    try:
        with open(blog_data_file, "r", encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading blog data: {e}")
        return None

def get_all_blog_data():
    """Get all available blog post data"""
    blog_files = list(ANALYSIS_DIR.glob("blog_data_*.json"))
    blog_posts = []
    
    for blog_file in blog_files:
        try:
            with open(blog_file, "r", encoding='utf-8') as f:
                blog_data = json.load(f)
                blog_posts.append(blog_data)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error loading blog data from {blog_file}: {e}")
            continue
    
    # Sort by date, newest first
    blog_posts.sort(key=lambda x: x.get('date', ''), reverse=True)
    return blog_posts

def generate_blog_post_html(blog_data, analysis_markdown):
    """Convert analysis markdown and blog data into structured HTML for blog post"""
    if not analysis_markdown:
        return ""
    
    # Convert markdown to HTML
    html_content = convert_markdown_to_html(analysis_markdown)
    
    # Enhance HTML with structured sections based on blog_data
    enhanced_html = html_content
    
    # Add executive summary with stats if not present
    if "Executive Summary" not in html_content and blog_data.get('stats'):
        stats = blog_data['stats']
        stats_html = f"""
        <h2>Executive Summary</h2>
        <p>Our latest threat intelligence analysis reveals a sophisticated attack campaign targeting users through fake CAPTCHA verification schemes. This comprehensive analysis of {stats['sites_analyzed']} sites uncovered a coordinated attack infrastructure with a {stats['malicious_rate']}% malicious detection rate.</p>
        
        <div class="stats-grid">
            <div class="stat-item">
                <span class="stat-number">{stats['sites_analyzed']}</span>
                <span class="stat-label">Sites Analyzed</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{stats['malicious_rate']}%</span>
                <span class="stat-label">Malicious Rate</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{stats['attack_patterns']}</span>
                <span class="stat-label">Attack Patterns</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{stats['powershell_downloads']}</span>
                <span class="stat-label">PowerShell Downloads</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{stats['clipboard_manipulations']}</span>
                <span class="stat-label">Clipboard Manipulations</span>
            </div>
            <div class="stat-item">
                <span class="stat-number">{stats['obfuscation_score']}/7</span>
                <span class="stat-label">Obfuscation Score</span>
            </div>
        </div>
        """
        
        # Insert stats after the first paragraph or at the beginning
        if "<p>" in enhanced_html:
            parts = enhanced_html.split("</p>", 1)
            if len(parts) == 2:
                enhanced_html = parts[0] + "</p>" + stats_html + parts[1]
        else:
            enhanced_html = stats_html + enhanced_html
    
    return enhanced_html

def build_analysis_page(env, base_url):
    """Build the main analysis page with blog post cards"""
    template = env.get_template("analysis.html")
    
    # Get all blog posts
    analysis_posts = get_all_blog_data()
    
    # Limit to recent posts for the main page
    recent_posts = analysis_posts[:5]
    
    html = template.render(
        analysis_posts=recent_posts,
        active_page='analysis',
        base_url=base_url
    )
    
    with open(OUTPUT_DIR / "analysis.html", "w", encoding='utf-8') as f:
        f.write(html)
    
    print(f"✅ Generated analysis.html with {len(recent_posts)} blog posts")

def build_blog_post_pages(env, base_url):
    """Build individual blog post pages"""
    template = env.get_template("blog_post.html")
    
    # Create analysis subdirectory
    analysis_dir = OUTPUT_DIR / "analysis"
    analysis_dir.mkdir(exist_ok=True)
    
    # Get all blog posts
    analysis_posts = get_all_blog_data()
    
    for blog_data in analysis_posts:
        date_str = blog_data.get('date')
        if not date_str:
            continue
        
        # Load corresponding markdown analysis
        analysis_markdown = load_analysis_markdown(date_str)
        
        # Generate enhanced HTML content
        blog_html_content = generate_blog_post_html(blog_data, analysis_markdown)
        
        # Create post data for template
        post_data = {
            "title": blog_data.get('title', f'ClickGrab Analysis - {date_str}'),
            "date": date_str,
            "content": blog_html_content,
            "read_time": blog_data.get('read_time', 12),
            "category": blog_data.get('category', 'Threat Analysis'),
            "tags": blog_data.get('tags', [])
        }
        
        html = template.render(
            post=post_data,
            active_page='analysis',
            base_url=base_url
        )
        
        # Save individual blog post
        blog_filename = f"{blog_data.get('slug', f'analysis-{date_str}')}.html"
        with open(analysis_dir / blog_filename, "w", encoding='utf-8') as f:
            f.write(html)
        
        print(f"✅ Generated blog post: {blog_filename}")

if __name__ == "__main__":
    build_site() 