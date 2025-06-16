#!/usr/bin/env python3
"""
ClickGrab
=========
URL Analyzer & Threat-Intel Collector for Fake CAPTCHA ("ClickFix") campaigns.

This command-line tool fetches suspect URLs (live feeds or user-supplied),
downloads their HTML, and statically analyses the content for indicators of
compromise (PowerShell, OAuth redirection abuse, clipboard hijacking, fake
CAPTCHAs, etc.).  It leverages a pattern library centralised in
`models.CommonPatterns` and modern Pydantic v2 models to return strongly-typed
results that can be rendered as HTML dashboards or ingested as JSON/CSV.

Key Features
------------
• Pull recent feeds from **URLhaus** & **AlienVault OTX** (tag-filtered).
• Detect and decode Base64, obfuscated JavaScript, encoded/hidden PowerShell.
• Extract URLs, IPs, clipboard commands, OAuth flows, and more.
• Risk-score sites and commands; generate HTML/JSON/CSV reports.
• Designed for automation — GitHub Actions workflow provided.

Author : Michael Haag  <https://github.com/MHaggis/ClickGrab>
License: Apache-2.0
"""

import argparse
import os
import sys
import re
import json
import logging
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Union
import csv
import pathlib
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from dotenv import load_dotenv
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes

from models import (
    ClickGrabConfig, AnalysisResult, AnalysisReport, 
    AnalysisVerdict, ReportFormat, CommandRiskLevel
)
import extractors

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("clickgrab")


def load_environment() -> Optional[str]:
    """Load environment variables from config/env or .env file.
    
    Returns:
        Optional[str]: OTX API key if found, None otherwise
    """
    # Try loading from config/env first
    if os.path.exists('config/env'):
        load_dotenv('config/env')
    else:
        # Fall back to .env in root directory
        load_dotenv()

    return os.getenv('OTX_API_KEY')


def sanitize_url(url: str) -> str:
    """Clean up defanged URLs to make them processable.
    
    Common defanging patterns in threat intelligence:
    - [.] -> .
    - [:]  -> :
    - hxxp -> http
    - hxxps -> https
    - (:) -> :
    - (.) -> .
    
    Args:
        url: The potentially defanged URL
        
    Returns:
        str: Sanitized URL ready for processing
    """
    if not url:
        return url
    
    # Make a copy to work with
    sanitized = url.strip()
    
    # Remove common defanging patterns
    defang_patterns = [
        ('[.]', '.'),      # [.] -> .
        ('[:]', ':'),      # [:] -> :
        ('(.)', '.'),      # (.) -> .
        ('(:)', ':'),      # (:) -> :
        ('[://]', '://'),  # [://] -> ://
        ('hxxp://', 'http://'),   # hxxp:// -> http://
        ('hxxps://', 'https://'), # hxxps:// -> https://
        ('hXXp://', 'http://'),   # hXXp:// -> http://
        ('hXXps://', 'https://'), # hXXps:// -> https://
    ]
    
    for pattern, replacement in defang_patterns:
        sanitized = sanitized.replace(pattern, replacement)
    
    # Log if we made changes
    if sanitized != url:
        logger.info(f"URL defanged: '{url}' -> '{sanitized}'")
    
    return sanitized


def get_html_content(url: str, max_redirects: int = 2) -> Optional[str]:
    """Fetch HTML content from a URL.
    
    Args:
        url: The URL to fetch content from
        max_redirects: Maximum number of redirects to follow
        
    Returns:
        str: HTML content if successful, None otherwise
    """
    try:
        # Check if URL is from a CDN known to host malware
        suspicious_cdns = [
            'cdn.jsdelivr.net',
            'code.jquery.com',
            'unpkg.com',  # Another potentially abused CDN
            'stackpath.bootstrapcdn.com'  # Also potentially abused
        ]
        
        parsed_url = urlparse(url)
        if any(cdn in parsed_url.netloc.lower() for cdn in suspicious_cdns):
            logger.warning(f"URL {url} is from a CDN known to host malware. Proceeding with analysis...")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Create a session to handle redirects
        with requests.Session() as session:
            session.max_redirects = max_redirects
            response = session.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
            response.raise_for_status()
            
            # Log redirect chain if any redirects occurred
            if len(response.history) > 0:
                logger.info(f"Redirect chain for {url}:")
                for r in response.history:
                    logger.info(f"  {r.status_code}: {r.url}")
                logger.info(f"  Final URL: {response.url}")
            
            return response.text
    except requests.RequestException as e:
        logger.error(f"Error fetching URL {url}: {e}")
        return None


def download_urlhaus_data(limit: Optional[int] = None, tags: Optional[List[str]] = None) -> List[str]:
    """Download recent URLs from URLhaus.
    
    Args:
        limit: Maximum number of URLs to return
        tags: List of tags to filter by (e.g. ['FakeCaptcha', 'ClickFix', 'click'])
        
    Returns:
        List[str]: List of URLs matching the criteria
    """
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    
    if tags is None:
        tags = ['FakeCaptcha', 'ClickFix', 'click']
    
    try:
        logger.info("Downloading URL data from URLhaus...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        lines = response.text.split('\n')
        
        header_idx = next(i for i, line in enumerate(lines) if line.startswith('# id'))
        
        clean_header = lines[header_idx].replace('# ', '')
        csv_data = [clean_header] + [line for line in lines[header_idx + 1:] if line and not line.startswith('#')]
        
        reader = csv.DictReader(csv_data)
        
        urls = []
        total_processed = 0
        for row in reader:
            if not row:  
                continue
            
            total_processed += 1
            url = row['url']
            url_tags = row['tags'].lower()
            threat = row.get('threat', '')
            
            logger.debug(f"\nProcessing entry #{total_processed}:")
            logger.debug(f"  URL: {url}")
            logger.debug(f"  Tags: {url_tags}")
            logger.debug(f"  Threat: {threat}")
            
            matching_tags = [tag for tag in tags if tag.lower() in url_tags]
            if matching_tags:
                logger.debug(f"  ✓ Tag match found: {matching_tags}")
                if url.endswith('/') or url.endswith('html') or url.endswith('htm'):
                    logger.debug(f"  ✓ URL pattern match: {url}")
                    urls.append(url)
                else:
                    logger.debug(f"  ✗ URL pattern check failed: Does not end with /, html, or htm")
            else:
                logger.debug(f"  ✗ No matching tags found. Required tags: {tags}")
            
            if limit and len(urls) >= limit:
                logger.debug(f"\nReached limit of {limit} URLs")
                break
        
        logger.info(f"Found {len(urls)} matching URLs from {total_processed} total entries")
        return urls
    
    except Exception as e:
        logger.error(f"Error downloading URLhaus data: {e}")
        return []


def download_otx_data(limit: Optional[int] = None, tags: Optional[List[str]] = None, days: int = 30) -> List[str]:
    """Download URLs from AlienVault OTX.
    
    Args:
        limit: Maximum number of URLs to return
        tags: List of tags to filter by (e.g. ['FakeCaptcha', 'ClickFix', 'click'])
        days: Number of days to look back for indicators
        
    Returns:
        List[str]: List of URLs matching the criteria
    """
    try:
        logger.info(f"Downloading URL data from AlienVault OTX (past {days} days)...")
        
        # Get API key from environment
        api_key = load_environment()
        if not api_key:
            logger.error("OTX API key not found. Please set OTX_API_KEY in config/env or .env file")
            return []

        if tags is None:
            tags = ['FakeCaptcha', 'ClickFix', 'click']
        
        results = []
        
        try:
            # Process each tag
            for tag in tags:
                logger.debug(f"Searching for indicators with tag: {tag}")
                
                # Build initial query URL - similar to PowerShell approach
                query = f"{tag.lower()} modified:<{days}d"
                otx_query = f"https://otx.alienvault.com/otxapi/indicators?include_inactive=0&sort=-modified&page=1&limit=100&q={query}&type=URL"
                
                page_count = 1
                
                # Use pagination like in PowerShell script
                while otx_query:
                    logger.debug(f"Fetching page {page_count} from AlienVault OTX...")
                    
                    # Make request with API key
                    headers = {'X-OTX-API-KEY': api_key}
                    response = requests.get(otx_query, headers=headers)
                    response.raise_for_status()
                    data = response.json()
                    
                    # Process indicators from this page
                    if 'results' in data:
                        for item in data['results']:
                            url = item.get('indicator')
                            if url and (url.endswith('/') or url.endswith('html') or url.endswith('htm')):
                                # Get additional metadata for the URL
                                try:
                                    meta_url = f"https://otx.alienvault.com/api/v1/indicators/url/{url}/url_list"
                                    meta_response = requests.get(meta_url, headers=headers)
                                    meta_response.raise_for_status()
                                    meta_data = meta_response.json()
                                    
                                    # Log metadata if available
                                    if isinstance(meta_data, dict) and meta_data.get('url_list'):
                                        logger.debug(f"Found URL with metadata: {url}")
                                        if isinstance(meta_data['url_list'], list) and meta_data['url_list']:
                                            first_entry = meta_data['url_list'][0]
                                            logger.debug(f"  Added: {first_entry.get('date')}")
                                    else:
                                        logger.debug(f"No metadata available for {url}")
                                except Exception as e:
                                    logger.debug(f"Could not fetch metadata for {url}: {str(e)}")
                                
                                if url not in results:
                                    results.append(url)
                                    logger.debug(f"Added URL: {url}")
                                    
                                    # Check limit
                                    if limit and len(results) >= limit:
                                        logger.debug(f"Reached limit of {limit} URLs from OTX")
                                        return results[:limit]
                    
                    # Get next page URL if available
                    otx_query = data.get('next')
                    page_count += 1
                    
                    logger.debug(f"Downloaded {len(results)} URLs so far...")
                        
        except Exception as e:
            logger.error(f"Error fetching OTX indicators: {e}")
            return results
        
        logger.info(f"Found {len(results)} matching URLs from AlienVault OTX")
        return results
        
    except Exception as e:
        logger.error(f"Error downloading AlienVault OTX data: {e}")
        return []


def analyze_url(url: str) -> Optional[AnalysisResult]:
    """Analyze a URL for malicious content and return results as a Pydantic model.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Optional[AnalysisResult]: Analysis results if successful, None otherwise
    """
    logger.info(f"Analyzing URL: {url}")
    
    # Sanitize URL to remove common defanging patterns
    url = sanitize_url(url)
    
    # If the URL doesn't start with http:// or https://, assume https://
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Get HTML content
    html_content = get_html_content(url)
    if not html_content:
        logger.error(f"Failed to retrieve content from {url}")
        return None
    
    # Create base analysis result
    result = AnalysisResult(
        URL=url,
        RawHTML=html_content
    )
    
    # Extract various indicators using optimized extractor functions
    result.Base64Strings = extractors.extract_base64_strings(html_content)
    result.URLs = extractors.extract_urls(html_content)
    result.PowerShellCommands = extractors.extract_powershell_commands(html_content)
    result.EncodedPowerShell = extractors.extract_encoded_powershell(html_content)
    result.IPAddresses = extractors.extract_ip_addresses(html_content)
    result.ClipboardCommands = extractors.extract_clipboard_commands(html_content)
    result.SuspiciousKeywords = extractors.extract_suspicious_keywords(html_content)
    result.ClipboardManipulation = extractors.extract_clipboard_manipulation(html_content)
    result.PowerShellDownloads = extractors.extract_powershell_downloads(html_content)
    result.CaptchaElements = extractors.extract_captcha_elements(html_content)
    result.ObfuscatedJavaScript = extractors.extract_obfuscated_javascript(html_content)
    result.SuspiciousCommands = extractors.extract_suspicious_commands(html_content)
    
    # Add new extractions
    result.BotDetection = extractors.extract_bot_detection(html_content)
    result.SessionHijacking = extractors.extract_session_hijacking(html_content)
    result.ProxyEvasion = extractors.extract_proxy_evasion(html_content)
    result.JavaScriptRedirects = extractors.extract_js_redirects(html_content)
    result.ParkingPageLoaders = extractors.extract_parking_page_loaders(html_content)
    
    logger.debug(f"Analysis complete for {url}. Found {result.TotalIndicators} indicators.")
    
    if result.TotalIndicators > 0:
        threat_score = result.ThreatScore
        logger.debug(f"Threat score: {threat_score}")
        if threat_score >= 60:
            logger.warning(f"HIGH THREAT DETECTED in {url} - Score: {threat_score}")
        elif threat_score >= 30:
            logger.warning(f"MEDIUM THREAT DETECTED in {url} - Score: {threat_score}")
    
    return result


def is_suspicious(result: AnalysisResult) -> bool:
    """Determine if an analysis result indicates a suspicious site.
    
    Args:
        result: The analysis result to check
        
    Returns:
        bool: True if the site is suspicious, False otherwise
    """
    return result.Verdict == AnalysisVerdict.SUSPICIOUS.value


def generate_html_report(results: List[AnalysisResult], config: ClickGrabConfig) -> str:
    """Generate an HTML report from analysis results.
    
    Args:
        results: List of analysis results
        config: ClickGrab configuration
        
    Returns:
        str: Path to the generated HTML report
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    suspicious_count = sum(1 for result in results if result.Verdict == AnalysisVerdict.SUSPICIOUS.value)
    
    # Output directory
    output_dir = config.output_dir
    os.makedirs(output_dir, exist_ok=True)
    
    # HTML report path
    report_name = f"clickgrab_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    report_path = os.path.join(output_dir, report_name)
    
    # Generate HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ClickGrab - URL Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2, h3 {{ color: #333; }}
            .site {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 5px; }}
            .site.suspicious {{ border-color: #ff9999; background-color: #ffeeee; }}
            .site-url {{ font-weight: bold; }}
            .indicator {{ margin: 5px 0; }}
            .indicator-title {{ font-weight: bold; }}
            .summary {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 20px; }}
            pre {{ background-color: #f8f8f8; padding: 10px; border-radius: 3px; overflow-x: auto; }}
            .highlight {{ background-color: yellow; }}
            .risk-high {{ color: #d9534f; font-weight: bold; }}
            .risk-medium {{ color: #f0ad4e; }}
            .risk-low {{ color: #5bc0de; }}
            .total-indicators {{ font-size: 1.2em; margin-top: 10px; }}
            .score-display {{ 
                display: inline-block; 
                padding: 5px 10px; 
                border-radius: 4px; 
                font-weight: bold; 
                margin-left: 10px;
                color: white;
            }}
            .score-high {{ background-color: #d9534f; }}
            .score-medium {{ background-color: #f0ad4e; }}
            .score-low {{ background-color: #5bc0de; }}
            .score-none {{ background-color: #5cb85c; }}
        </style>
    </head>
    <body>
        <h1>ClickGrab URL Analysis Report</h1>
        <div class="summary">
            <p><strong>Generated:</strong> {timestamp}</p>
            <p><strong>Sites Analyzed:</strong> {len(results)}</p>
            <p><strong>Suspicious Sites:</strong> {suspicious_count}</p>
        </div>
        
        <h2>Analysis Results</h2>
    """
    
    # Add each site analysis
    for result in results:
        is_sus = result.Verdict == AnalysisVerdict.SUSPICIOUS.value
        sus_class = "suspicious" if is_sus else ""
        
        # Determine threat score styling
        threat_score = result.ThreatScore
        score_class = "score-none"
        if threat_score >= 60:
            score_class = "score-high"
        elif threat_score >= 30:
            score_class = "score-medium"
        elif threat_score > 0:
            score_class = "score-low"
            
        html_content += f"""
        <div class="site {sus_class}">
            <h3 class="site-url">{result.URL}</h3>
            <p>
                <strong>Verdict:</strong> {'⚠️ SUSPICIOUS' if is_sus else '✅ Likely Safe'}
                <span class="score-display {score_class}">Score: {threat_score}</span>
            </p>
            <p class="total-indicators"><strong>Total Indicators:</strong> {result.TotalIndicators}</p>
        """
        
        # Base64 Strings
        if result.Base64Strings:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Base64 Strings ({len(result.Base64Strings)})</p>
                <ul>
            """
            for b64 in result.Base64Strings:
                html_content += f"<li><strong>Encoded:</strong> {b64.Base64[:50]}...</li>"
                html_content += f"<li><strong>Decoded:</strong> <pre>{b64.Decoded[:200]}...</pre></li>"
                html_content += f"<li><strong>Contains PowerShell:</strong> {'Yes ⚠️' if b64.ContainsPowerShell else 'No'}</li>"
            html_content += "</ul></div>"
        
        # PowerShell Commands
        if result.PowerShellCommands:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">PowerShell Commands ({len(result.PowerShellCommands)})</p>
                <ul>
            """
            for cmd in result.PowerShellCommands:
                html_content += f"<li><pre>{cmd}</pre></li>"
            html_content += "</ul></div>"
        
        # Encoded PowerShell
        if result.EncodedPowerShell:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Encoded PowerShell ({len(result.EncodedPowerShell)})</p>
                <ul>
            """
            for enc in result.EncodedPowerShell:
                html_content += f"<li><strong>Full Match:</strong> {enc.FullMatch[:100]}...</li>"
                html_content += f"<li><strong>Decoded:</strong> <pre>{enc.DecodedCommand[:200]}...</pre></li>"
                html_content += f"<li><strong>Suspicious Content:</strong> {'Yes ⚠️' if enc.HasSuspiciousContent else 'No'}</li>"
                html_content += f"<li><strong>Risk Level:</strong> <span class='{get_risk_level_class(enc.RiskLevel)}'>{enc.RiskLevel}</span></li>"
            html_content += "</ul></div>"
        
        # PowerShell Downloads
        if result.PowerShellDownloads:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">PowerShell Downloads ({len(result.PowerShellDownloads)})</p>
                <ul>
            """
            for download in result.PowerShellDownloads:
                html_content += f"<li><strong>Full Match:</strong> {download.FullMatch[:100]}...</li>"
                if download.URL:
                    html_content += f"<li><strong>URL:</strong> {download.URL}</li>"
                html_content += f"<li><strong>Risk Level:</strong> <span class='{get_risk_level_class(download.RiskLevel)}'>{download.RiskLevel}</span></li>"
            html_content += "</ul></div>"
        
        # Clipboard Manipulation
        if result.ClipboardManipulation:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Clipboard Manipulation ({len(result.ClipboardManipulation)})</p>
                <ul>
            """
            for clip in result.ClipboardManipulation:
                html_content += f"<li><pre>{clip}</pre></li>"
            html_content += "</ul></div>"
        
        # Clipboard Commands
        if result.ClipboardCommands:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Clipboard Commands ({len(result.ClipboardCommands)})</p>
                <ul>
            """
            for cmd in result.ClipboardCommands:
                html_content += f"<li><pre>{cmd}</pre></li>"
            html_content += "</ul></div>"
        
        # CAPTCHA Elements
        if result.CaptchaElements:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">CAPTCHA Elements ({len(result.CaptchaElements)})</p>
                <ul>
            """
            for elem in result.CaptchaElements:
                html_content += f"<li><pre>{elem}</pre></li>"
            html_content += "</ul></div>"
        
        # Obfuscated JavaScript
        if result.ObfuscatedJavaScript:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Obfuscated JavaScript ({len(result.ObfuscatedJavaScript)})</p>
                <ul>
            """
            for js in result.ObfuscatedJavaScript:
                if isinstance(js, dict) and 'script' in js:
                    html_content += f"<li><pre>{js['script']}</pre></li>"
                    if 'score' in js:
                        html_content += f"<li><strong>Obfuscation Score:</strong> {js['score']}</li>"
                else:
                    html_content += f"<li><pre>{js}</pre></li>"
            html_content += "</ul></div>"
        
        # Suspicious Commands
        if result.SuspiciousCommands:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Suspicious Commands ({len(result.SuspiciousCommands)})</p>
                <ul>
            """
            for cmd in result.SuspiciousCommands:
                risk_class = get_risk_level_class(cmd.RiskLevel)
                
                html_content += f"<li><strong>Type:</strong> {cmd.CommandType}</li>"
                html_content += f"<li><strong>Risk Level:</strong> <span class='{risk_class}'>{cmd.RiskLevel}</span></li>"
                html_content += f"<li><strong>Command:</strong> <pre>{cmd.Command}</pre></li>"
                if cmd.Source:
                    html_content += f"<li><strong>Source:</strong> {cmd.Source}</li>"
            html_content += "</ul></div>"
        
        # High Risk Commands Summary
        if result.HighRiskCommands:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title risk-high">⚠️ High Risk Commands Summary ({len(result.HighRiskCommands)})</p>
                <ul>
            """
            for cmd in result.HighRiskCommands:
                html_content += f"<li><strong>{cmd.CommandType}:</strong> <pre>{cmd.Command[:100]}{'...' if len(cmd.Command) > 100 else ''}</pre></li>"
            html_content += "</ul></div>"
        
        # Suspicious Keywords
        if result.SuspiciousKeywords:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Suspicious Keywords ({len(result.SuspiciousKeywords)})</p>
                <ul>
            """
            for kw in result.SuspiciousKeywords:
                html_content += f"<li>{kw}</li>"
            html_content += "</ul></div>"
        
        # URLs
        if result.URLs:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">URLs ({len(result.URLs)})</p>
                <ul>
            """
            for url in result.URLs:
                html_content += f"<li>{url}</li>"
            html_content += "</ul></div>"
        
        # IP Addresses
        if result.IPAddresses:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">IP Addresses ({len(result.IPAddresses)})</p>
                <ul>
            """
            for ip in result.IPAddresses:
                html_content += f"<li>{ip}</li>"
            html_content += "</ul></div>"
        
        # Add the new extraction fields: Bot Detection, Session Hijacking, Proxy Evasion
        # Bot Detection
        if result.BotDetection:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Bot Detection and Sandbox Evasion ({len(result.BotDetection)})</p>
                <ul>
            """
            for detection in result.BotDetection:
                html_content += f"<li><pre>{detection}</pre></li>"
            html_content += "</ul></div>"
            
        # Session Hijacking
        if result.SessionHijacking:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Session Hijacking Attempts ({len(result.SessionHijacking)})</p>
                <ul>
            """
            for hijack in result.SessionHijacking:
                html_content += f"<li><pre>{hijack}</pre></li>"
            html_content += "</ul></div>"
            
        # Proxy Evasion
        if result.ProxyEvasion:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Proxy/Security Tool Evasion ({len(result.ProxyEvasion)})</p>
                <ul>
            """
            for evasion in result.ProxyEvasion:
                html_content += f"<li><pre>{evasion}</pre></li>"
            html_content += "</ul></div>"
        
        # JavaScript Redirects
        if result.JavaScriptRedirects:
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title risk-high">JavaScript Redirects and Loaders ({len(result.JavaScriptRedirects)})</p>
                <ul>
            """
            for redirect in result.JavaScriptRedirects:
                html_content += f"<li><pre>{redirect}</pre></li>"
            html_content += "</ul></div>"
        
        html_content += "</div>"
    
    html_content += """
    </body>
    </html>
    """
    
    # Write HTML to file
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path


def get_risk_level_class(risk_level: str) -> str:
    """Get CSS class for a risk level.
    
    Args:
        risk_level: The risk level string
        
    Returns:
        str: CSS class for the risk level
    """
    if CommandRiskLevel.HIGH.value in risk_level or CommandRiskLevel.CRITICAL.value in risk_level:
        return "risk-high"
    elif CommandRiskLevel.MEDIUM.value in risk_level:
        return "risk-medium"
    else:
        return "risk-low"


def generate_json_report(results: List[AnalysisResult], config: ClickGrabConfig) -> str:
    """Generate a JSON report from analysis results.
    
    Args:
        results: List of analysis results
        config: ClickGrab configuration
        
    Returns:
        str: Path to the generated JSON report
    """
    output_dir = config.output_dir
    os.makedirs(output_dir, exist_ok=True)
    
    # Create report structure
    report = AnalysisReport(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_sites_analyzed=len(results),
        summary={
            "suspicious_sites": sum(1 for result in results if result.Verdict == AnalysisVerdict.SUSPICIOUS.value),
            "powershell_commands": sum(len(result.PowerShellCommands) for result in results),
            "base64_strings": sum(len(result.Base64Strings) for result in results),
            "clipboard_manipulation": sum(len(result.ClipboardManipulation) for result in results),
            "captcha_elements": sum(len(result.CaptchaElements) for result in results),
            "high_risk_commands": sum(len(result.HighRiskCommands) for result in results),
            "encoded_powershell": sum(len(result.EncodedPowerShell) for result in results),
            "powershell_downloads": sum(len(result.PowerShellDownloads) for result in results),
            "obfuscated_javascript": sum(len(result.ObfuscatedJavaScript) for result in results),
            "suspicious_commands": sum(len(result.SuspiciousCommands) for result in results),
            "suspicious_keywords": sum(len(result.SuspiciousKeywords) for result in results),
            "ip_addresses": sum(len(result.IPAddresses) for result in results),
            "clipboard_commands": sum(len(result.ClipboardCommands) for result in results),
            "javascript_redirects": sum(len(result.JavaScriptRedirects) for result in results),
            "average_threat_score": round(sum(result.ThreatScore for result in results) / len(results)) if results else 0
        },
        sites=results
    )
    
    # JSON report path
    report_name = f"clickgrab_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path = os.path.join(output_dir, report_name)
    
    # Write JSON to file with additional info
    with open(report_path, 'w', encoding='utf-8') as f:
        json_data = report.model_dump_json(exclude_none=True, indent=2)
        f.write(json_data)
    
    # Also create a latest copy for easy access
    latest_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "latest_consolidated_report.json")
    with open(latest_path, 'w', encoding='utf-8') as f:
        f.write(json_data)
    
    return report_path


def generate_csv_report(results: List[AnalysisResult], config: ClickGrabConfig) -> str:
    """Generate a CSV report from analysis results.
    
    Args:
        results: List of analysis results
        config: ClickGrab configuration
        
    Returns:
        str: Path to the generated CSV report
    """
    output_dir = config.output_dir
    os.makedirs(output_dir, exist_ok=True)
    
    # CSV report path
    report_name = f"clickgrab_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    report_path = os.path.join(output_dir, report_name)
    
    # Define CSV headers
    headers = [
        "URL", 
        "Suspicious", 
        "Threat Score",
        "Total Indicators",
        "Base64Strings", 
        "PowerShellCommands", 
        "EncodedPowerShell",
        "PowerShellDownloads", 
        "ClipboardManipulation", 
        "ClipboardCommands",
        "CaptchaElements", 
        "ObfuscatedJavaScript", 
        "SuspiciousCommands",
        "SuspiciousKeywords",
        "IP Addresses",
        "High Risk Commands",
        "JavaScript Redirects"
    ]
    
    # Write CSV file
    with open(report_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for result in results:
            suspicious = "Yes" if result.Verdict == AnalysisVerdict.SUSPICIOUS.value else "No"
            writer.writerow([
                result.URL,
                suspicious,
                result.ThreatScore,
                result.TotalIndicators,
                len(result.Base64Strings),
                len(result.PowerShellCommands),
                len(result.EncodedPowerShell),
                len(result.PowerShellDownloads),
                len(result.ClipboardManipulation),
                len(result.ClipboardCommands),
                len(result.CaptchaElements),
                len(result.ObfuscatedJavaScript),
                len(result.SuspiciousCommands),
                len(result.SuspiciousKeywords),
                len(result.IPAddresses),
                len(result.HighRiskCommands),
                len(result.JavaScriptRedirects)
            ])
    
    return report_path


def parse_arguments() -> ClickGrabConfig:
    """Parse command line arguments and return as a Pydantic model.
    
    Returns:
        ClickGrabConfig: Configuration based on command line arguments
    """
    parser = argparse.ArgumentParser(description="ClickGrab - URL Analyzer for detecting fake CAPTCHA sites")
    
    parser.add_argument("analyze", nargs="?", help="URL to analyze or path to a file containing URLs (one per line)")
    parser.add_argument("--limit", type=int, help="Limit the number of URLs to process")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--output-dir", default="reports", help="Directory for report output")
    parser.add_argument("--format", choices=["html", "json", "csv", "all"], default="all", help="Report format")
    parser.add_argument("--tags", help="Comma-separated list of tags to look for")
    parser.add_argument("--download", action="store_true", help="Download and analyze URLs from URLhaus")
    parser.add_argument("--otx", action="store_true", help="Download and analyze URLs from AlienVault OTX")
    parser.add_argument("--days", type=int, default=30, help="Number of days to look back in AlienVault OTX (default: 30)")
    
    args = parser.parse_args()
    
    # Convert args to dict and create Pydantic model
    return ClickGrabConfig(**vars(args))


def read_urls_from_file(file_path: str) -> List[str]:
    """Read URLs from a file, one per line.
    
    Args:
        file_path: Path to the file containing URLs
        
    Returns:
        List[str]: List of URLs read from the file
    """
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Failed to read URLs from file {file_path}: {e}")
        return []


def main():
    """Main entry point for ClickGrab."""
    # Parse arguments
    config = parse_arguments()
    
    # Configure logging level
    if config.debug:
        logger.setLevel(logging.DEBUG)
        # Also set urllib3 warnings to be displayed in debug mode
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    else:
        # Disable request warnings in normal mode
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        import warnings
        warnings.filterwarnings("ignore")
    
    # Initialize results list
    results = []
    
    # Determine mode of operation
    if config.download or config.otx:
        urls = []
        
        # Download from URLhaus if requested
        if config.download:
            logger.info("Running in URLhaus download mode")
            tags = None
            if config.tags:
                # config.tags is already a list due to the validator in the Pydantic model
                tags = config.tags
            
            urlhaus_urls = download_urlhaus_data(config.limit, tags)
            if urlhaus_urls:
                logger.info(f"Downloaded {len(urlhaus_urls)} URLs from URLhaus")
                urls.extend(urlhaus_urls)
        
        # Download from AlienVault OTX if requested
        if config.otx:
            logger.info("Running in AlienVault OTX download mode")
            tags = None
            if config.tags:
                tags = config.tags
            
            otx_urls = download_otx_data(config.limit, tags, config.days)
            if otx_urls:
                logger.info(f"Downloaded {len(otx_urls)} URLs from AlienVault OTX")
                urls.extend(otx_urls)
        
        # Deduplicate URLs
        unique_urls = list(dict.fromkeys(urls))
        if len(unique_urls) < len(urls):
            logger.info(f"Removed {len(urls) - len(unique_urls)} duplicate URLs")
        
        # Apply limit after combining sources if needed
        if config.limit and len(unique_urls) > config.limit:
            unique_urls = unique_urls[:config.limit]
            logger.info(f"Limited to {config.limit} URLs total")
        
        if not unique_urls:
            logger.error("No URLs found from the specified sources matching the criteria")
            sys.exit(1)
        
        # Process each URL
        for url in unique_urls:
            result = analyze_url(url)
            if result:
                results.append(result)
                
    elif config.analyze:
        # Standard mode - analyze specified URL or file
        if os.path.isfile(config.analyze):
            # Read URLs from file
            urls = read_urls_from_file(config.analyze)
            logger.info(f"Loaded {len(urls)} URLs from file {config.analyze}")
            
            # Apply limit if specified
            if config.limit and config.limit > 0:
                urls = urls[:config.limit]
                logger.info(f"Limited to first {config.limit} URLs")
            
            # Process each URL
            for url in urls:
                result = analyze_url(url)
                if result:
                    results.append(result)
        else:
            # Single URL analysis
            result = analyze_url(config.analyze)
            if result:
                results.append(result)
    else:
        # No URL or file specified, and not in download mode
        print("Error: No URL or file specified.")
        print("Usage: python clickgrab.py [URL or file] [options]")
        print("       python clickgrab.py --download [options] to download from URLhaus")
        print("       python clickgrab.py --otx [options] to download from AlienVault OTX")
        print("For more information, use --help")
        sys.exit(1)
    
    # Generate reports
    if results:
        logger.info(f"Analysis complete. Processing {len(results)} results.")
        
        reports = []
        
        if config.format == ReportFormat.HTML.value or config.format == ReportFormat.ALL.value:
            html_report = generate_html_report(results, config)
            reports.append(("HTML", html_report))
        
        if config.format == ReportFormat.JSON.value or config.format == ReportFormat.ALL.value:
            json_report = generate_json_report(results, config)
            reports.append(("JSON", json_report))
        
        if config.format == ReportFormat.CSV.value or config.format == ReportFormat.ALL.value:
            csv_report = generate_csv_report(results, config)
            reports.append(("CSV", csv_report))
        
        # Print summary
        print("\nAnalysis Summary:")
        print(f"URLs analyzed: {len(results)}")
        suspicious_count = sum(1 for r in results if r.Verdict == AnalysisVerdict.SUSPICIOUS.value)
        print(f"Suspicious sites: {suspicious_count} ({round((suspicious_count / len(results)) * 100, 1)}%)")
        
        high_risk_count = sum(len(r.HighRiskCommands) for r in results)
        if high_risk_count > 0:
            print(f"High risk commands detected: {high_risk_count}")
        
        # Print threat scores
        if len(results) > 0:
            scores = [r.ThreatScore for r in results]
            avg_score = sum(scores) / len(scores)
            max_score = max(scores)
            print(f"Average threat score: {avg_score:.1f}")
            print(f"Maximum threat score: {max_score}")
        
        print("\nReports generated:")
        for report_type, report_path in reports:
            print(f"- {report_type}: {report_path}")
    else:
        logger.warning("No results to generate reports from.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1) 