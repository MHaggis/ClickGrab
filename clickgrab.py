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
import hashlib
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Union, Tuple
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

DEFAULT_CLICKFIX_GIST_ID = "9f563dfb78a06fad5db794f33ba93a3f"
DEFAULT_CLICKFIX_GIST_FILENAME = "clickfix_domains.txt"
CLICKFIX_GIST_CACHE_FILE = pathlib.Path("analysis/clickfix_gist_cache.json")

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
    """Download online URLs from URLhaus.
    
    Prefers the authenticated API (if env var URLHAUS_AUTH_KEY or URLHAUS_API_KEY is set),
    and falls back to the public CSV feed otherwise.
    
    Args:
        limit: Maximum number of URLs to return
        tags: List of tags to filter by (e.g. ['FakeCaptcha', 'ClickFix', 'click'])
        
    Returns:
        List[str]: List of URLs matching the criteria
    """
    if tags is None:
        tags = ['FakeCaptcha', 'ClickFix', 'click', 'fakecloudflarecaptcha']

    # 1) Try authenticated API first if a key is present
    import os
    api_key = os.getenv('URLHAUS_AUTH_KEY') or os.getenv('URLHAUS_API_KEY')
    if api_key:
        try:
            # Collect from both recent and tag endpoints
            use_limit = max(1, min(int(limit) if limit else 1000, 1000))
            combined_entries = []

            # 1) Recent
            recent_url = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{use_limit}/"
            logger.info("Fetching URLhaus recent URLs via Auth API…")
            resp = requests.get(recent_url, headers={"Auth-Key": api_key}, timeout=30)
            resp.raise_for_status()
            data_recent = resp.json()
            if data_recent.get('query_status') != 'ok':
                logger.warning(f"URLhaus API recent status: {data_recent.get('query_status')}")
            combined_entries.extend(data_recent.get('urls', []))

            # 2) Tag queries (historical)
            tag_endpoint = "https://urlhaus-api.abuse.ch/v1/tag/"
            seen_urls = set(e.get('url') for e in combined_entries if isinstance(e, dict))
            for tg in set(t.lower() for t in tags):
                try:
                    resp_t = requests.post(
                        tag_endpoint,
                        headers={"Auth-Key": api_key},
                        data={"tag": tg, "limit": str(use_limit)},
                        timeout=30,
                    )
                    resp_t.raise_for_status()
                    data_t = resp_t.json()
                    if data_t.get('query_status') != 'ok':
                        logger.debug(f"Tag query for '{tg}' returned status {data_t.get('query_status')}")
                        continue
                    for e in data_t.get('urls', []):
                        u = e.get('url')
                        if u and u not in seen_urls:
                            combined_entries.append(e)
                            seen_urls.add(u)
                except Exception as te:
                    logger.debug(f"URLhaus tag query error for '{tg}': {te}")

            # Filter combined entries
            urls: List[str] = []
            total_processed = 0
            for entry in combined_entries:
                total_processed += 1
                entry_url = entry.get('url', '')
                entry_tags = entry.get('tags') or []
                entry_tags_lc = [t.lower() for t in entry_tags if isinstance(t, str)]
                url_status = (entry.get('url_status') or '').lower()

                logger.debug(f"\nProcessing API entry #{total_processed}:")
                logger.debug(f"  URL: {entry_url}")
                logger.debug(f"  Tags: {entry_tags_lc}")
                logger.debug(f"  Status: {url_status}")

                # Tag filter
                matching_tags = [tag for tag in tags if tag.lower() in entry_tags_lc]
                if not matching_tags:
                    continue

                # Only consider online pages likely to be HTML landing pages
                if url_status != 'online':
                    continue
                if not (entry_url.endswith('/') or entry_url.endswith('html') or entry_url.endswith('htm')):
                    continue

                urls.append(entry_url)
                if limit and len(urls) >= limit:
                    break

            if urls:
                logger.info(f"Found {len(urls)} matching URLs from {total_processed} API entries (recent+tag)")
                return urls
            else:
                logger.info("No matching URLs found via API (recent+tag), falling back to CSV feed…")
        except Exception as e:
            logger.error(f"URLhaus API error: {e}. Falling back to CSV feed…")

    # 2) Fallback to CSV feed
    csv_url = "https://urlhaus.abuse.ch/downloads/csv_online" 
    try:
        logger.info("Downloading URL data from URLhaus CSV feed…")
        response = requests.get(csv_url, timeout=30)
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
            entry_url = row['url']
            url_tags = row['tags'].lower()
            threat = row.get('threat', '')

            logger.debug(f"\nProcessing CSV entry #{total_processed}:")
            logger.debug(f"  URL: {entry_url}")
            logger.debug(f"  Tags: {url_tags}")
            logger.debug(f"  Threat: {threat}")

            matching_tags = [tag for tag in tags if tag.lower() in url_tags]
            if matching_tags and (entry_url.endswith('/') or entry_url.endswith('html') or entry_url.endswith('htm')):
                urls.append(entry_url)
                if limit and len(urls) >= limit:
                    break

        logger.info(f"Found {len(urls)} matching URLs from {total_processed} CSV entries")
        return urls
    except Exception as e:
        logger.error(f"Error downloading URLhaus CSV data: {e}")
        return []


def get_latest_gist_url(gist_id: str, filename: str) -> Optional[str]:
    """Fetch the latest raw URL for a specific file in a GitHub Gist using the API.
    
    This ensures we always get the most recent version even if the gist is updated.
    
    Args:
        gist_id: The GitHub Gist ID
        filename: The name of the file within the gist
        
    Returns:
        Optional[str]: The raw URL to the latest version, or None if unavailable
    """
    try:
        api_url = f"https://api.github.com/gists/{gist_id}"
        logger.debug(f"Fetching latest gist metadata from GitHub API: {api_url}")
        
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'ClickGrab-URLAnalyzer'
        }
        
        response = requests.get(api_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        gist_data = response.json()
        
        # Get the file data from the gist
        if 'files' in gist_data and filename in gist_data['files']:
            file_data = gist_data['files'][filename]
            raw_url = file_data.get('raw_url')
            
            if raw_url:
                logger.info(f"Retrieved latest raw URL for {filename}")
                return raw_url
            else:
                logger.warning(f"No raw_url found for {filename} in gist {gist_id}")
                return None
        else:
            logger.warning(f"File {filename} not found in gist {gist_id}")
            return None
            
    except requests.RequestException as exc:
        logger.warning(f"Could not fetch gist metadata from API: {exc}. Falling back to direct URL.")
        # Fall back to the standard raw URL format (always points to latest)
        return f"https://gist.githubusercontent.com/{gist_id}/raw/{filename}"
    except Exception as exc:
        logger.warning(f"Unexpected error fetching gist metadata: {exc}")
        return f"https://gist.githubusercontent.com/{gist_id}/raw/{filename}"


def fetch_clickfix_gist(gist_id: str = DEFAULT_CLICKFIX_GIST_ID, filename: str = DEFAULT_CLICKFIX_GIST_FILENAME) -> Tuple[List[str], Optional[str]]:
    """Fetch domain list from the public ClickFix gist feed.

    The gist is a simple pipe-delimited table with one domain per row. The
    function normalizes the entries, deduplicates them, and returns both the
    list of domains and a hash of the raw content to allow change detection.

    Args:
        gist_id: The GitHub Gist ID
        filename: The filename within the gist

    Returns:
        Tuple[List[str], Optional[str]]: unique domain list and optional SHA256 hash.
    """
    try:
        # Get the latest raw URL from the GitHub API
        url = get_latest_gist_url(gist_id, filename)
        
        if not url:
            logger.error("Could not determine gist URL")
            return [], None
        
        logger.info(f"Fetching ClickFix gist feed from {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        raw_text = response.text
        content_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        domains: List[str] = []
        seen: set[str] = set()

        # Parse line by line - handle both plain text and pipe-delimited formats
        for line in raw_text.splitlines():
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
            
            # Skip markdown table headers and separators
            if line.startswith('|') and ('-' in line or 'domain' in line.lower()):
                continue
            
            # Handle pipe-delimited format (| domain |) or plain format
            if line.startswith('|'):
                cleaned = line.strip('|').strip()
            else:
                cleaned = line
            
            if not cleaned:
                continue

            # Domains might include URLs; attempt to normalize
            domain = cleaned
            if domain.startswith("http"):
                try:
                    parsed = urlparse(domain)
                    domain = parsed.netloc or parsed.path
                except Exception:
                    logger.debug(f"Could not parse domain entry '{cleaned}'")
                    continue

            domain = domain.strip()
            if not domain:
                continue

            domain = domain.lower()
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)

        logger.info(f"Fetched {len(domains)} unique domains from ClickFix gist")
        return domains, content_hash

    except requests.RequestException as exc:
        logger.error(f"Error fetching ClickFix gist feed: {exc}")
        return [], None


def load_clickfix_cache(gist_id: str) -> Tuple[Optional[str], List[str]]:
    """Load cached ClickFix gist metadata from disk."""
    if not CLICKFIX_GIST_CACHE_FILE.exists():
        return None, []

    try:
        with CLICKFIX_GIST_CACHE_FILE.open("r", encoding="utf-8") as cache_file:
            data = json.load(cache_file)

        if not isinstance(data, dict):
            return None, []

        cached_gist_id = data.get("gist_id")
        if cached_gist_id and cached_gist_id != gist_id:
            logger.info(f"Cached gist ID {cached_gist_id} differs from requested {gist_id}, ignoring cache")
            return None, []

        cached_hash = data.get("hash")
        cached_domains = data.get("domains") or []

        if not isinstance(cached_domains, list):
            cached_domains = []

        # Deduplicate while preserving order
        deduped_domains = list(dict.fromkeys(str(domain).lower().strip() for domain in cached_domains if domain))
        return cached_hash, deduped_domains

    except Exception as exc:
        logger.warning(f"Could not read ClickFix gist cache: {exc}")
        return None, []


def save_clickfix_cache(hash_value: str, domains: List[str], gist_id: str) -> None:
    """Persist ClickFix gist metadata so future runs can skip unchanged feeds."""
    try:
        CLICKFIX_GIST_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "gist_id": gist_id,
            "hash": hash_value,
            "domains": domains,
            "cached_at": datetime.utcnow().isoformat()
        }
        with CLICKFIX_GIST_CACHE_FILE.open("w", encoding="utf-8") as cache_file:
            json.dump(payload, cache_file, indent=2)
    except Exception as exc:
        logger.warning(f"Failed to write ClickFix gist cache: {exc}")


def build_urls_from_domains(domains: List[str]) -> List[str]:
    """Convert bare domains into full URLs suitable for analysis."""
    urls: List[str] = []
    seen: set[str] = set()

    for domain in domains:
        if not domain:
            continue

        sanitized = sanitize_url(domain.strip())
        if not sanitized:
            continue

        if not sanitized.startswith(("http://", "https://")):
            sanitized = f"https://{sanitized}"

        sanitized = sanitized.rstrip("/")

        if sanitized not in seen:
            seen.add(sanitized)
            urls.append(sanitized)

    return urls


def collect_clickfix_gist_urls(config: ClickGrabConfig) -> List[str]:
    """Return newly observed ClickFix gist domains as URLs."""
    # Use custom gist_id if provided, otherwise use default
    gist_id = config.clickfix_gist_id or DEFAULT_CLICKFIX_GIST_ID
    filename = DEFAULT_CLICKFIX_GIST_FILENAME
    
    logger.info(f"Collecting domains from ClickFix gist ID: {gist_id}")
    domains, new_hash = fetch_clickfix_gist(gist_id, filename)

    if not domains:
        logger.warning("No domains retrieved from ClickFix gist feed")
        return []

    cached_hash, cached_domains = load_clickfix_cache(gist_id)

    if new_hash and cached_hash and new_hash == cached_hash:
        logger.info("ClickFix gist has not changed since the last run. Skipping analysis of cached domains.")
        return []

    cached_domain_set = set(cached_domains)
    new_domains = [domain for domain in domains if domain not in cached_domain_set]

    if not new_domains:
        logger.info("No new ClickFix domains detected compared to cached run.")
    else:
        logger.info(f"Identified {len(new_domains)} new ClickFix domains for analysis")

    if new_hash:
        save_clickfix_cache(new_hash, domains, gist_id)

    if not new_domains:
        return []

    return build_urls_from_domains(new_domains)


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
            tags = ['FakeCaptcha', 'ClickFix', 'click', 'fakecloudflarecaptcha']
        
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
    
    # Create base analysis result
    result = AnalysisResult(
        URL=url,
        RawHTML=""
    )
    
    # Get HTML content
    html_content = get_html_content(url)
    if not html_content:
        logger.error(f"Failed to retrieve content from {url}")
        # Still return a result with empty content and failed status
        result.RawHTML = "ERROR: Failed to retrieve content"
        result.SuspiciousKeywords = ["failed_to_retrieve"]
        # Mark as non-suspicious since we couldn't analyze it
        return result
    
    # Update with actual content
    result.RawHTML = html_content
    
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
        
        # Clipboard Manipulation (truncated for HTML display)
        if result.ClipboardManipulation:
            max_items = 5
            max_length = 1000
            displayed_items = result.ClipboardManipulation[:max_items]
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Clipboard Manipulation (showing {len(displayed_items)} of {len(result.ClipboardManipulation)})</p>
                <ul>
            """
            for clip in displayed_items:
                truncated_clip = clip[:max_length] + "... [truncated]" if len(clip) > max_length else clip
                html_content += f"<li><pre>{truncated_clip}</pre></li>"
            if len(result.ClipboardManipulation) > max_items:
                html_content += f"<li><em>... and {len(result.ClipboardManipulation) - max_items} more entries (see JSON for full data)</em></li>"
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
        
        # Obfuscated JavaScript (truncated for HTML display)
        if result.ObfuscatedJavaScript:
            max_items = 5
            max_length = 1000
            displayed_items = result.ObfuscatedJavaScript[:max_items]
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Obfuscated JavaScript (showing {len(displayed_items)} of {len(result.ObfuscatedJavaScript)})</p>
                <ul>
            """
            for js in displayed_items:
                if isinstance(js, dict) and 'script' in js:
                    script_truncated = js['script'][:max_length] + "... [truncated]" if len(js['script']) > max_length else js['script']
                    html_content += f"<li><pre>{script_truncated}</pre></li>"
                    if 'score' in js:
                        html_content += f"<li><strong>Obfuscation Score:</strong> {js['score']}</li>"
                else:
                    js_truncated = str(js)[:max_length] + "... [truncated]" if len(str(js)) > max_length else js
                    html_content += f"<li><pre>{js_truncated}</pre></li>"
            if len(result.ObfuscatedJavaScript) > max_items:
                html_content += f"<li><em>... and {len(result.ObfuscatedJavaScript) - max_items} more entries (see JSON for full data)</em></li>"
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
        
        # Suspicious Keywords (truncated for HTML display)
        if result.SuspiciousKeywords:
            max_items = 30
            displayed_items = result.SuspiciousKeywords[:max_items]
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Suspicious Keywords (showing {len(displayed_items)} of {len(result.SuspiciousKeywords)})</p>
                <ul>
            """
            for kw in displayed_items:
                html_content += f"<li>{kw}</li>"
            if len(result.SuspiciousKeywords) > max_items:
                html_content += f"<li><em>... and {len(result.SuspiciousKeywords) - max_items} more keywords (see JSON for full data)</em></li>"
            html_content += "</ul></div>"
        
        # URLs (truncated for HTML display)
        if result.URLs:
            max_items = 30
            displayed_items = result.URLs[:max_items]
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">URLs (showing {len(displayed_items)} of {len(result.URLs)})</p>
                <ul>
            """
            for url in displayed_items:
                html_content += f"<li>{url}</li>"
            if len(result.URLs) > max_items:
                html_content += f"<li><em>... and {len(result.URLs) - max_items} more URLs (see JSON for full data)</em></li>"
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
        # Bot Detection (truncated for HTML display)
        if result.BotDetection:
            max_items = 10
            max_length = 500
            displayed_items = result.BotDetection[:max_items]
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Bot Detection and Sandbox Evasion (showing {len(displayed_items)} of {len(result.BotDetection)})</p>
                <ul>
            """
            for detection in displayed_items:
                truncated_detection = detection[:max_length] + "... [truncated]" if len(detection) > max_length else detection
                html_content += f"<li><pre>{truncated_detection}</pre></li>"
            if len(result.BotDetection) > max_items:
                html_content += f"<li><em>... and {len(result.BotDetection) - max_items} more entries (see JSON for full data)</em></li>"
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
            
        # Proxy Evasion (truncated for HTML display)
        if result.ProxyEvasion:
            max_items = 10
            max_length = 500
            displayed_items = result.ProxyEvasion[:max_items]
            html_content += f"""
            <div class="indicator">
                <p class="indicator-title">Proxy/Security Tool Evasion (showing {len(displayed_items)} of {len(result.ProxyEvasion)})</p>
                <ul>
            """
            for evasion in displayed_items:
                truncated_evasion = evasion[:max_length] + "... [truncated]" if len(evasion) > max_length else evasion
                html_content += f"<li><pre>{truncated_evasion}</pre></li>"
            if len(result.ProxyEvasion) > max_items:
                html_content += f"<li><em>... and {len(result.ProxyEvasion) - max_items} more entries (see JSON for full data)</em></li>"
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
    parser.add_argument("--clickfix-gist", action="store_true", help="Pull domains from the public ClickFix gist feed")
    parser.add_argument("--clickfix-gist-id", default=None, help=f"Override GitHub Gist ID for the ClickFix feed (default: {DEFAULT_CLICKFIX_GIST_ID})")
    
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
    if config.download or config.otx or config.clickfix_gist:
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

        # Pull domains from ClickFix gist if requested
        if config.clickfix_gist:
            logger.info("Fetching domains from ClickFix gist feed")
            gist_urls = collect_clickfix_gist_urls(config)
            if gist_urls:
                logger.info(f"Queued {len(gist_urls)} URLs from ClickFix gist for analysis")
                urls.extend(gist_urls)
        
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
                results.append(result)
        else:
            # Single URL analysis
            result = analyze_url(config.analyze)
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