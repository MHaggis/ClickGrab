#!/usr/bin/env python3
"""
ClickGrab Threat Analysis Tool

A professional tool for analyzing ClickGrab threat intelligence reports,
identifying malicious patterns, and generating comprehensive analysis reports.
"""

import argparse
import json
import logging
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelligence:
    """Container for threat intelligence data extracted from reports."""
    
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    powershell_commands: List[str] = field(default_factory=list)
    clipboard_manipulations: List[str] = field(default_factory=list)
    suspicious_keywords: List[str] = field(default_factory=list)
    powershell_downloads: List[Dict] = field(default_factory=list)
    captcha_elements: List[str] = field(default_factory=list)
    html_content: List[str] = field(default_factory=list)
    malicious_sites: List[Dict] = field(default_factory=list)
    
    def add_site_data(self, site: Dict) -> None:
        """Extract and add data from a single site."""
        if not site:
            return
            
        # Extract URLs
        urls = self._normalize_urls(site.get("URLs", site.get("Urls", [])))
        self.urls.extend(urls)
        
        # Extract domains
        for url in urls:
            try:
                domain = urlparse(url).netloc
                if domain:
                    self.domains.append(domain)
            except Exception as e:
                logger.debug(f"Failed to parse URL {url}: {e}")
        
        # Extract PowerShell commands
        ps_commands = site.get("PowerShellCommands", site.get("PowershellCommands"))
        if ps_commands:
            if isinstance(ps_commands, list):
                self.powershell_commands.extend(ps_commands)
            else:
                self.powershell_commands.append(ps_commands)
        
        # Extract clipboard manipulation code
        clipboard = site.get("ClipboardManipulation", site.get("Clipboardmanipulation", []))
        if clipboard and isinstance(clipboard, list):
            self.clipboard_manipulations.extend(clipboard)
        
        # Extract suspicious keywords
        keywords = site.get("SuspiciousKeywords", site.get("Suspiciouskeywords", []))
        if keywords and isinstance(keywords, list):
            self.suspicious_keywords.extend(keywords)
        
        # Extract PowerShell downloads
        ps_downloads = site.get("PowerShellDownloads", site.get("PowershellDownloads"))
        if ps_downloads:
            if isinstance(ps_downloads, list):
                self.powershell_downloads.extend(ps_downloads)
            elif isinstance(ps_downloads, dict):
                self.powershell_downloads.append(ps_downloads)
        
        # Extract CAPTCHA elements
        captcha = site.get("CaptchaElements", [])
        if captcha and isinstance(captcha, list):
            self.captcha_elements.extend(captcha)
        
        # Extract HTML content
        html = site.get("HTML", site.get("Html", ""))
        if html and len(html) > 0:
            self.html_content.append(html)
        
        # Check if site has malicious indicators
        if self._is_malicious_site(site):
            self.malicious_sites.append(site)
    
    def _normalize_urls(self, urls: Union[str, List[str], None]) -> List[str]:
        """Normalize URLs to a consistent list format."""
        if not urls:
            return []
        if isinstance(urls, str):
            return [urls]
        if isinstance(urls, list):
            return urls
        return []
    
    def _is_malicious_site(self, site: Dict) -> bool:
        """Determine if a site contains malicious indicators."""
        malicious_indicators = [
            "PowerShellDownloads", "PowershellDownloads",
            "ClipboardManipulation", "Clipboardmanipulation",
            "PowerShellCommands", "PowershellCommands"
        ]
        return any(
            site.get(indicator) for indicator in malicious_indicators
        )


class PatternAnalyzer:
    """Analyzer for identifying patterns in threat intelligence data."""
    
    @staticmethod
    def analyze_url_patterns(urls: List[str]) -> Dict[str, Counter]:
        """Analyze patterns in URL data."""
        patterns = {
            "reCAPTCHA imagery": Counter([
                url for url in urls 
                if "recaptcha" in url.lower() or "captcha" in url.lower()
            ]),
            "Font resources": Counter([
                url for url in urls 
                if "font" in url.lower() or ".woff" in url.lower()
            ]),
            "CDN hosted scripts": Counter([
                url for url in urls 
                if "cdn" in url.lower() or "jsdelivr" in url.lower()
            ]),
            "Google resources": Counter([
                url for url in urls 
                if "google" in url.lower()
            ]),
        }
        return patterns
    
    @staticmethod
    def analyze_clipboard_patterns(clipboard_code: List[str]) -> Dict[str, Tuple[int, List[str]]]:
        """Analyze clipboard manipulation patterns."""
        patterns = {
            "document.execCommand copy": r'document\.execCommand\s*\(\s*[\'"]copy[\'"]',
            "textarea manipulation": r'document\.createElement\s*\(\s*[\'"]textarea[\'"]|textarea\.select\(\)|select\(\)|document\.body\.append\s*\(\s*tempTextArea',
        }
        
        results = {}
        for pattern_name, regex in patterns.items():
            matches = 0
            matching_snippets = []
            
            for code_snippet in clipboard_code:
                if re.search(regex, code_snippet, re.IGNORECASE | re.DOTALL):
                    matches += 1
                    relevant_part = re.search(
                        r'([^\n;]{0,50}' + regex + r'[^\n;]{0,100})', 
                        code_snippet, 
                        re.IGNORECASE | re.DOTALL
                    )
                    if relevant_part and len(relevant_part.group(0)) > 20:
                        matching_snippets.append(relevant_part.group(0).strip())
            
            results[pattern_name] = (matches, list(set(matching_snippets)))
        
        return results
    
    @staticmethod
    def extract_complete_functions(clipboard_code: List[str]) -> List[str]:
        """Extract complete JavaScript functions from clipboard code."""
        functions = []
        for code in clipboard_code:
            function_matches = re.findall(
                r'(function\s+\w+\s*\([^)]*\)\s*\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\})', 
                code, 
                re.DOTALL
            )
            for func in function_matches:
                if len(func) > 30 and any(keyword in func for keyword in ["copy", "clipboard", "textarea"]):
                    functions.append(func.strip())
        
        return list(set(functions))
    
    @staticmethod
    def extract_malicious_commands(ps_downloads: List[Dict]) -> List[Tuple[str, str]]:
        """Extract malicious commands and their contexts."""
        command_pattern = r'const\s+commandToRun\s*=\s*[\'"](.*?)[\'"]|var\s+commandToRun\s*=\s*[\'"](.*?)[\'"]|commandToRun\s*=\s*[\'"](.*?)[\'"]|commandToRun\s*=\s*`(.*?)`'
        
        commands = []
        for download in ps_downloads:
            context = download.get("Context", "")
            if not context:
                continue
                
            matches = re.findall(command_pattern, context, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if isinstance(match, tuple):
                    cmd = ''.join([part for part in match if part])
                    if cmd:
                        # Extract surrounding context
                        surrounding = re.search(
                            r'(.{0,100}' + re.escape(cmd) + r'.{0,100})', 
                            context, 
                            re.DOTALL
                        )
                        context_snippet = (
                            surrounding.group(1) if surrounding 
                            else context[:200] if len(context) > 200 else context
                        )
                        commands.append((cmd, context_snippet))
        
        return commands
    
    @staticmethod
    def analyze_keyword_patterns(keywords: List[str]) -> Dict[str, any]:
        """Analyze suspicious keyword patterns using fuzzy matching and clustering."""
        if not keywords:
            return {}
        
        # Clean and normalize keywords
        normalized_keywords = [kw.strip() for kw in keywords if kw and kw.strip()]
        
        # Categorize keywords by type
        categories = {
            "Social Engineering": [],
            "Obfuscation Indicators": [],
            "System Commands": [],
            "Verification Text": [],
            "JavaScript Functions": [],
            "Symbols & Emojis": [],
            "Technical Terms": []
        }
        
        # Keyword classification patterns
        social_patterns = [
            r"robot", r"captcha", r"verification", r"prove", r"human", r"security",
            r"check", r"confirm", r"validate", r"authentic"
        ]
        
        obfuscation_patterns = [
            r"_0x[0-9a-fA-F]+", r"atob\s*\(", r"document\.write", r"eval\s*\(",
            r"fromCharCode", r"\\x[0-9a-fA-F]+", r"[A-Za-z0-9+/]{20,}={0,2}"  # Base64-like
        ]
        
        system_patterns = [
            r"command", r"powershell", r"cmd", r"exec", r"shell", r"process",
            r"script", r"run", r"invoke"
        ]
        
        verification_patterns = [
            r"✅", r"checkmark", r"hash", r"id", r"success", r"complete", 
            r"verified", r"passed"
        ]
        
        js_function_patterns = [
            r"function", r"document\.", r"window\.", r"addEventListener",
            r"getElementById", r"createElement", r"appendChild"
        ]
        
        # Classify keywords
        for keyword in normalized_keywords:
            keyword_lower = keyword.lower()
            
            if any(re.search(pattern, keyword_lower) for pattern in social_patterns):
                categories["Social Engineering"].append(keyword)
            elif any(re.search(pattern, keyword) for pattern in obfuscation_patterns):
                categories["Obfuscation Indicators"].append(keyword)
            elif any(re.search(pattern, keyword_lower) for pattern in system_patterns):
                categories["System Commands"].append(keyword)
            elif any(re.search(pattern, keyword) for pattern in verification_patterns):
                categories["Verification Text"].append(keyword)
            elif any(re.search(pattern, keyword_lower) for pattern in js_function_patterns):
                categories["JavaScript Functions"].append(keyword)
            elif re.search(r'^[^\w\s]+$', keyword):  # Only symbols/emojis
                categories["Symbols & Emojis"].append(keyword)
            else:
                categories["Technical Terms"].append(keyword)
        
        # Find fuzzy similar keywords
        similar_groups = PatternAnalyzer._find_similar_keywords(normalized_keywords)
        
        # Count frequency
        keyword_counts = Counter(normalized_keywords)
        
        return {
            "categories": {k: list(set(v)) for k, v in categories.items() if v},
            "similar_groups": similar_groups,
            "frequency": keyword_counts.most_common(20),
            "total_unique": len(set(normalized_keywords)),
            "total_count": len(normalized_keywords)
        }
    
    @staticmethod
    def _find_similar_keywords(keywords: List[str], threshold: float = 0.7) -> List[List[str]]:
        """Find groups of similar keywords using fuzzy matching."""
        if not keywords:
            return []
            
        groups = []
        used = set()
        
        for i, keyword in enumerate(keywords):
            if keyword in used:
                continue
                
            group = [keyword]
            used.add(keyword)
            
            for j, other in enumerate(keywords[i+1:], i+1):
                if other in used:
                    continue
                    
                similarity = SequenceMatcher(None, keyword.lower(), other.lower()).ratio()
                if similarity >= threshold:
                    group.append(other)
                    used.add(other)
            
            if len(group) > 1:
                groups.append(group)
        
        return groups
    
    @staticmethod
    def analyze_obfuscation_techniques(captcha_elements: List[str], keywords: List[str]) -> Dict[str, any]:
        """Analyze JavaScript obfuscation techniques used in malicious code."""
        if not captcha_elements:
            return {}
        
        all_code = " ".join(captcha_elements) + " ".join(keywords)
        
        techniques = {
            "Hexadecimal Variables": {
                "pattern": r"_0x[0-9a-fA-F]+",
                "matches": [],
                "description": "Variables using hexadecimal naming convention"
            },
            "Base64 Encoding": {
                "pattern": r"atob\s*\(\s*['\"]?([A-Za-z0-9+/]{10,}={0,2})['\"]?\s*\)",
                "matches": [],
                "description": "Base64 encoded strings being decoded"
            },
            "Array Obfuscation": {
                "pattern": r"var\s+_0x[0-9a-fA-F]+\s*=\s*\[[^\]]+\]",
                "matches": [],
                "description": "Obfuscated arrays with hex variable names"
            },
            "Dynamic Property Access": {
                "pattern": r"\[['\"]([^'\"]+)['\"]\]",
                "matches": [],
                "description": "Dynamic property access to hide function names"
            },
            "String Concatenation": {
                "pattern": r"['\"][^'\"]*['\"]\s*\+\s*['\"][^'\"]*['\"]",
                "matches": [],
                "description": "String splitting to avoid detection"
            },
            "Character Code Manipulation": {
                "pattern": r"fromCharCode|charCodeAt",
                "matches": [],
                "description": "Character code manipulation for obfuscation"
            },
            "Document Write": {
                "pattern": r"document\.write\s*\(",
                "matches": [],
                "description": "Dynamic code injection via document.write"
            }
        }
        
        for technique_name, info in techniques.items():
            matches = re.findall(info["pattern"], all_code, re.IGNORECASE | re.DOTALL)
            if matches:
                techniques[technique_name]["matches"] = list(set(matches))[:10]  # Limit examples
                techniques[technique_name]["count"] = len(matches)
        
        # Extract specific obfuscated patterns
        hex_vars = re.findall(r"_0x[0-9a-fA-F]+", all_code)
        base64_strings = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", all_code)
        
        return {
            "techniques": {k: v for k, v in techniques.items() if v.get("matches")},
            "hex_variables": list(set(hex_vars))[:15],
            "base64_strings": list(set(base64_strings))[:10],
            "obfuscation_score": len([t for t in techniques.values() if t.get("matches")])
        }
    
    @staticmethod
    def analyze_clipboard_attack_flow(clipboard_manipulations: List[str], captcha_elements: List[str]) -> Dict[str, any]:
        """Analyze the complete clipboard attack flow and techniques."""
        if not clipboard_manipulations:
            return {}
        
        all_code = " ".join(clipboard_manipulations + captcha_elements)
        
        # Attack flow components
        flow_components = {
            "Element Creation": {
                "patterns": [r"createElement\s*\(\s*['\"]textarea['\"]", r"createElement\s*\(\s*['\"]input['\"]"],
                "description": "Creating temporary DOM elements"
            },
            "Content Injection": {
                "patterns": [r"\.value\s*=", r"\.innerHTML\s*=", r"\.textContent\s*="],
                "description": "Injecting malicious content into elements"
            },
            "DOM Manipulation": {
                "patterns": [r"appendChild", r"append\s*\(", r"insertBefore", r"body\.append"],
                "description": "Adding elements to the DOM"
            },
            "Selection Methods": {
                "patterns": [r"\.select\s*\(\)", r"selectAllChildren", r"setSelectionRange"],
                "description": "Selecting content for copying"
            },
            "Clipboard Operations": {
                "patterns": [r"execCommand\s*\(\s*['\"]copy['\"]", r"navigator\.clipboard"],
                "description": "Executing clipboard copy operations"
            },
            "Cleanup Operations": {
                "patterns": [r"removeChild", r"remove\s*\(\)", r"parentNode\.removeChild"],
                "description": "Removing temporary elements"
            },
            "Event Handling": {
                "patterns": [r"addEventListener", r"onclick\s*=", r"\.click\s*\("],
                "description": "Handling user interactions"
            }
        }
        
        detected_components = {}
        for component, info in flow_components.items():
            matches = []
            for pattern in info["patterns"]:
                found = re.findall(pattern, all_code, re.IGNORECASE)
                matches.extend(found)
            
            if matches:
                detected_components[component] = {
                    "count": len(matches),
                    "description": info["description"],
                    "examples": list(set(matches))[:5]
                }
        
        # Analyze clipboard payload construction
        payload_patterns = {
            "Command Concatenation": r"commandToRun\s*\+",
            "Verification Text": r"['\"]✅[^'\"]*['\"]|['\"].*robot.*['\"]",
            "Hash Generation": r"verification.*id|hash.*[0-9]+",
            "Comment Injection": r"#\s*['\"][^'\"]*['\"]"
        }
        
        payload_analysis = {}
        for pattern_name, pattern in payload_patterns.items():
            matches = re.findall(pattern, all_code, re.IGNORECASE | re.DOTALL)
            if matches:
                payload_analysis[pattern_name] = {
                    "count": len(matches),
                    "examples": list(set(matches))[:3]
                }
        
        return {
            "flow_components": detected_components,
            "payload_construction": payload_analysis,
            "attack_sophistication": len(detected_components),
            "total_techniques": sum(comp["count"] for comp in detected_components.values())
        }


class ReportGenerator:
    """Generates comprehensive threat analysis reports."""
    
    def __init__(self, output_dir: Path = Path("analysis")):
        self.output_dir = output_dir
        self.output_dir.mkdir(exist_ok=True)
    
    def generate_blog_post_data(self, threat_data: ThreatIntelligence, report_date: str, 
                               total_sites: int) -> Dict:
        """Generate structured data for blog post template."""
        malicious_percentage = (len(threat_data.malicious_sites) / total_sites) * 100 if total_sites > 0 else 0
        
        # Extract key statistics for the blog post
        obfuscation_analysis = PatternAnalyzer.analyze_obfuscation_techniques(
            threat_data.captcha_elements, 
            threat_data.suspicious_keywords
        )
        
        flow_analysis = PatternAnalyzer.analyze_clipboard_attack_flow(
            threat_data.clipboard_manipulations,
            threat_data.captcha_elements
        )
        
        keyword_analysis = PatternAnalyzer.analyze_keyword_patterns(threat_data.suspicious_keywords)
        
        # Determine the main focus of this analysis
        if len(threat_data.clipboard_manipulations) > 10:
            category = "Clipboard Hijacking Analysis"
            tags = ["Clipboard Hijacking", "Fake CAPTCHA", "Social Engineering", "JavaScript", "PowerShell"]
        elif len(threat_data.powershell_downloads) > 5:
            category = "PowerShell Attack Analysis"
            tags = ["PowerShell", "Malware Distribution", "Command Injection", "Download Attacks"]
        else:
            category = "Threat Analysis"
            tags = ["URL Analysis", "Threat Intelligence", "Malicious Domains"]
        
        # Add obfuscation tags if detected
        if obfuscation_analysis.get("obfuscation_score", 0) > 2:
            tags.append("JavaScript Obfuscation")
        
        # Generate title based on content
        if malicious_percentage > 70:
            severity = "Critical"
        elif malicious_percentage > 40:
            severity = "High-Impact" 
        else:
            severity = "Emerging"
        
        title = f"{severity} ClickGrab Campaign: Advanced Analysis of {report_date} Attack Patterns"
        
        # Generate excerpt
        excerpt = (f"Comprehensive analysis of {total_sites} sites reveals {malicious_percentage:.1f}% "
                  f"malicious rate with {len(threat_data.powershell_downloads)} PowerShell attack attempts "
                  f"and {len(threat_data.clipboard_manipulations)} clipboard hijacking instances.")
        
        # Create slug for URL
        slug = f"clickgrab-analysis-{report_date}"
        
        blog_data = {
            "title": title,
            "date": report_date,
            "category": category,
            "excerpt": excerpt,
            "slug": slug,
            "tags": tags,
            "read_time": 12,  # Estimated reading time
            "stats": {
                "sites_analyzed": total_sites,
                "malicious_rate": round(malicious_percentage),
                "attack_patterns": len(threat_data.urls),
                "powershell_downloads": len(threat_data.powershell_downloads),
                "clipboard_manipulations": len(threat_data.clipboard_manipulations),
                "obfuscation_score": obfuscation_analysis.get("obfuscation_score", 0),
                "attack_sophistication": flow_analysis.get("attack_sophistication", 0)
            },
            "analysis_data": {
                "obfuscation_analysis": obfuscation_analysis,
                "flow_analysis": flow_analysis,
                "keyword_analysis": keyword_analysis,
                "domain_counts": Counter(threat_data.domains).most_common(10),
                "url_patterns": PatternAnalyzer.analyze_url_patterns(threat_data.urls)
            }
        }
        
        return blog_data
    
    def generate_report(self, threat_data: ThreatIntelligence, report_date: str, 
                       total_sites: int) -> Path:
        """Generate a comprehensive markdown report."""
        output_file = self.output_dir / f"report_{report_date}.md"
        
        with open(output_file, "w", encoding='utf-8') as f:
            self._write_header(f, report_date)
            self._write_statistics(f, threat_data, total_sites)
            self._write_domain_analysis(f, threat_data)
            self._write_pattern_analysis(f, threat_data)
            self._write_keyword_analysis(f, threat_data)
            self._write_obfuscation_analysis(f, threat_data)
            self._write_clipboard_analysis(f, threat_data)
            self._write_attack_flow_analysis(f, threat_data)
            self._write_attack_reconstruction(f, threat_data)
            self._write_conclusion(f, threat_data, total_sites)
        
        # Also generate structured blog post data
        blog_data = self.generate_blog_post_data(threat_data, report_date, total_sites)
        blog_data_file = self.output_dir / f"blog_data_{report_date}.json"
        
        with open(blog_data_file, "w", encoding='utf-8') as f:
            import json
            json.dump(blog_data, f, indent=2, default=str)
        
        self._create_latest_link(output_file)
        
        # Create latest blog data link
        latest_blog_data = self.output_dir / "latest_blog_data.json"
        try:
            if latest_blog_data.exists():
                latest_blog_data.unlink()
            
            try:
                latest_blog_data.symlink_to(blog_data_file.name)
            except (OSError, AttributeError):
                import shutil
                shutil.copy2(blog_data_file, latest_blog_data)
            
            logger.info(f"Created latest blog data link at {latest_blog_data}")
        except Exception as e:
            logger.warning(f"Could not create latest blog data link: {e}")
        
        return output_file
    
    def _write_header(self, f, report_date: str) -> None:
        """Write report header."""
        f.write(f"# ClickGrab Threat Analysis Report - {report_date}\n\n")
        f.write(f"*Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
    
    def _write_statistics(self, f, threat_data: ThreatIntelligence, total_sites: int) -> None:
        """Write key statistics section."""
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total sites analyzed**: {total_sites:,}\n")
        f.write(f"- **Sites with malicious content**: {len(threat_data.malicious_sites):,}\n")
        f.write(f"- **Unique domains encountered**: {len(set(threat_data.domains)):,}\n")
        f.write(f"- **Total URLs extracted**: {len(threat_data.urls):,}\n")
        f.write(f"- **PowerShell download attempts**: {len(threat_data.powershell_downloads):,}\n")
        f.write(f"- **Clipboard manipulation instances**: {len(threat_data.clipboard_manipulations):,}\n\n")
    
    def _write_domain_analysis(self, f, threat_data: ThreatIntelligence) -> None:
        """Write domain analysis section."""
        f.write("## Domain Analysis\n\n")
        
        domain_counts = Counter(threat_data.domains)
        f.write("### Most Frequently Encountered Domains\n\n")
        
        for domain, count in domain_counts.most_common(15):
            f.write(f"- **{domain}**: {count:,} occurrences\n")
        
        f.write("\n")
    
    def _write_pattern_analysis(self, f, threat_data: ThreatIntelligence) -> None:
        """Write pattern analysis section."""
        f.write("## URL Pattern Analysis\n\n")
        
        patterns = PatternAnalyzer.analyze_url_patterns(threat_data.urls)
        
        for pattern_name, url_counter in patterns.items():
            if url_counter:
                total_urls = sum(url_counter.values())
                unique_urls = len(url_counter)
                f.write(f"### {pattern_name}\n")
                f.write(f"*{total_urls:,} occurrences across {unique_urls:,} distinct URLs*\n\n")
                
                for url, count in url_counter.most_common(5):
                    f.write(f"- `{url}` ({count:,} times)\n")
                
                if len(url_counter) > 5:
                    f.write(f"- *...and {len(url_counter) - 5:,} more distinct URLs*\n")
                f.write("\n")
    
    def _write_keyword_analysis(self, f, threat_data: ThreatIntelligence) -> None:
        """Write suspicious keyword analysis."""
        if not threat_data.suspicious_keywords:
            return
            
        f.write("## Suspicious Keyword Analysis\n\n")
        
        keyword_analysis = PatternAnalyzer.analyze_keyword_patterns(threat_data.suspicious_keywords)
        
        f.write(f"**Total Keywords Found**: {keyword_analysis.get('total_count', 0):,} ({keyword_analysis.get('total_unique', 0):,} unique)\n\n")
        
        # Categories
        categories = keyword_analysis.get("categories", {})
        if categories:
            f.write("### Keyword Categories\n\n")
            for category, keywords in categories.items():
                if keywords:
                    f.write(f"#### {category}\n")
                    f.write(f"*{len(keywords)} unique keywords*\n\n")
                    for keyword in keywords[:10]:  # Show top 10
                        f.write(f"- `{keyword}`\n")
                    if len(keywords) > 10:
                        f.write(f"- *...and {len(keywords) - 10} more*\n")
                    f.write("\n")
        
        # Frequency analysis
        frequency = keyword_analysis.get("frequency", [])
        if frequency:
            f.write("### Most Frequent Keywords\n\n")
            for keyword, count in frequency[:15]:
                f.write(f"- **{keyword}**: {count:,} occurrences\n")
            f.write("\n")
        
        # Similar keyword groups
        similar_groups = keyword_analysis.get("similar_groups", [])
        if similar_groups:
            f.write("### Similar Keyword Patterns\n\n")
            f.write("*Groups of keywords that appear to be variations of the same theme:*\n\n")
            for i, group in enumerate(similar_groups[:5], 1):
                f.write(f"**Group {i}**: {', '.join(f'`{kw}`' for kw in group)}\n\n")
    
    def _write_obfuscation_analysis(self, f, threat_data: ThreatIntelligence) -> None:
        """Write JavaScript obfuscation analysis."""
        if not threat_data.captcha_elements:
            return
            
        f.write("## JavaScript Obfuscation Analysis\n\n")
        
        obfuscation_analysis = PatternAnalyzer.analyze_obfuscation_techniques(
            threat_data.captcha_elements, 
            threat_data.suspicious_keywords
        )
        
        obfuscation_score = obfuscation_analysis.get("obfuscation_score", 0)
        f.write(f"**Obfuscation Sophistication Score**: {obfuscation_score}/7\n\n")
        
        techniques = obfuscation_analysis.get("techniques", {})
        if techniques:
            f.write("### Detected Obfuscation Techniques\n\n")
            for technique, info in techniques.items():
                f.write(f"#### {technique}\n")
                f.write(f"*{info['description']}*\n\n")
                f.write(f"**Instances Found**: {info.get('count', len(info['matches'])):,}\n\n")
                
                if info['matches']:
                    f.write("**Examples:**\n")
                    for example in info['matches'][:5]:
                        f.write(f"- `{example}`\n")
                    f.write("\n")
        
        # Hexadecimal variables
        hex_vars = obfuscation_analysis.get("hex_variables", [])
        if hex_vars:
            f.write("### Hexadecimal Variable Names\n\n")
            f.write("*These obfuscated variable names are commonly used to hide malicious functionality:*\n\n")
            for var in hex_vars[:10]:
                f.write(f"- `{var}`\n")
            if len(hex_vars) > 10:
                f.write(f"- *...and {len(hex_vars) - 10} more*\n")
            f.write("\n")
        
        # Base64 strings
        base64_strings = obfuscation_analysis.get("base64_strings", [])
        if base64_strings:
            f.write("### Potential Base64 Encoded Content\n\n")
            f.write("*These strings may contain encoded malicious payloads:*\n\n")
            for b64 in base64_strings[:5]:
                f.write(f"- `{b64[:50]}{'...' if len(b64) > 50 else ''}`\n")
            f.write("\n")
    
    def _write_attack_flow_analysis(self, f, threat_data: ThreatIntelligence) -> None:
        """Write detailed clipboard attack flow analysis."""
        if not threat_data.clipboard_manipulations:
            return
            
        f.write("## Clipboard Attack Flow Analysis\n\n")
        
        flow_analysis = PatternAnalyzer.analyze_clipboard_attack_flow(
            threat_data.clipboard_manipulations,
            threat_data.captcha_elements
        )
        
        sophistication = flow_analysis.get("attack_sophistication", 0)
        total_techniques = flow_analysis.get("total_techniques", 0)
        
        f.write(f"**Attack Sophistication**: {sophistication}/7 components detected\n")
        f.write(f"**Total Technique Instances**: {total_techniques:,}\n\n")
        
        # Flow components
        flow_components = flow_analysis.get("flow_components", {})
        if flow_components:
            f.write("### Attack Flow Components\n\n")
            f.write("*The following components show how the clipboard attack is executed:*\n\n")
            
            for component, info in flow_components.items():
                f.write(f"#### {component}\n")
                f.write(f"*{info['description']}*\n\n")
                f.write(f"**Instances**: {info['count']:,}\n")
                
                if info.get('examples'):
                    f.write("**Examples**: ")
                    f.write(", ".join(f"`{ex}`" for ex in info['examples'][:3]))
                    f.write("\n\n")
        
        # Payload construction
        payload_construction = flow_analysis.get("payload_construction", {})
        if payload_construction:
            f.write("### Malicious Payload Construction\n\n")
            f.write("*How the final clipboard payload is assembled:*\n\n")
            
            for technique, info in payload_construction.items():
                f.write(f"#### {technique}\n")
                f.write(f"**Instances**: {info['count']:,}\n")
                
                if info.get('examples'):
                    f.write("**Examples:**\n")
                    for example in info['examples']:
                        f.write(f"- `{example}`\n")
                    f.write("\n")
    
    def _write_clipboard_analysis(self, f, threat_data: ThreatIntelligence) -> None:
        """Write clipboard manipulation analysis."""
        if not threat_data.clipboard_manipulations:
            return
            
        f.write("## Clipboard Manipulation Analysis\n\n")
        f.write(f"Detected clipboard manipulation in **{len(threat_data.clipboard_manipulations):,}** instances.\n\n")
        
        # Analyze patterns
        patterns = PatternAnalyzer.analyze_clipboard_patterns(threat_data.clipboard_manipulations)
        
        for pattern_name, (matches, snippets) in patterns.items():
            if matches > 0:
                percentage = (matches / len(threat_data.clipboard_manipulations)) * 100
                f.write(f"### {pattern_name.title()}\n")
                f.write(f"Found in **{matches:,}** snippets ({percentage:.1f}% of clipboard code)\n\n")
                
                if snippets:
                    f.write("**Examples:**\n\n")
                    for i, snippet in enumerate(snippets[:3]):
                        f.write(f"```javascript\n{snippet}\n```\n\n")
        
        # Complete functions
        complete_functions = PatternAnalyzer.extract_complete_functions(threat_data.clipboard_manipulations)
        if complete_functions:
            f.write("### Complete Malicious Functions\n\n")
            for i, func in enumerate(complete_functions[:3]):
                f.write(f"**Function {i+1}:**\n")
                f.write(f"```javascript\n{func}\n```\n\n")
    
    def _write_attack_reconstruction(self, f, threat_data: ThreatIntelligence) -> None:
        """Write attack pattern reconstruction."""
        f.write("## Attack Pattern Reconstruction\n\n")
        
        malicious_commands = PatternAnalyzer.extract_malicious_commands(threat_data.powershell_downloads)
        
        if malicious_commands:
            f.write("### Malicious Command Analysis\n\n")
            f.write(f"Identified **{len(malicious_commands):,}** malicious command preparations.\n\n")
            
            for i, (cmd, context) in enumerate(malicious_commands[:5]):
                f.write(f"**Command {i+1}:**\n")
                f.write(f"```powershell\n{cmd}\n```\n\n")
                f.write(f"**Context:**\n")
                f.write(f"```javascript\n{context}\n```\n\n")
        
        # Extract download URLs
        download_urls = set()
        for download in threat_data.powershell_downloads:
            url = download.get("URL")
            if url:
                download_urls.add(url)
        
        if download_urls:
            f.write("### Malicious Download Sources\n\n")
            for url in sorted(download_urls):
                f.write(f"- `{url}`\n")
            f.write("\n")
    
    def _write_conclusion(self, f, threat_data: ThreatIntelligence, total_sites: int) -> None:
        """Write conclusion section."""
        f.write("## Key Findings\n\n")
        
        malicious_percentage = (len(threat_data.malicious_sites) / total_sites) * 100 if total_sites > 0 else 0
        
        f.write(f"1. **Prevalence**: {malicious_percentage:.1f}% of analyzed sites contained malicious content\n")
        f.write(f"2. **Primary Attack Vector**: Fake CAPTCHA verification leading to clipboard hijacking\n")
        f.write(f"3. **Target Platform**: Windows systems via PowerShell execution\n")
        f.write(f"4. **Social Engineering**: Sophisticated UI mimicking legitimate Google reCAPTCHA\n\n")
        
        f.write("## Recommendations\n\n")
        f.write("1. **User Education**: Warn users about fake CAPTCHA verification schemes\n")
        f.write("2. **Clipboard Monitoring**: Implement clipboard monitoring for suspicious PowerShell commands\n")
        f.write("3. **URL Filtering**: Block known malicious domains identified in this analysis\n")
        f.write("4. **PowerShell Execution Policy**: Restrict PowerShell execution in corporate environments\n\n")
    
    def _create_latest_link(self, output_file: Path) -> None:
        """Create a symlink to the latest report."""
        latest_file = self.output_dir / "latest.md"
        
        try:
            if latest_file.exists():
                latest_file.unlink()
            
            try:
                latest_file.symlink_to(output_file.name)
            except (OSError, AttributeError):
                import shutil
                shutil.copy2(output_file, latest_file)
            
            logger.info(f"Created latest report link at {latest_file}")
        except Exception as e:
            logger.warning(f"Could not create latest report link: {e}")


class ClickGrabAnalyzer:
    """Main analyzer class for ClickGrab threat intelligence reports."""
    
    def __init__(self, reports_dir: Path = Path("nightly_reports"), 
                 output_dir: Path = Path("analysis")):
        self.reports_dir = reports_dir
        self.output_dir = output_dir
        self.report_generator = ReportGenerator(output_dir)
    
    def find_latest_report(self) -> Optional[Path]:
        """Find the most recent report file."""
        if not self.reports_dir.exists():
            logger.error(f"Reports directory not found: {self.reports_dir}")
            return None
        
        json_files = list(self.reports_dir.glob("clickgrab_report_*.json"))
        if not json_files:
            logger.error(f"No report files found in {self.reports_dir}")
            return None
        
        # Sort by modification time, newest first
        latest_file = max(json_files, key=lambda f: f.stat().st_mtime)
        logger.info(f"Found latest report: {latest_file}")
        return latest_file
    
    def find_report_by_date(self, date: str) -> Optional[Path]:
        """Find a report file for a specific date."""
        report_file = self.reports_dir / f"clickgrab_report_{date}.json"
        if report_file.exists():
            return report_file
        
        logger.error(f"Report file not found: {report_file}")
        return None
    
    def load_report_data(self, report_file: Path) -> Optional[Dict]:
        """Load and parse report data from JSON file."""
        try:
            logger.info(f"Loading report data from {report_file}")
            with open(report_file, "r", encoding='utf-8') as f:
                data = json.load(f)
            logger.info(f"Successfully loaded {len(data.get('sites', []))} sites")
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in report file: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load report file: {e}")
            return None
    
    def extract_threat_intelligence(self, data: Dict) -> ThreatIntelligence:
        """Extract threat intelligence from report data."""
        logger.info("Extracting threat intelligence from report data")
        
        threat_data = ThreatIntelligence()
        sites = data.get("sites", [])
        
        for site in sites:
            if site is not None:  # Skip None values
                threat_data.add_site_data(site)
        
        logger.info(f"Extracted data from {len(threat_data.malicious_sites)} malicious sites")
        return threat_data
    
    def analyze_report(self, report_file: Optional[Path] = None, 
                      report_date: Optional[str] = None) -> Optional[Path]:
        """Analyze a threat intelligence report and generate analysis."""
        
        # Determine which report to analyze
        if report_file:
            target_file = report_file
            date = report_file.stem.split('_')[-1]  # Extract date from filename
        elif report_date:
            target_file = self.find_report_by_date(report_date)
            date = report_date
        else:
            target_file = self.find_latest_report()
            if target_file:
                date = target_file.stem.split('_')[-1]
            else:
                return None
        
        if not target_file:
            return None
        
        # Load and analyze data
        data = self.load_report_data(target_file)
        if not data:
            return None
        
        threat_data = self.extract_threat_intelligence(data)
        total_sites = data.get("total_sites_analyzed", len(data.get("sites", [])))
        
        # Generate report
        logger.info("Generating analysis report")
        output_file = self.report_generator.generate_report(threat_data, date, total_sites)
        
        logger.info(f"Analysis complete! Report saved to {output_file}")
        return output_file


def main():
    """Main entry point for the analyzer."""
    parser = argparse.ArgumentParser(
        description="Analyze ClickGrab threat intelligence reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py                    # Analyze latest report
  python analyze.py -d 2025-06-17     # Analyze specific date
  python analyze.py -f report.json    # Analyze specific file
  python analyze.py -v                # Verbose output
        """
    )
    
    parser.add_argument(
        "-d", "--date", 
        help="Report date (YYYY-MM-DD format)"
    )
    parser.add_argument(
        "-f", "--file", 
        type=Path,
        help="Specific report file to analyze"
    )
    parser.add_argument(
        "-o", "--output-dir", 
        type=Path, 
        default=Path("analysis"),
        help="Output directory for analysis reports (default: analysis)"
    )
    parser.add_argument(
        "-r", "--reports-dir", 
        type=Path, 
        default=Path("nightly_reports"),
        help="Directory containing report files (default: nightly_reports)"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize analyzer
    analyzer = ClickGrabAnalyzer(
        reports_dir=args.reports_dir,
        output_dir=args.output_dir
    )
    
    # Run analysis
    try:
        output_file = analyzer.analyze_report(
            report_file=args.file,
            report_date=args.date
        )
        
        if output_file:
            print(f"\n✅ Analysis complete!")
            print(f"📊 Report saved to: {output_file}")
            print(f"🔗 Latest report link: {args.output_dir / 'latest.md'}")
        else:
            print("❌ Analysis failed. Check logs for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n🛑 Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()