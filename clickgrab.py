#!/usr/bin/env python3
"""
ClickGrab URL Analyzer

This script downloads data from URLhaus and filters for ClickFix URLs with specific tags
(such as FakeCaptcha, ClickFix, click). It provides analysis mode to:

- Download HTML content from filtered URLs
- Analyze content for potential threats:
  * Base64 encoded strings (with decoding attempts)
  * Embedded URLs and IP addresses
  * PowerShell commands and download instructions
  * JavaScript clipboard manipulation code
  * Links to potentially malicious files (.ps1, .hta)
  * Suspicious keywords and commands
- Generate detailed HTML and JSON reports with the findings

The script provides extensive filtering options, including tag-based filtering,
date restrictions, and URL pattern matching.

Usage:
    python3 clickgrab.py [options]

Options:
    --test          Run in test mode without opening actual URLs
    --limit N       Limit number of URLs to process
    --tags TAGS     Comma-separated list of tags to filter for (default: "FakeCaptcha,ClickFix,click")
    --debug         Enable debug mode to show extra information
"""

import requests
import csv
import re
import os
import json
import base64
import argparse
from datetime import datetime, timedelta
from urllib.parse import urlparse
import logging
from pathlib import Path
import html


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def extract_base64_strings(text):
    """Extract and decode Base64 strings from text."""
    base64_pattern = r'[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    results = []
    
    # Also look for base64 strings assigned in JavaScript (often used in phishing pages)
    atob_pattern = r'atob\([\'"`]([A-Za-z0-9+/=]+)[\'"`]\)'
    for match in re.finditer(atob_pattern, text, re.DOTALL):
        if match.group(1):
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-8')
                if re.match(r'[\x20-\x7E]{8,}', decoded):  # Check if decoded text is printable
                    results.append({
                        'Base64': match.group(1),
                        'Decoded': decoded,
                        'Context': 'From atob() function'
                    })
            except:
                continue
    
    # Look for document.getElementById("code").value = atob("...") pattern
    code_pattern = r'document\.getElementById\([\'"`]code[\'"`]\)\.value\s*=\s*atob\([\'"`]([A-Za-z0-9+/=]+)[\'"`]\)'
    for match in re.finditer(code_pattern, text, re.DOTALL):
        if match.group(1):
            try:
                decoded = base64.b64decode(match.group(1)).decode('utf-8')
                if re.match(r'[\x20-\x7E]{8,}', decoded):
                    results.append({
                        'Base64': match.group(1),
                        'Decoded': decoded,
                        'Context': 'From code element'
                    })
            except:
                continue
    
    # Look for standard base64 strings
    for match in re.finditer(base64_pattern, text):
        if len(match.group()) > 16: 
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8')
                if re.match(r'[\x20-\x7E]{8,}', decoded):
                    already_added = False
                    for result in results:
                        if result['Base64'] == match.group():
                            already_added = True
                            break
                    
                    if not already_added:
                        results.append({
                            'Base64': match.group(),
                            'Decoded': decoded
                        })
            except:
                continue
    
    return results

def extract_urls(text):
    """Extract URLs from text."""
    url_pattern = r'(https?://[^\s"\'<>\)\(]+)'
    return [match.group() for match in re.finditer(url_pattern, text)]

def extract_powershell_commands(text):
    """Extract PowerShell commands from text."""
    cmd_patterns = [
        r'powershell(?:\.exe)?\s+(?:-\w+\s+)*.*',
        r'iex\s*\(.*\)',
        r'invoke-expression.*?',
        r'invoke-webrequest.*?',
        r'iwr\s+.*?',
        r'wget\s+.*?',
        r'curl\s+.*?',
        r'net\s+use.*?',
        r'new-object\s+.*?',
        r'powershell\s+\-w\s+\d+\s+.*',
        r'powershell\s+-w\s+\d+\s+.*',
        r'const\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'cmd\s+/c\s+start\s+/min\s+powershell.*',
        r'cmd\s*/c\s+start\s+powershell.*',
        r'cmd\s+/c\s+start\s+/min\s+powershell\s+-w\s+H\s+-c.*',
        r'cmd\s+/c\s+.*',
        r'powershell\s+\-encodedcommand',
        r'powershell\s+\-enc',
        r'powershell\s+\-e'
    ]
    
    results = []
    for pattern in cmd_patterns:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            results.extend(match.group() for match in matches if match.group() not in results)
        except re.error:
            continue
    
    base64_strings = extract_base64_strings(text)
    for b64_obj in base64_strings:
        if 'Decoded' in b64_obj:
            decoded_text = b64_obj['Decoded']
            for pattern in cmd_patterns:
                try:
                    matches = re.finditer(pattern, decoded_text, re.IGNORECASE)
                    for match in matches:
                        if match.group() not in results:
                            results.append(match.group())
                except re.error:
                    continue
    
    return results

def extract_ip_addresses(text):
    """Extract IP addresses from text."""
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    return [match.group() for match in re.finditer(ip_pattern, text)]

def extract_clipboard_commands(html_content):
    """Extract clipboard-related commands from HTML/JavaScript."""
    results = []
    
    clipboard_func_pattern = r'function\s+(?:setClipboard|copyToClipboard|stageClipboard).*?\{(.*?)\}'
    func_matches = re.finditer(clipboard_func_pattern, html_content, re.DOTALL)
    
    for match in func_matches:
        func_body = match.group(1)
        var_pattern = r'const\s+(\w+)\s*=\s*[\'"](.+?)[\'"]'
        var_matches = re.finditer(var_pattern, func_body)
        
        vars_dict = {m.group(1): m.group(2) for m in var_matches}
        
        copy_pattern = r'textToCopy\s*=\s*(.+)'
        copy_matches = re.finditer(copy_pattern, func_body)
        
        for copy_match in copy_matches:
            copy_expr = copy_match.group(1).strip()
            if copy_expr in vars_dict:
                results.append(vars_dict[copy_expr])
    
    cmd_pattern = r'const\s+commandToRun\s*=\s*[`\'"](.+?)[`\'"]'
    cmd_matches = re.finditer(cmd_pattern, html_content, re.DOTALL)
    results.extend(match.group(1) for match in cmd_matches)
    
    return results

def extract_suspicious_keywords(text):
    """Extract suspicious keywords and patterns from text."""
    suspicious_patterns = [
        # Command execution patterns
        r'cmd(?:.exe)?\s+(?:/\w+\s+)*.*',
        r'command(?:.com)?\s+(?:/\w+\s+)*.*',
        r'bash\s+-c\s+.*',
        r'sh\s+-c\s+.*',
        r'exec\s+.*',
        r'system\s*\(.*\)',
        r'exec\s*\(.*\)',
        r'eval\s*\(.*\)',
        r'execSync\s*\(.*\)',
        
        # Common malware keywords
        r'bypass',
        r'shellcode',
        r'payload',
        r'exploit',
        r'keylogger',
        r'rootkit',
        r'backdoor',
        r'trojan',
        r'ransomware',
        r'exfiltration',
        r'obfuscated',
        r'encrypted',
        
        # CAPTCHA verification patterns
        r'✓',
        r'✅',
        r'white_check_mark',
        r'I am not a robot',
        r'I am human',
        r'Ray ID',
        r'Verification ID',
        r'Verification Hash',
        r'Human verification complete',
        r'reCAPTCHA Verification',
        r'Verification successful',
        
        # Social engineering phrases
        r'Press Win\+R',
        r'Press Windows\+R',
        r'Copy and paste this code',
        r'To verify you are human',
        r'Type the following command',
        r'To confirm you are not a bot',
        r'Verification session',
        r'Verification token:',
        r'Security verification required',
        r'Anti-bot verification',
        r'Solve this CAPTCHA by',
        r'Complete verification by typing',
        r'Bot detection bypassed',
        r'Human verification complete',
        r'Copy this command to proceed',
        r'Paste in command prompt',
        r'Paste in PowerShell',
        r'Start\s+->?\s+Run',
        r'Press\s+Ctrl\+C\s+to\s+copy',
        r'Press\s+Ctrl\+V\s+to\s+paste',
        
        # More general captcha-related patterns
        r'captcha[a-zA-Z0-9_-]*',
        r'robot(?:OrHuman)?',
        r'verification[a-zA-Z0-9_-]*',
        r'press the key combination',
        
        # Fake CAPTCHA verification keywords
        r'Checking if you are human',
        r'Verify you are human',
        r'Cloudflare verification',
        r'To better prove you are not a robot',
        r'I\'m not a robot',
        r'navigator\.clipboard\.writeText',
        r'const command = ',
        r'powershell -w 1 ',
        
        # Obfuscated JavaScript detection (verified reasonable)
        r'<script[^>]*src=',
        r'<script>',
        r'_0x',
        r'eval\(',
        r'atob\(',
        r'unescape\(',
        r'fromCharCode',
        r'\\x[0-9a-f]{2}',
        r'\\u00[0-9a-f]{2}',
        r'document\.write',
        r'noindex,nofollow',
        r'display:none',
        r'position:absolute;left:-9999px',
        r'createElement\(script\)',
        r'Array\.prototype',
        r'constructor',
        r'window\.location\.replace'
    ]
    
    results = []
    for pattern in suspicious_patterns:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                if match.group() not in results:
                    results.append(match.group())
        except re.error:
            continue
    
    return results

def extract_clipboard_manipulation(html_content):
    """Detect JavaScript clipboard manipulation."""
    results = []
    
    clipboard_patterns = [
        # Standard Clipboard API
        r'navigator\.clipboard\.writeText\s*\(',
        r'document\.execCommand\s*\(\s*[\'"]copy[\'"]',
        r'clipboardData\.setData\s*\(',
        
        # Event listeners
        r'addEventListener\s*\(\s*[\'"]copy[\'"]',
        r'addEventListener\s*\(\s*[\'"]cut[\'"]',
        r'addEventListener\s*\(\s*[\'"]paste[\'"]',
        r'onpaste\s*=',
        r'oncopy\s*=',
        r'oncut\s*=',
        
        # jQuery clipboard
        r'\$\s*\(.*\)\.clipboard\s*\(',
        
        # ClipboardJS
        r'new\s+ClipboardJS',
        r'clipboardjs',
        
        # Event prevention
        r'preventDefault\s*\(\s*\)\s*.*\s*copy',
        r'preventDefault\s*\(\s*\)\s*.*\s*cut',
        r'preventDefault\s*\(\s*\)\s*.*\s*paste',
        r'return\s+false\s*.*\s*copy',
        
        # Selection manipulation
        r'document\.getSelection\s*\(',
        r'window\.getSelection\s*\(',
        r'createRange\s*\(',
        r'selectNodeContents\s*\(',
        r'select\s*\(\s*\)',
        
        # Specific clipboard write patterns in malicious sites
        r'navigator\.clipboard\.writeText\(command\)',
        r'const\s+command\s*=.*?clipboard',
    ]
    
    for pattern in clipboard_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            start = max(0, match.start() - 50)
            end = min(len(html_content), match.end() + 50)
            context = html_content[start:end].strip()
            context = re.sub(r'\s+', ' ', context)
            context = f"...{context}..."
            
            if context not in results:
                results.append(context)
    
    return results

def extract_powershell_downloads(html_content):
    """Extract PowerShell download and execution commands."""
    results = []
    
    download_patterns = [
        r'iwr\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'Invoke-WebRequest\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*Invoke-Expression',
        r'curl\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'wget\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'\(New-Object\s+Net\.WebClient\)\.DownloadString\(["\']?(https?://[^"\'\)\s]+)["\']?\)',
        r'["\']?(https?://[^"\'\)\s]+\.ps1)["\']?',
        r'["\']?(https?://[^"\'\)\s]+\.hta)["\']?',
        r'iwr\s+(https?://[^\s|]+)(?:\|iex)?',
        r'powershell\s+-\w+\s+\d+\s+iwr\s+(https?://[^\s|]+)',
        r'command\s*=\s*["\'\`].*?iwr\s+(https?://[^\s|]+).*?["\`]',
        r'irm\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'Invoke-RestMethod\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*Invoke-Expression',
        r'powershell\s+\-encodedcommand',
        r'powershell\s+\-enc',
        r'powershell\s+\-e'
    ]
    
    for pattern in download_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                url = None
                if len(match.groups()) > 0:
                    url = match.group(1)
                
                context = match.group()[:100] if len(match.group()) > 100 else match.group()
                
                download_info = {
                    'FullMatch': match.group(),
                    'URL': url,
                    'Context': context
                }
                
                results.append(download_info)
        except re.error:
            continue 
    
    hta_path_patterns = [
        r'const\s+htaPath\s*=\s*["\'](.+?\.hta)["\']',
        r'var\s+htaPath\s*=\s*["\'](.+?\.hta)["\']'
    ]
    
    for pattern in hta_path_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if len(match.groups()) > 0:
                    hta_path = match.group(1)
                    
                    hta_info = {
                        'FullMatch': match.group(),
                        'URL': 'N/A (File Path)',
                        'HTAPath': hta_path
                    }
                    
                    results.append(hta_info)
        except re.error:
             continue 

    return results

def extract_captcha_elements(html_content):
    """Extract captcha-related HTML elements and patterns."""
    results = []
    
    # Look for captcha-related HTML elements
    captcha_patterns = [
        # Element IDs - using regex patterns for more flexible matching
        r'id\s*=\s*[\'"]captcha[a-zA-Z0-9_-]*[\'"]',
        r'id\s*=\s*[\'"]robot(?:OrHuman)?[\'"]',
        r'id\s*=\s*[\'"]verification[a-zA-Z0-9_-]*[\'"]',
        r'id\s*=\s*[\'"]step[0-9][\'"]',
        r'id\s*=\s*[\'"]fixit[\'"]',
        r'id\s*=\s*[\'"]prompt[0-9][\'"]',
        r'id\s*=\s*[\'"]code[\'"]',
        r'id\s*=\s*[\'"]retry[\'"]',
        # Suspicious single letter or short IDs - more general pattern
        r'id\s*=\s*[\'"][a-z]{1,2}[\'"]',
        
        # Element classes - using regex patterns for more flexible matching
        r'class\s*=\s*[\'"]captcha[a-zA-Z0-9_-]*[\'"]',
        r'class\s*=\s*[\'"]verification[a-zA-Z0-9_-]*[\'"]',
        r'class\s*=\s*[\'"]modal-[a-zA-Z0-9_-]*[\'"]',
        r'class\s*=\s*[\'"]button[a-zA-Z0-9_-]*[\'"]',
        r'class\s*=\s*[\'"]step[a-zA-Z0-9_-]*[\'"]',
        # Suspicious single letter class names - more general pattern
        r'class\s*=\s*[\'"][a-z]{1,2}[\'"]',
        
        # Function attributes
        r'onclick\s*=\s*[\'"][a-zA-Z]+Click\(\)[\'"]',
        r'onclick\s*=\s*[\'"]location\.reload\(\)[\'"]',
        
        # Script content
        r'function\s+[a-zA-Z]+Click\s*\(',
        r'function\s+hide[a-zA-Z]+\s*\(',
        r'function\s+fallback[a-zA-Z]+\s*\(',
        r'[a-zA-Z]+OperationActive\s*=',
        r'document\.getElementById\([\'"][a-zA-Z0-9_-]+[\'"]',
        
        # Clipboard operations
        r'document\.execCommand\([\'"]copy',
        r'document\.execCommand\([\'"]cut',
        r'document\.execCommand\([\'"]paste',
        r'navigator\.clipboard\.writeText',
        r'select\(\)',
        r'window\.getSelection\(\)',
        
        # Base64 operations commonly used in fake captchas
        r'atob\(',
        r'document\.getElementById\([\'"]code[\'"]\)\.value\s*=\s*atob',
        
        # Fix-it button common in fake captchas
        r'[\'"]fixit[\'"]\.addEventListener\([\'"]click',
        
        # Common fake security headers
        r'Ray ID:',
        r'Performance & security by',
        r'needs to review the security of your connection',
        
        # Cloudflare specific elements commonly faked
        r'cloudflare',
        
        # Suspicious script tags and obfuscation
        r'<script[^>]*src=[\'"][^\'">]*\.txt[\'"]',
        r'<script[^>]*src=[\'"][^\'">]*php\?[^\'">]*[\'"]',
        r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k',
        r'<script>\s*var\s+_0x[a-f0-9]+=',
        r'<script>\s*var\s+[a-z]{1,2}=',
        r'document\.write\s*\(\s*(?:unescape|atob|String\.fromCharCode)',
        r'\\x[0-9a-f]{2}\\x[0-9a-f]{2}',
        r'window\[[\'"][^\'")]{1,3}[\'"]\]',
        r'<meta[^>]*content=[\'"]noindex,nofollow[\'"]',
    ]
    
    for pattern in captcha_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                start = max(0, match.start() - 20)
                end = min(len(html_content), match.end() + 20)
                context = html_content[start:end].strip()
                context = re.sub(r'\s+', ' ', context)
                
                if context not in results:
                    results.append(context)
        except re.error:
            continue
    
    return results

def extract_obfuscated_javascript(html_content):
    """Detect heavily obfuscated JavaScript patterns that indicate malicious intent."""
    results = []
    
    obfuscation_patterns = [
        # Hexadecimal variable naming pattern (_0x1234) - strong indicator of obfuscation
        r'var\s+_0x[a-f0-9]{4,6}\s*=',
        r'_0x[a-f0-9]{4,6}\[.*?\]',
        r'_0x[a-f0-9]{2,6}\s*=\s*function',
        r'\(function\s*\(\s*_0x[a-f0-9]{2,6}\s*,\s*_0x[a-f0-9]{2,6}\s*\)',
        
        # Array/string manipulation often used in deobfuscation routines
        r'String\.fromCharCode\.apply\(null,',
        r'\[\]\["constructor"\]\["constructor"\]',
        r'\[\]\."filter"\."constructor"\(',
        r'atob\(.*?\)\."replace"\(',
        
        # Nested string indexing operations common in obfuscated code
        r'\[\(![!][""]\+[""]\)\[[\d]+\]\]',
        r'\("\\"\[\"constructor"\]\("return escape"\)\(\)\+"\\"\)\[\d+\]',
        
        # Self-modifying function detection
        r'function\s*\(\)\s*\{\s*return\s*function\s*\(\)\s*\{\s*',
        r'new Function\(\s*[\w\s,]+\,\s*atob\s*\(',
        
        # Extremely long strings with repeated patterns (BASE64, etc.)
        r'["\']((?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))["\']',
        
        # Object property access obfuscation
        r'[\'"`][a-zA-Z0-9_$]{1,3}[\'"`]\s*in\s*window',
        r'window\[[\'"`][a-zA-Z0-9_$]{1,3}[\'"`]\]',
        
        # Packed JavaScript indicators
        r'eval\(function\(p,a,c,k,e,(?:r|d)?\)',
        r'eval\(function\(p,a,c,k,e,r\)',
        
        # JJEncoder/Dean Edwards packer detection
        r'\$=~\[\];\$=\{___:\+\$,\$\$\$\$',
        r'__=\[\]\[\'fill\'\]'
    ]
    
    for pattern in obfuscation_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 40)
                end = min(len(html_content), match.end() + 40)
                context = html_content[start:end].strip()
                
                # Clean up the context
                context = re.sub(r'\s+', ' ', context)
                context = f"...{context}..."
                
                if context not in results:
                    results.append(context)
        except re.error:
            continue
    
    # Additional check for script density/complexity indicators
    script_tags = re.findall(r'<script[^>]*>(.*?)</script>', html_content, re.DOTALL)
    for script in script_tags:
        # Check for high symbol-to-character ratio (indicator of obfuscation)
        if len(script) > 100:  # Only check substantial scripts
            symbols = len(re.findall(r'[\(\)\[\]\{\}+\-*/=!<>?:;,.]', script))
            script_length = len(script)
            symbol_ratio = symbols / script_length
            
            # High ratio of symbols to characters suggests obfuscation
            if symbol_ratio > 0.25:  # Threshold determined empirically
                snippet = script[:100] + "..." if len(script) > 100 else script
                context = f"High symbol density ({symbol_ratio:.2f}): {snippet}"
                if context not in results:
                    results.append(context)
    
    return results

def extract_suspicious_commands(text):
    """Extract suspicious OS commands like mshta, curl, wget, etc."""
    suspicious_command_patterns = [
        r'mshta\s+(?:https?://[^\s"\'<>\)\(]+)',
        r'curl\s+(?:-[a-zA-Z]\s+)*(?:https?://[^\s"\'<>\)\(]+)',
        r'wget\s+(?:-[a-zA-Z]\s+)*(?:https?://[^\s"\'<>\)\(]+)',
        r'bitsadmin\s+(?:/transfer|/addfile)',
        r'certutil\s+(?:-urlcache|-encode|-decode)',
        r'regsvr32\s+(?:/s\s+/u\s+/i:|/i)',
        r'rundll32\s+(?:url\.dll,FileProtocolHandler)',
        r'cmd(?:\.exe)?\s+(?:/c|/k)',
        r'cscript\s+(?:https?://[^\s"\'<>\)\(]+|[^\s"\'<>\)\(]+\.(?:js|vbs|wsf))',
        r'wscript\s+(?:https?://[^\s"\'<>\)\(]+|[^\s"\'<>\)\(]+\.(?:js|vbs|wsf))',
        r'explorer\s+(?:javascript:|vbscript:|data:)',
        r'(?:nslookup|dig|ping)\s+[^\s]+\s+(?:\|\s*(?:sh|bash|cmd))',
        r'schtasks\s+/create',
        r'reg\s+(?:add|delete|query)',
        r'attrib\s+(?:\+[a-zA-Z]\s+)+[^\s]+',
        r'start\s+(?:/min\s+)?(?:https?://[^\s"\'<>\)\(]+|[^\s"\'<>\)\(]+\.(?:exe|bat|cmd|ps1|vbs|hta))',
        r'pushd\s+(?:https?://[^\s"\'<>\)\(]+)',
        r'copy\s+(?:https?://[^\s"\'<>\)\(]+)',
        r'\\\\[^\s"\'<>\)\(]+\\[^\s"\'<>\)\(]+'  # UNC paths
    ]
    
    results = []
    for pattern in suspicious_command_patterns:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            results.extend([{
                'Command': match.group(),
                'CommandType': determine_command_type(match.group())
            } for match in matches])
        except re.error:
            continue
    
    # Also look in base64 encoded strings
    base64_strings = extract_base64_strings(text)
    for b64_obj in base64_strings:
        if 'Decoded' in b64_obj:
            decoded_text = b64_obj['Decoded']
            for pattern in suspicious_command_patterns:
                try:
                    matches = re.finditer(pattern, decoded_text, re.IGNORECASE)
                    for match in matches:
                        command_info = {
                            'Command': match.group(),
                            'CommandType': determine_command_type(match.group()),
                            'Source': 'Base64 Decoded'
                        }
                        if command_info not in results:
                            results.append(command_info)
                except re.error:
                    continue
    
    # Also check clipboard commands for suspicious commands
    for clipboard_cmd in extract_clipboard_commands(text):
        for pattern in suspicious_command_patterns:
            try:
                if re.search(pattern, clipboard_cmd, re.IGNORECASE):
                    command_info = {
                        'Command': clipboard_cmd,
                        'CommandType': determine_command_type(clipboard_cmd),
                        'Source': 'Clipboard Command'
                    }
                    if command_info not in results:
                        results.append(command_info)
            except re.error:
                continue
    
    return results

def determine_command_type(command):
    """Determine the type of suspicious command."""
    command_lower = command.lower()
    
    if 'mshta' in command_lower:
        return 'MSHTA (High Risk)'
    elif 'powershell' in command_lower or 'iwr' in command_lower or 'iex' in command_lower:
        return 'PowerShell (High Risk)'
    elif 'cmd' in command_lower or 'command' in command_lower:
        return 'Command Prompt (High Risk)'
    elif 'rundll32' in command_lower or 'regsvr32' in command_lower:
        return 'DLL Loading (High Risk)'
    elif 'curl' in command_lower or 'wget' in command_lower or 'bitsadmin' in command_lower:
        return 'File Download (Medium Risk)'
    elif 'certutil' in command_lower:
        return 'Certificate Utility (Medium Risk)'
    elif 'cscript' in command_lower or 'wscript' in command_lower:
        return 'Script Engine (Medium Risk)'
    elif 'schtasks' in command_lower or 'reg' in command_lower:
        return 'System Configuration (Medium Risk)'
    else:
        return 'Suspicious Command'

def create_html_report(analysis_results, output_dir):
    """Generate a consolidated HTML report."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    total_base64 = sum(len(site['Base64Strings']) for site in analysis_results)
    total_urls = sum(len(site['URLs']) for site in analysis_results)
    total_powershell = sum(len(site['PowerShellCommands']) for site in analysis_results)
    total_ips = sum(len(site['IPAddresses']) for site in analysis_results)
    total_clipboard = sum(len(site['ClipboardCommands']) for site in analysis_results)
    total_suspicious = sum(len(site['SuspiciousKeywords']) for site in analysis_results)
    total_clipboard_manip = sum(len(site['ClipboardManipulation']) for site in analysis_results)
    total_ps_downloads = sum(len(site['PowerShellDownloads']) for site in analysis_results)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>URLhaus Analysis Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            h1, h2, h3, h4 {{
                color: #333;
            }}
            .summary {{
                background-color: #f8f9fa;
                padding: 15px;
                border-radius: 4px;
                margin-bottom: 20px;
            }}
            .site-section {{
                margin-bottom: 30px;
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }}
            .findings-table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 15px;
            }}
            .findings-table th, .findings-table td {{
                padding: 8px;
                text-align: left;
                border: 1px solid #ddd;
            }}
            .findings-table th {{
                background-color: #f8f9fa;
            }}
            .toggle-btn {{
                background-color: #007bff;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                cursor: pointer;
                margin-right: 10px;
                margin-bottom: 10px;
            }}
            .toggle-btn:hover {{
                background-color: #0056b3;
            }}
            .content-section {{
                display: none;
                margin-top: 10px;
            }}
            .active {{
                display: block;
            }}
            pre {{
                background-color: #f8f9fa;
                padding: 10px;
                border-radius: 4px;
                overflow-x: auto;
            }}
            .warning {{
                color: #dc3545;
                font-weight: bold;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-bottom: 20px;
            }}
            .stat-card {{
                background-color: #fff;
                padding: 15px;
                border-radius: 4px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .stat-number {{
                font-size: 24px;
                font-weight: bold;
                color: #007bff;
            }}
            .indicators {{
                margin-top: 20px;
                margin-bottom: 20px;
            }}
            .indicator-table {{
                width: 100%;
                border-collapse: collapse;
            }}
            .indicator-table th, .indicator-table td {{
                padding: 8px;
                text-align: left;
                border: 1px solid #ddd;
            }}
            .indicator-table th {{
                background-color: #f8f9fa;
            }}
            .url-badge {{
                display: inline-block;
                background-color: #ff9800;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-right: 5px;
            }}
            .ip-badge {{
                display: inline-block;
                background-color: #2196F3;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-right: 5px;
            }}
            .ps-badge {{
                display: inline-block;
                background-color: #4CAF50;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-right: 5px;
            }}
            .suspicious-badge {{
                display: inline-block;
                background-color: #f44336;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-size: 12px;
                margin-right: 5px;
            }}
        </style>
        <script>
            function toggleSection(siteId, section) {{
                const sections = document.querySelectorAll(`#${{siteId}} .content-section`);
                sections.forEach(s => s.classList.remove('active'));
                document.getElementById(`${{siteId}}-${{section}}`).classList.add('active');
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <h1>URLhaus Analysis Report</h1>
            <p>Generated on: {timestamp}</p>
            
            <div class="summary">
                <h2>Analysis Summary</h2>
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">{total_base64}</div>
                        <div>Base64 Strings</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_urls}</div>
                        <div>URLs</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_powershell}</div>
                        <div>PowerShell Commands</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_ips}</div>
                        <div>IP Addresses</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_clipboard}</div>
                        <div>Clipboard Commands</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_suspicious}</div>
                        <div>Suspicious Keywords</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_clipboard_manip}</div>
                        <div>Clipboard Manipulation</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_ps_downloads}</div>
                        <div>PS Downloads</div>
                    </div>
                </div>
            </div>
    """
    
    for i, site in enumerate(analysis_results):
        site_id = f"site-{i}"
        html_content += f"""
            <div class="site-section" id="{site_id}">
                <h3>Site: {html.escape(site['URL'])}</h3>
                <p>Total findings: {len(site['Base64Strings']) + len(site['URLs']) + len(site['PowerShellCommands']) + len(site['IPAddresses']) + len(site['ClipboardCommands']) + len(site['SuspiciousKeywords']) + len(site['ClipboardManipulation']) + len(site['PowerShellDownloads'])}</p>
                
                <div>
                    <button class="toggle-btn" onclick="toggleSection('{site_id}', 'indicators')">Indicators of Compromise</button>
                    <button class="toggle-btn" onclick="toggleSection('{site_id}', 'summary')">Analysis Details</button>
                    <button class="toggle-btn" onclick="toggleSection('{site_id}', 'json')">JSON Analysis</button>
                    <button class="toggle-btn" onclick="toggleSection('{site_id}', 'raw')">Raw HTML</button>
                </div>
                
                <div id="{site_id}-indicators" class="content-section active">
                    <h4>Indicators of Compromise</h4>
        """
        
        has_indicators = (len(site['URLs']) > 0 or len(site['IPAddresses']) > 0 or 
                         len(site['PowerShellDownloads']) > 0 or len(site['PowerShellCommands']) > 0)
        
        if has_indicators:
            html_content += """
                    <table class="indicator-table">
                        <tr>
                            <th style="width: 150px;">Type</th>
                            <th>Value</th>
                        </tr>
            """
            
            # Add URLs
            for url in site['URLs']:
                if url.endswith('.ps1') or url.endswith('.exe') or url.endswith('.bat') or url.endswith('.cmd') or url.endswith('.hta'):
                    html_content += f"""
                        <tr>
                            <td><span class="url-badge">URL</span></td>
                            <td><a href="{html.escape(url)}" target="_blank">{html.escape(url)}</a></td>
                        </tr>
                    """
                elif 'cdn' in url or not url.startswith('http://www.w3.org'):  # Filter out w3.org URLs as they're typically SVG related
                    html_content += f"""
                        <tr>
                            <td><span class="url-badge">URL</span></td>
                            <td><a href="{html.escape(url)}" target="_blank">{html.escape(url)}</a></td>
                        </tr>
                    """
            
            # Add PowerShell Download URLs
            for ps_download in site['PowerShellDownloads']:
                if isinstance(ps_download, dict) and 'URL' in ps_download and ps_download['URL']:
                    html_content += f"""
                        <tr>
                            <td><span class="ps-badge">PS Download</span></td>
                            <td>{html.escape(str(ps_download['URL']))}</td>
                        </tr>
                    """
            
            # Add IP addresses
            for ip in site['IPAddresses']:
                html_content += f"""
                    <tr>
                        <td><span class="ip-badge">IP</span></td>
                        <td>{html.escape(ip)}</td>
                    </tr>
                """
            
            # Add PowerShell Commands
            for cmd in site['PowerShellCommands']:
                html_content += f"""
                    <tr>
                        <td><span class="ps-badge">PowerShell</span></td>
                        <td>{html.escape(cmd)}</td>
                    </tr>
                """
            
            # Add Suspicious Keywords
            for keyword in site['SuspiciousKeywords']:
                html_content += f"""
                    <tr>
                        <td><span class="suspicious-badge">Suspicious</span></td>
                        <td>{html.escape(keyword)}</td>
                    </tr>
                """
                
            html_content += """
                    </table>
            """
        else:
            html_content += """
                    <p>No significant indicators of compromise found.</p>
            """
        
        html_content += f"""
                </div>
                
                <div id="{site_id}-summary" class="content-section">
                    <h4>Analysis Summary</h4>
                    <table class="findings-table">
                        <tr>
                            <th>Finding Type</th>
                            <th>Count</th>
                            <th>Details</th>
                        </tr>
        """
        
        finding_types = [
            ('Base64 Strings', 'Base64Strings'),
            ('URLs', 'URLs'),
            ('PowerShell Commands', 'PowerShellCommands'),
            ('IP Addresses', 'IPAddresses'),
            ('Clipboard Commands', 'ClipboardCommands'),
            ('Suspicious Keywords', 'SuspiciousKeywords'),
            ('Clipboard Manipulation', 'ClipboardManipulation'),
            ('PowerShell Downloads', 'PowerShellDownloads')
        ]
        
        for label, key in finding_types:
            findings = site[key]
            count = len(findings)
            
            if isinstance(findings[0], dict) if findings else False:
                details_list = []
                for f in findings[:5]:
                    if 'FullMatch' in f:
                        details_list.append(html.escape(str(f['FullMatch'])))
                    elif 'Base64' in f:
                        details_list.append(f"{html.escape(str(f['Base64']))} → {html.escape(str(f['Decoded']))}")
                    else:
                        details_list.append(html.escape(str(f)))
                details = '<br>'.join(details_list)
            else:
                details = '<br>'.join(html.escape(str(f)) for f in findings[:5])
                
            if count > 5:
                details += f'<br>... and {count - 5} more'
            
            html_content += f"""
                        <tr>
                            <td>{label}</td>
                            <td>{count}</td>
                            <td>{details}</td>
                        </tr>
            """
        
        html_content += f"""
                    </table>
                </div>
                
                <div id="{site_id}-json" class="content-section">
                    <h4>JSON Analysis</h4>
                    <pre>{html.escape(json.dumps(site, indent=2))}</pre>
                </div>
                
                <div id="{site_id}-raw" class="content-section">
                    <h4>Raw HTML Content</h4>
                    <pre>{html.escape(site['RawHTML'])}</pre>
                </div>
            </div>
        """
    
    html_content += """
        </div>
    </body>
    </html>
    """
    
    report_path = os.path.join(output_dir, 'analysis_report.html')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return report_path

def create_json_report(analysis_results, output_dir):
    """Generate a consolidated JSON report."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'total_sites_analyzed': len(analysis_results),
        'summary': {
            'total_base64_strings': sum(len(site['Base64Strings']) for site in analysis_results),
            'total_urls': sum(len(site['URLs']) for site in analysis_results),
            'total_powershell_commands': sum(len(site['PowerShellCommands']) for site in analysis_results),
            'total_ip_addresses': sum(len(site['IPAddresses']) for site in analysis_results),
            'total_clipboard_commands': sum(len(site['ClipboardCommands']) for site in analysis_results),
            'total_suspicious_keywords': sum(len(site['SuspiciousKeywords']) for site in analysis_results)
        },
        'sites': analysis_results
    }
    
    report_path = os.path.join(output_dir, 'analysis_report.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    
    return report_path

def create_csv_report(analysis_results, output_dir):
    """Generate a consolidated CSV report."""
    report_path = os.path.join(output_dir, 'analysis_report.csv')
    
    with open(report_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        writer.writerow([
            'URL',
            'Base64 Strings Count',
            'URLs Count',
            'PowerShell Commands Count',
            'IP Addresses Count',
            'Clipboard Commands Count',
            'Suspicious Keywords Count',
            'Clipboard Manipulation Count',
            'PowerShell Downloads Count',
            'Base64 Strings',
            'URLs',
            'PowerShell Commands',
            'IP Addresses',
            'Clipboard Commands',
            'Suspicious Keywords',
            'Clipboard Manipulation',
            'PowerShell Downloads'
        ])
        
        for site in analysis_results:
            writer.writerow([
                site['URL'],
                len(site['Base64Strings']),
                len(site['URLs']),
                len(site['PowerShellCommands']),
                len(site['IPAddresses']),
                len(site['ClipboardCommands']),
                len(site['SuspiciousKeywords']),
                len(site['ClipboardManipulation']),
                len(site['PowerShellDownloads']),
                '; '.join(str(x) for x in site['Base64Strings']),
                '; '.join(site['URLs']),
                '; '.join(site['PowerShellCommands']),
                '; '.join(site['IPAddresses']),
                '; '.join(str(x) for x in site['ClipboardCommands']),
                '; '.join(site['SuspiciousKeywords']),
                '; '.join(str(x) for x in site['ClipboardManipulation']),
                '; '.join(str(x) for x in site['PowerShellDownloads'])
            ])
    
    return report_path

def download_urlhaus_data(limit=None, tags=None):
    """Download recent URLs from URLhaus.
    
    Args:
        limit: Maximum number of URLs to return
        tags: List of tags to filter by (e.g. ['FakeCaptcha', 'ClickFix', 'click'])
    """
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    
    if tags is None:
        tags = ['FakeCaptcha', 'ClickFix', 'click']
    
    try:
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
            
            logging.debug(f"\nProcessing entry #{total_processed}:")
            logging.debug(f"  URL: {url}")
            logging.debug(f"  Tags: {url_tags}")
            logging.debug(f"  Threat: {threat}")
            
            matching_tags = [tag for tag in tags if tag.lower() in url_tags]
            if matching_tags:
                logging.debug(f"  ✓ Tag match found: {matching_tags}")
                if url.endswith('/') or url.endswith('html') or url.endswith('htm'):
                    logging.debug(f"  ✓ URL pattern match: {url}")
                    urls.append(url)
                else:
                    logging.debug(f"  ✗ URL pattern check failed: Does not end with /, html, or htm")
            else:
                logging.debug(f"  ✗ No matching tags found. Required tags: {tags}")
            
            if limit and len(urls) >= limit:
                logging.debug(f"\nReached limit of {limit} URLs")
                break
        
        logging.info(f"Found {len(urls)} matching URLs from {total_processed} total entries")
        return urls
    
    except Exception as e:
        logging.error(f"Error downloading URLhaus data: {e}")
        return []

def analyze_url(url):
    """Analyze a single URL for malicious content."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        html_content = response.text
        
        analysis = {
            'URL': url,
            'RawHTML': html_content,
            'Base64Strings': extract_base64_strings(html_content),
            'URLs': extract_urls(html_content),
            'PowerShellCommands': extract_powershell_commands(html_content),
            'IPAddresses': extract_ip_addresses(html_content),
            'ClipboardCommands': extract_clipboard_commands(html_content),
            'SuspiciousKeywords': extract_suspicious_keywords(html_content),
            'ClipboardManipulation': extract_clipboard_manipulation(html_content),
            'PowerShellDownloads': extract_powershell_downloads(html_content),
            'CaptchaElements': extract_captcha_elements(html_content),
            'ObfuscatedJavaScript': extract_obfuscated_javascript(html_content),
            'SuspiciousCommands': extract_suspicious_commands(html_content)
        }
        
        return analysis
    
    except Exception as e:
        logging.error(f"Error analyzing URL {url}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Analyze URLs from URLhaus for malicious content.')
    parser.add_argument('--analyze', help='Analyze a specific URL instead of downloading from URLhaus')
    parser.add_argument('--limit', type=int, help='Limit the number of URLs to analyze')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--output-dir', default='reports', help='Directory to store reports')
    parser.add_argument('--format', choices=['html', 'json', 'csv', 'all'], default='all',
                      help='Output format for the report')
    parser.add_argument('--tags', help='Comma-separated list of tags to filter URLs (default: FakeCaptcha,ClickFix,click)')
    
    args = parser.parse_args()
    
    tags = None
    if args.tags:
        tags = [t.strip() for t in args.tags.split(',')]
    
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    requests.packages.urllib3.disable_warnings()
    
    urls_to_analyze = []
    if args.analyze:
        urls_to_analyze = [args.analyze]
    else:
        logging.info("Downloading URLs from URLhaus...")
        urls_to_analyze = download_urlhaus_data(args.limit, tags)
        
    if not urls_to_analyze:
        logging.error("No URLs to analyze!")
        return
    
    logging.info(f"Analyzing {len(urls_to_analyze)} URLs...")
    analysis_results = []
    for url in urls_to_analyze:
        logging.info(f"Analyzing: {url}")
        result = analyze_url(url)
        if result:
            analysis_results.append(result)
    
    if not analysis_results:
        logging.error("No analysis results to report!")
        return
    
    logging.info("Generating reports...")
    if args.format in ['html', 'all']:
        html_path = create_html_report(analysis_results, args.output_dir)
        logging.info(f"HTML report saved to: {html_path}")
    
    if args.format in ['json', 'all']:
        json_path = create_json_report(analysis_results, args.output_dir)
        logging.info(f"JSON report saved to: {json_path}")
    
    if args.format in ['csv', 'all']:
        csv_path = create_csv_report(analysis_results, args.output_dir)
        logging.info(f"CSV report saved to: {csv_path}")
    
    logging.info("Analysis complete!")

if __name__ == '__main__':
    main()
