import streamlit as st
import requests
import pandas as pd
import json
import base64
import re
import io
import urllib3
import warnings
from datetime import datetime
import os
from urllib.parse import urlparse
from pathlib import Path
from clickgrab import (
    analyze_url,
    download_urlhaus_data,
    sanitize_url
)
from extractors import (
    extract_base64_strings,
    extract_urls,
    extract_powershell_commands,
    extract_ip_addresses,
    extract_clipboard_commands,
    extract_suspicious_keywords,
    extract_clipboard_manipulation,
    extract_powershell_downloads,
    extract_suspicious_commands
)
from models import CommonPatterns

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

if 'analysis_option' not in st.session_state:
    st.session_state.analysis_option = "Single URL Analysis"
if 'url_input' not in st.session_state:
    st.session_state.url_input = ""
if 'urls_text' not in st.session_state:
    st.session_state.urls_text = ""
if 'urlhaus_tags' not in st.session_state:
    st.session_state.urlhaus_tags = "FakeCaptcha,ClickFix,click"
if 'urlhaus_limit' not in st.session_state:
    st.session_state.urlhaus_limit = 10
if 'urlhaus_results' not in st.session_state:
    st.session_state.urlhaus_results = None
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'multi_analysis_results' not in st.session_state:
    st.session_state.multi_analysis_results = None

st.set_page_config(
    page_title="ClickGrab Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main {
        background-color: #f5f8fa;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f0f2f6;
        border-radius: 4px 4px 0px 0px;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #4CAF50 !important;
        color: white !important;
    }
    .stMarkdown h1, h2, h3 {
        padding-top: 20px;
        padding-bottom: 10px;
    }
    .status-badge {
        padding: 5px 10px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-green {
        background-color: #4CAF50;
        color: white;
    }
    .badge-red {
        background-color: #f44336;
        color: white;
    }
    .badge-orange {
        background-color: #ff9800;
        color: white;
    }
    .badge-blue {
        background-color: #2196F3;
        color: white;
    }
    .url-badge {
        display: inline-block;
        background-color: #ff9800;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        margin-right: 5px;
    }
    .ip-badge {
        display: inline-block;
        background-color: #2196F3;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        margin-right: 5px;
    }
    .ps-badge {
        display: inline-block;
        background-color: #4CAF50;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        margin-right: 5px;
    }
    .suspicious-badge {
        display: inline-block;
        background-color: #f44336;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 12px;
        margin-right: 5px;
    }
    .indicator-container {
        padding: 20px;
        border-radius: 5px;
        background-color: #fff;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        margin-bottom: 20px;
    }
    .stat-card {
        background-color: #fff;
        border-radius: 5px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        padding: 20px;
        text-align: center;
    }
    .stat-number {
        font-size: 36px;
        font-weight: bold;
        color: #4CAF50;
    }
    .keyword-text {
        font-family: monospace;
        background-color: #f0f2f6;
        padding: 2px 6px;
        border-radius: 3px;
        white-space: pre-wrap;
        word-break: break-all;
    }
</style>
""", unsafe_allow_html=True)

def local_css(file_name):
    """Load and inject local CSS"""
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def get_threat_level(results):
    """Calculate threat level based on analysis results"""
    # Use ThreatScore if available, otherwise calculate
    if hasattr(results, 'ThreatScore'):
        score = results.ThreatScore
    else:
        score = 0
        
        # PowerShell commands are highly suspicious
        ps_commands = getattr(results, 'PowerShellCommands', [])
        if len(ps_commands) > 0:
            score += 30
        
        # PowerShell downloads are highly suspicious
        ps_downloads = getattr(results, 'PowerShellDownloads', [])
        if len(ps_downloads) > 0:
            score += 30
        
        # Clipboard manipulation is suspicious
        clipboard_manip = getattr(results, 'ClipboardManipulation', [])
        if len(clipboard_manip) > 0:
            score += 20
        
        # Clipboard commands are suspicious
        clipboard_cmds = getattr(results, 'ClipboardCommands', [])
        if len(clipboard_cmds) > 0:
            score += 20
        
        # Obfuscated JavaScript is highly suspicious - add major points for this
        obfuscated_js = getattr(results, 'ObfuscatedJavaScript', [])
        if len(obfuscated_js) > 0:
            obfuscation_count = len(obfuscated_js)
            score += min(40, obfuscation_count * 8)
        
        # Suspicious commands are highly suspicious
        suspicious_cmds = getattr(results, 'SuspiciousCommands', [])
        if len(suspicious_cmds) > 0:
            suspicious_cmds_count = len(suspicious_cmds)
            score += min(50, suspicious_cmds_count * 10)
        
        # Base64 strings might be suspicious
        base64_strings = getattr(results, 'Base64Strings', [])
        if len(base64_strings) > 0:
            score += min(15, len(base64_strings))
        
        # Suspicious keywords
        suspicious_keywords = getattr(results, 'SuspiciousKeywords', [])
        if len(suspicious_keywords) > 0:
            score += min(30, len(suspicious_keywords) * 3)
        
        # CAPTCHA elements are suspicious
        captcha_elements = getattr(results, 'CaptchaElements', [])
        if len(captcha_elements) > 0:
            score += min(20, len(captcha_elements) * 2)
            
        # JavaScript redirects are suspicious
        js_redirects = getattr(results, 'JavaScriptRedirects', [])
        if len(js_redirects) > 0:
            score += min(25, len(js_redirects) * 5)
            
        # Parking page loaders are suspicious
        parking_page_loaders = getattr(results, 'ParkingPageLoaders', [])
        if len(parking_page_loaders) > 0:
            score += min(20, len(parking_page_loaders) * 4)
    
    if score >= 60:
        return "High", "badge-red"
    elif score >= 30:
        return "Medium", "badge-orange"
    elif score > 0:
        return "Low", "badge-blue"
    else:
        return "None", "badge-green"

def render_indicators_section(results):
    """Render the indicators of compromise section"""
    st.markdown("### Indicators of Compromise")
    
    # Get attributes safely
    urls = getattr(results, 'URLs', [])
    ip_addresses = getattr(results, 'IPAddresses', [])
    ps_downloads = getattr(results, 'PowerShellDownloads', [])
    ps_commands = getattr(results, 'PowerShellCommands', [])
    suspicious_keywords = getattr(results, 'SuspiciousKeywords', [])
    captcha_elements = getattr(results, 'CaptchaElements', [])
    obfuscated_js = getattr(results, 'ObfuscatedJavaScript', [])
    suspicious_cmds = getattr(results, 'SuspiciousCommands', [])
    js_redirects = getattr(results, 'JavaScriptRedirects', [])
    parking_page_loaders = getattr(results, 'ParkingPageLoaders', [])
    
    # Display threat score if available
    threat_score = getattr(results, 'ThreatScore', None)
    if threat_score is not None:
        threat_level, badge_class = get_threat_level(results)
        st.markdown(f"<span class='status-badge {badge_class}'>{threat_level} Threat (Score: {threat_score})</span>", unsafe_allow_html=True)
    else:
        threat_level, badge_class = get_threat_level(results)
        st.markdown(f"<span class='status-badge {badge_class}'>{threat_level} Threat</span>", unsafe_allow_html=True)
    
    has_indicators = (
        len(urls) > 0 or 
        len(ip_addresses) > 0 or 
        len(ps_downloads) > 0 or 
        len(ps_commands) > 0 or
        len(suspicious_keywords) > 0 or
        len(captcha_elements) > 0 or
        len(obfuscated_js) > 0 or
        len(suspicious_cmds) > 0 or
        len(js_redirects) > 0 or
        len(parking_page_loaders) > 0
    )
    
    if not has_indicators:
        st.info("No significant indicators of compromise found.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        if len(urls) > 0:
            st.markdown("#### Suspicious URLs")
            for url in urls:
                if (url.endswith('.ps1') or url.endswith('.exe') or 
                    url.endswith('.bat') or url.endswith('.cmd') or 
                    url.endswith('.hta') or 'cdn' in url or 
                    not url.startswith('http://www.w3.org')):
                    st.markdown(f'<span class="url-badge">URL</span> <a href="{url}" target="_blank">{url}</a>', 
                                unsafe_allow_html=True)
        
        if len(ps_downloads) > 0:
            st.markdown("#### PowerShell Download URLs")
            for ps_download in ps_downloads:
                # Check if ps_download is a dict or an object with URL attribute
                if isinstance(ps_download, dict) and 'URL' in ps_download and ps_download['URL']:
                    st.markdown(f'<span class="ps-badge">PS Download</span> {ps_download["URL"]}', 
                                unsafe_allow_html=True)
                elif hasattr(ps_download, 'URL') and ps_download.URL:
                    st.markdown(f'<span class="ps-badge">PS Download</span> {ps_download.URL}', 
                                unsafe_allow_html=True)
        
        if len(obfuscated_js) > 0:
            st.markdown("#### Obfuscated JavaScript")
            for i, element in enumerate(obfuscated_js[:5]):  # Limit to 5 elements
                # Safely convert element to string before slicing
                element_str = str(element)
                st.markdown(f'<span class="suspicious-badge" style="background-color: #d9534f;">Obfuscated JS</span> {element_str[:50]}...', 
                            unsafe_allow_html=True)
            if len(obfuscated_js) > 5:
                st.markdown(f'<span class="suspicious-badge" style="background-color: #d9534f;">+{len(obfuscated_js) - 5} more</span>', 
                            unsafe_allow_html=True)
                
        if len(suspicious_cmds) > 0:
            st.markdown("#### Suspicious Commands")
            for i, cmd_info in enumerate(suspicious_cmds[:5]):  # Limit to 5 elements
                if isinstance(cmd_info, dict) and 'Command' in cmd_info and 'CommandType' in cmd_info:
                    command = str(cmd_info['Command'])
                    cmd_type = cmd_info['CommandType']
                    badge_color = "#d9534f" if "High Risk" in cmd_type else "#f0ad4e"
                    st.markdown(f'<span class="suspicious-badge" style="background-color: {badge_color};">{cmd_type}</span> {command[:50]}...', 
                                unsafe_allow_html=True)
                elif hasattr(cmd_info, 'Command') and hasattr(cmd_info, 'CommandType'):
                    command = str(cmd_info.Command)
                    cmd_type = cmd_info.CommandType
                    # Use RiskLevel if available, otherwise default logic
                    if hasattr(cmd_info, 'RiskLevel'):
                        badge_color = "#d9534f" if "High Risk" in cmd_info.RiskLevel else "#f0ad4e"
                    else:
                        badge_color = "#d9534f" if "High Risk" in cmd_type else "#f0ad4e"
                    st.markdown(f'<span class="suspicious-badge" style="background-color: {badge_color};">{cmd_type}</span> {command[:50]}...', 
                                unsafe_allow_html=True)
            if len(suspicious_cmds) > 5:
                st.markdown(f'<span class="suspicious-badge" style="background-color: #d9534f;">+{len(suspicious_cmds) - 5} more</span>', 
                            unsafe_allow_html=True)

        if len(js_redirects) > 0:
            st.markdown("#### JavaScript Redirects")
            for i, redirect in enumerate(js_redirects[:5]):  # Limit to 5 elements
                redirect_str = str(redirect)
                st.markdown(f'<span class="suspicious-badge" style="background-color: #f0ad4e;">JS Redirect</span> {redirect_str[:50]}...', 
                            unsafe_allow_html=True)
            if len(js_redirects) > 5:
                st.markdown(f'<span class="suspicious-badge" style="background-color: #f0ad4e;">+{len(js_redirects) - 5} more</span>', 
                            unsafe_allow_html=True)
    
    with col2:
        if len(ip_addresses) > 0:
            st.markdown("#### IP Addresses")
            for ip in ip_addresses:
                st.markdown(f'<span class="ip-badge">IP</span> {ip}', unsafe_allow_html=True)
        
        if len(ps_commands) > 0:
            st.markdown("#### PowerShell Commands")
            for cmd in ps_commands:
                st.markdown(f'<span class="ps-badge">PowerShell</span> {str(cmd)[:50]}...', unsafe_allow_html=True)
        
        if len(captcha_elements) > 0:
            st.markdown("#### Fake CAPTCHA Elements")
            for i, element in enumerate(captcha_elements[:5]):  # Limit to 5 elements
                element_str = str(element)
                st.markdown(f'<span class="suspicious-badge">Fake CAPTCHA</span> {element_str[:50]}...', 
                            unsafe_allow_html=True)
            if len(captcha_elements) > 5:
                st.markdown(f'<span class="suspicious-badge">+{len(captcha_elements) - 5} more</span>', 
                            unsafe_allow_html=True)
                
        if len(parking_page_loaders) > 0:
            st.markdown("#### Parking Page Loaders")
            for i, loader in enumerate(parking_page_loaders[:5]):  # Limit to 5 elements
                loader_str = str(loader)
                if "Base64:" in loader_str:
                    # Extract the first part before Base64:
                    display_text = loader_str.split("Base64:")[0].strip()
                    display_text = display_text[:50] + "..." if len(display_text) > 50 else display_text
                else:
                    display_text = loader_str[:50] + "..." if len(loader_str) > 50 else loader_str
                st.markdown(f'<span class="suspicious-badge" style="background-color: #5bc0de;">Parking Page</span> {display_text}', 
                            unsafe_allow_html=True)
            if len(parking_page_loaders) > 5:
                st.markdown(f'<span class="suspicious-badge" style="background-color: #5bc0de;">+{len(parking_page_loaders) - 5} more</span>', 
                            unsafe_allow_html=True)
    
    if len(suspicious_keywords) > 0:
        st.markdown("#### Suspicious Keywords")
        keywords_cols = st.columns(3)
        for i, keyword in enumerate(suspicious_keywords):
            col_index = i % 3
            with keywords_cols[col_index]:
                # Ensure keyword is a string
                keyword_str = str(keyword)
                # Escape HTML special characters
                escaped_keyword = keyword_str.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
                # Truncate long keywords
                display_keyword = escaped_keyword[:150] + "..." if len(escaped_keyword) > 150 else escaped_keyword
                st.markdown(f'<span class="suspicious-badge">Suspicious</span> <span class="keyword-text">{display_keyword}</span>', 
                            unsafe_allow_html=True)

def render_detailed_analysis(results, use_expanders=True):
    """Render the detailed analysis section"""
    st.markdown("### Detailed Analysis")
    
    # Get attributes safely
    base64_strings = getattr(results, 'Base64Strings', [])
    urls = getattr(results, 'URLs', [])
    ps_commands = getattr(results, 'PowerShellCommands', [])
    ip_addresses = getattr(results, 'IPAddresses', [])
    clipboard_cmds = getattr(results, 'ClipboardCommands', [])
    suspicious_keywords = getattr(results, 'SuspiciousKeywords', [])
    clipboard_manip = getattr(results, 'ClipboardManipulation', [])
    ps_downloads = getattr(results, 'PowerShellDownloads', [])
    captcha_elements = getattr(results, 'CaptchaElements', [])
    obfuscated_js = getattr(results, 'ObfuscatedJavaScript', [])
    suspicious_cmds = getattr(results, 'SuspiciousCommands', [])
    js_redirects = getattr(results, 'JavaScriptRedirects', [])
    parking_page_loaders = getattr(results, 'ParkingPageLoaders', [])
    
    tabs = st.tabs([
        "Base64 Strings", 
        "URLs", 
        "PowerShell Commands",
        "IP Addresses",
        "Clipboard Commands",
        "Suspicious Keywords",
        "Clipboard Manipulation",
        "PowerShell Downloads",
        "CAPTCHA Elements",
        "Obfuscated JavaScript",
        "Suspicious Commands",
        "JavaScript Redirects",
        "Parking Page Loaders"
    ])
    
    with tabs[0]:
        if len(base64_strings) > 0:
            # Filter out Base64 strings that only contain benign URLs
            filtered_base64 = []
            for b64 in base64_strings:
                # Handle both dict and Pydantic model cases
                if isinstance(b64, dict):
                    filtered_base64.append(b64)
                elif hasattr(b64, 'ContainsBenignURL') and not b64.ContainsBenignURL:
                    filtered_base64.append(b64)
                elif not hasattr(b64, 'ContainsBenignURL'):
                    filtered_base64.append(b64)
            
            if filtered_base64:
                st.markdown(f"Found **{len(filtered_base64)}** relevant Base64 strings (excluding standard web references)")
                for i, b64 in enumerate(filtered_base64):
                    # Handle both dict and Pydantic model cases
                    if isinstance(b64, dict) and 'Base64' in b64 and 'Decoded' in b64:
                        if use_expanders:
                            with st.expander(f"Base64 String {i+1}"):
                                st.code(b64['Base64'], language="text")
                                st.markdown("**Decoded:**")
                                st.code(b64['Decoded'], language="text")
                        else:
                            st.markdown(f"**Base64 String {i+1}:**")
                            st.code(b64['Base64'], language="text")
                            st.markdown("**Decoded:**")
                            st.code(b64['Decoded'], language="text")
                            st.markdown("---")
                    elif hasattr(b64, 'Base64') and hasattr(b64, 'Decoded'):
                        if use_expanders:
                            with st.expander(f"Base64 String {i+1}"):
                                st.code(b64.Base64, language="text")
                                st.markdown("**Decoded:**")
                                st.code(b64.Decoded, language="text")
                        else:
                            st.markdown(f"**Base64 String {i+1}:**")
                            st.code(b64.Base64, language="text")
                            st.markdown("**Decoded:**")
                            st.code(b64.Decoded, language="text")
                            st.markdown("---")
            else:
                st.info("No significant Base64 strings found (only standard web references detected).")
        else:
            st.info("No Base64 strings found.")
    
    with tabs[1]:
        # Filter out common framework URLs
        filtered_urls = [url for url in urls 
                         if not url.startswith('http://www.w3.org') 
                         and not 'cloudflare.com/ajax/libs' in url]
        
        if len(filtered_urls) > 0:
            st.markdown(f"Found **{len(filtered_urls)}** URLs (excluding common framework URLs)")
            for i, url in enumerate(filtered_urls):
                # Highlight malicious URLs
                if ('cfcaptcha' in url or 
                    url.endswith('.ps1') or 
                    url.endswith('.exe') or 
                    url.endswith('.bat') or 
                    '|iex' in url or 
                    'flwssetp' in url):
                    st.markdown(f"{i+1}. <span style='color:red; font-weight:bold'>[{url}]({url})</span>", unsafe_allow_html=True)
                else:
                    st.markdown(f"{i+1}. [{url}]({url})")
        else:
            st.info("No significant URLs found (common framework URLs excluded).")
    
    with tabs[2]:
        if len(ps_commands) > 0:
            # Count PowerShell commands that are embedded in JavaScript
            embedded_count = sum(1 for cmd in ps_commands if cmd.startswith("EMBEDDED_IN_JS:"))
            
            if embedded_count > 0:
                st.markdown(f"Found **{len(ps_commands)}** PowerShell commands (including {embedded_count} embedded in JavaScript)")
            else:
                st.markdown(f"Found **{len(ps_commands)}** PowerShell commands")
            
            for i, cmd in enumerate(ps_commands):
                # Check if this is a PowerShell command embedded in JavaScript
                is_embedded = cmd.startswith("EMBEDDED_IN_JS:")
                
                # Format command appropriately
                if is_embedded:
                    # Remove the prefix and format it nicely
                    display_cmd = cmd.replace("EMBEDDED_IN_JS:", "").strip()
                    
                    if use_expanders:
                        with st.expander(f"PowerShell Command {i+1} (Embedded in JavaScript)"):
                            st.markdown("⚠️ **This PowerShell command was found inside JavaScript code**")
                            st.code(display_cmd, language="powershell")
                    else:
                        st.markdown(f"**PowerShell Command {i+1} (Embedded in JavaScript):**")
                        st.markdown("⚠️ **This PowerShell command was found inside JavaScript code**")
                        st.code(display_cmd, language="powershell")
                        st.markdown("---")
                else:
                    if use_expanders:
                        with st.expander(f"Command {i+1}"):
                            st.code(cmd, language="powershell")
                    else:
                        st.markdown(f"**Command {i+1}:**")
                        st.code(cmd, language="powershell")
                        st.markdown("---")
        else:
            st.info("No PowerShell commands found.")
    
    with tabs[3]:
        if len(ip_addresses) > 0:
            st.markdown(f"Found **{len(ip_addresses)}** IP addresses")
            for i, ip in enumerate(ip_addresses):
                st.markdown(f"{i+1}. `{ip}`")
        else:
            st.info("No IP addresses found.")
    
    with tabs[4]:
        if len(clipboard_cmds) > 0:
            st.markdown(f"Found **{len(clipboard_cmds)}** clipboard commands")
            for i, cmd in enumerate(clipboard_cmds):
                if use_expanders:
                    with st.expander(f"Command {i+1}"):
                        st.code(cmd, language="text")
                else:
                    st.markdown(f"**Command {i+1}:**")
                    st.code(cmd, language="text")
                    st.markdown("---")
        else:
            st.info("No clipboard commands found.")
    
    with tabs[5]:
        if len(suspicious_keywords) > 0:
            st.markdown("#### Suspicious Keywords")
            
            # Group keywords by severity
            high_severity = []
            medium_severity = []
            low_severity = []
            
            for keyword in suspicious_keywords:
                if any(term in keyword.lower() for term in ['powershell', 'iwr', 'iex', 'invoke', 'download']):
                    high_severity.append(keyword)
                elif any(term in keyword.lower() for term in ['cmd', 'command', 'execute', 'run', 'press win+r']):
                    medium_severity.append(keyword)
                else:
                    low_severity.append(keyword)
            
            if high_severity:
                st.markdown("#### High Risk Keywords:")
                for i, keyword in enumerate(high_severity):
                    escaped_keyword = keyword.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
                    display_keyword = escaped_keyword[:150] + "..." if len(escaped_keyword) > 150 else escaped_keyword
                    st.markdown(f'<span style="color:red; font-weight:bold">{i+1}. <span class="keyword-text">{display_keyword}</span></span>', 
                                unsafe_allow_html=True)
            
            if medium_severity:
                st.markdown("#### Medium Risk Keywords:")
                for i, keyword in enumerate(medium_severity):
                    escaped_keyword = keyword.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
                    display_keyword = escaped_keyword[:150] + "..." if len(escaped_keyword) > 150 else escaped_keyword
                    st.markdown(f'<span style="color:orange; font-weight:bold">{i+1}. <span class="keyword-text">{display_keyword}</span></span>', 
                                unsafe_allow_html=True)
            
            if low_severity:
                st.markdown("#### Other Suspicious Keywords:")
                for i, keyword in enumerate(low_severity):
                    escaped_keyword = keyword.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
                    display_keyword = escaped_keyword[:150] + "..." if len(escaped_keyword) > 150 else escaped_keyword
                    st.markdown(f'{i+1}. <span class="keyword-text">{display_keyword}</span>', 
                                unsafe_allow_html=True)
        else:
            st.info("No suspicious keywords found.")
    
    with tabs[6]:
        if len(clipboard_manip) > 0:
            st.markdown(f"Found **{len(clipboard_manip)}** clipboard manipulation instances")
            for i, manip in enumerate(clipboard_manip):
                # Highlight navigator.clipboard.writeText
                if 'navigator.clipboard.writeText' in manip:
                    st.markdown(f"<span style='color:red; font-weight:bold'>⚠️ Clipboard write detected:</span>", unsafe_allow_html=True)
                
                if use_expanders:
                    with st.expander(f"Instance {i+1}"):
                        st.code(manip, language="javascript")
                else:
                    st.markdown(f"**Instance {i+1}:**")
                    st.code(manip, language="javascript")
                    st.markdown("---")
        else:
            st.info("No clipboard manipulation found.")
    
    with tabs[7]:
        if len(ps_downloads) > 0:
            st.markdown(f"Found **{len(ps_downloads)}** PowerShell download commands")
            for i, download in enumerate(ps_downloads):
                if isinstance(download, dict):
                    # Add a warning label for high-risk downloads
                    if 'URL' in download and download['URL']:
                        st.markdown(f"<span style='color:red; font-weight:bold'>⚠️ Malicious download detected:</span>", unsafe_allow_html=True)
                    
                    if use_expanders:
                        with st.expander(f"Download {i+1}"):
                            st.markdown(f"**Full Match:** `{download.get('FullMatch', 'N/A')}`")
                            st.markdown(f"**URL:** `{download.get('URL', 'N/A')}`")
                            if 'HTAPath' in download:
                                st.markdown(f"**HTA Path:** `{download.get('HTAPath', 'N/A')}`")
                            st.markdown(f"**Context:** `{download.get('Context', 'N/A')}`")
                    else:
                        st.markdown(f"**Download {i+1}:**")
                        st.markdown(f"**Full Match:** `{download.get('FullMatch', 'N/A')}`")
                        st.markdown(f"**URL:** `{download.get('URL', 'N/A')}`")
                        if 'HTAPath' in download:
                            st.markdown(f"**HTA Path:** `{download.get('HTAPath', 'N/A')}`")
                        st.markdown(f"**Context:** `{download.get('Context', 'N/A')}`")
                        st.markdown("---")
                elif hasattr(download, 'URL'):
                    # Handle Pydantic model
                    if download.URL:
                        st.markdown(f"<span style='color:red; font-weight:bold'>⚠️ Malicious download detected:</span>", unsafe_allow_html=True)
                    
                    if use_expanders:
                        with st.expander(f"Download {i+1}"):
                            st.markdown(f"**Full Match:** `{getattr(download, 'FullMatch', 'N/A')}`")
                            st.markdown(f"**URL:** `{getattr(download, 'URL', 'N/A')}`")
                            if hasattr(download, 'HTAPath') and download.HTAPath:
                                st.markdown(f"**HTA Path:** `{download.HTAPath}`")
                            st.markdown(f"**Context:** `{getattr(download, 'Context', 'N/A')}`")
                    else:
                        st.markdown(f"**Download {i+1}:**")
                        st.markdown(f"**Full Match:** `{getattr(download, 'FullMatch', 'N/A')}`")
                        st.markdown(f"**URL:** `{getattr(download, 'URL', 'N/A')}`")
                        if hasattr(download, 'HTAPath') and download.HTAPath:
                            st.markdown(f"**HTA Path:** `{download.HTAPath}`")
                        st.markdown(f"**Context:** `{getattr(download, 'Context', 'N/A')}`")
                        st.markdown("---")
        else:
            st.info("No PowerShell downloads found.")
    
    with tabs[8]:
        if len(captcha_elements) > 0:
            st.markdown(f"Found **{len(captcha_elements)}** CAPTCHA-related elements")
            
            # Categorize captcha elements by type
            id_elements = []
            class_elements = []
            function_elements = []
            
            for element in captcha_elements:
                if 'id=' in element.lower():
                    id_elements.append(element)
                elif 'class=' in element.lower():
                    class_elements.append(element)
                elif 'function' in element.lower() or 'onclick' in element.lower():
                    function_elements.append(element)
                else:
                    function_elements.append(element)  # Default category
            
            if id_elements:
                st.markdown("#### CAPTCHA Element IDs:")
                for i, element in enumerate(id_elements):
                    if use_expanders:
                        with st.expander(f"Element ID {i+1}"):
                            st.code(element, language="html")
                    else:
                        st.markdown(f"**Element ID {i+1}:**")
                        st.code(element, language="html")
                        st.markdown("---")
            
            if class_elements:
                st.markdown("#### CAPTCHA Element Classes:")
                for i, element in enumerate(class_elements):
                    if use_expanders:
                        with st.expander(f"Element Class {i+1}"):
                            st.code(element, language="html")
                    else:
                        st.markdown(f"**Element Class {i+1}:**")
                        st.code(element, language="html")
                        st.markdown("---")
            
            if function_elements:
                st.markdown("#### CAPTCHA Functions and Event Handlers:")
                for i, element in enumerate(function_elements):
                    if use_expanders:
                        with st.expander(f"Function/Handler {i+1}"):
                            st.code(element, language="javascript")
                    else:
                        st.markdown(f"**Function/Handler {i+1}:**")
                        st.code(element, language="javascript")
                        st.markdown("---")
        else:
            st.info("No CAPTCHA elements found.")
    
    with tabs[9]:
        if len(obfuscated_js) > 0:
            st.markdown(f"Found **{len(obfuscated_js)}** instances of obfuscated JavaScript")
            
            # Add a warning banner for obfuscated JavaScript
            st.warning("⚠️ **HIGH RISK INDICATOR:** Obfuscated JavaScript is commonly used to hide malicious code and is a strong indicator of malicious intent.")
            
            for i, snippet in enumerate(obfuscated_js):
                if use_expanders:
                    with st.expander(f"Obfuscated JavaScript {i+1}"):
                        st.code(snippet, language="javascript")
                else:
                    st.markdown(f"**Obfuscated JavaScript {i+1}:**")
                    st.code(snippet, language="javascript")
                    st.markdown("---")
        else:
            st.info("No obfuscated JavaScript found.")
    
    with tabs[10]:
        if len(suspicious_cmds) > 0:
            st.markdown(f"Found **{len(suspicious_cmds)}** suspicious commands")
            
            # Group commands by risk level
            high_risk_commands = []
            medium_risk_commands = []
            other_commands = []
            
            for cmd_info in suspicious_cmds:
                if isinstance(cmd_info, dict) and 'Command' in cmd_info and 'CommandType' in cmd_info:
                    if 'High Risk' in cmd_info['CommandType']:
                        high_risk_commands.append(cmd_info)
                    elif 'Medium Risk' in cmd_info['CommandType']:
                        medium_risk_commands.append(cmd_info)
                    else:
                        other_commands.append(cmd_info)
                elif hasattr(cmd_info, 'Command') and hasattr(cmd_info, 'CommandType'):
                    # Handle Pydantic model
                    risk_level = getattr(cmd_info, 'RiskLevel', '')
                    if 'High Risk' in risk_level:
                        high_risk_commands.append(cmd_info)
                    elif 'Medium Risk' in risk_level:
                        medium_risk_commands.append(cmd_info)
                    else:
                        other_commands.append(cmd_info)
            
            if high_risk_commands:
                st.markdown("#### High Risk Commands:")
                for i, cmd_info in enumerate(high_risk_commands):
                    if isinstance(cmd_info, dict):
                        if use_expanders:
                            with st.expander(f"{cmd_info['CommandType']} - Command {i+1}"):
                                st.code(cmd_info['Command'], language="bash")
                                if 'Source' in cmd_info:
                                    st.markdown(f"**Source:** {cmd_info['Source']}")
                        else:
                            st.markdown(f"**{cmd_info['CommandType']} - Command {i+1}:**")
                            st.code(cmd_info['Command'], language="bash")
                            if 'Source' in cmd_info:
                                st.markdown(f"**Source:** {cmd_info['Source']}")
                            st.markdown("---")
                    else:
                        # Handle Pydantic model
                        cmd_type = cmd_info.CommandType
                        if use_expanders:
                            with st.expander(f"{cmd_type} - Command {i+1}"):
                                st.code(cmd_info.Command, language="bash")
                                if hasattr(cmd_info, 'Source') and cmd_info.Source:
                                    st.markdown(f"**Source:** {cmd_info.Source}")
                        else:
                            st.markdown(f"**{cmd_type} - Command {i+1}:**")
                            st.code(cmd_info.Command, language="bash")
                            if hasattr(cmd_info, 'Source') and cmd_info.Source:
                                st.markdown(f"**Source:** {cmd_info.Source}")
                            st.markdown("---")
            
            if medium_risk_commands:
                st.markdown("#### Medium Risk Commands:")
                for i, cmd_info in enumerate(medium_risk_commands):
                    if isinstance(cmd_info, dict):
                        if use_expanders:
                            with st.expander(f"{cmd_info['CommandType']} - Command {i+1}"):
                                st.code(cmd_info['Command'], language="bash")
                                if 'Source' in cmd_info:
                                    st.markdown(f"**Source:** {cmd_info['Source']}")
                        else:
                            st.markdown(f"**{cmd_info['CommandType']} - Command {i+1}:**")
                            st.code(cmd_info['Command'], language="bash")
                            if 'Source' in cmd_info:
                                st.markdown(f"**Source:** {cmd_info['Source']}")
                            st.markdown("---")
                    else:
                        # Handle Pydantic model
                        cmd_type = cmd_info.CommandType
                        if use_expanders:
                            with st.expander(f"{cmd_type} - Command {i+1}"):
                                st.code(cmd_info.Command, language="bash")
                                if hasattr(cmd_info, 'Source') and cmd_info.Source:
                                    st.markdown(f"**Source:** {cmd_info.Source}")
                        else:
                            st.markdown(f"**{cmd_type} - Command {i+1}:**")
                            st.code(cmd_info.Command, language="bash")
                            if hasattr(cmd_info, 'Source') and cmd_info.Source:
                                st.markdown(f"**Source:** {cmd_info.Source}")
                            st.markdown("---")
            
            if other_commands:
                st.markdown("#### Other Suspicious Commands:")
                for i, cmd_info in enumerate(other_commands):
                    if isinstance(cmd_info, dict):
                        if use_expanders:
                            with st.expander(f"Command {i+1}"):
                                st.code(cmd_info['Command'], language="bash")
                                if 'Source' in cmd_info:
                                    st.markdown(f"**Source:** {cmd_info['Source']}")
                        else:
                            st.markdown(f"**Command {i+1}:**")
                            st.code(cmd_info['Command'], language="bash")
                            if 'Source' in cmd_info:
                                st.markdown(f"**Source:** {cmd_info['Source']}")
                            st.markdown("---")
                    else:
                        # Handle Pydantic model
                        if use_expanders:
                            with st.expander(f"Command {i+1}"):
                                st.code(cmd_info.Command, language="bash")
                                if hasattr(cmd_info, 'Source') and cmd_info.Source:
                                    st.markdown(f"**Source:** {cmd_info.Source}")
                        else:
                            st.markdown(f"**Command {i+1}:**")
                            st.code(cmd_info.Command, language="bash")
                            if hasattr(cmd_info, 'Source') and cmd_info.Source:
                                st.markdown(f"**Source:** {cmd_info.Source}")
                            st.markdown("---")
        else:
            st.info("No suspicious commands found.")

    with tabs[11]:
        if len(js_redirects) > 0:
            st.markdown(f"Found **{len(js_redirects)}** JavaScript redirects")
            
            for i, redirect in enumerate(js_redirects):
                if use_expanders:
                    with st.expander(f"Redirect {i+1}"):
                        st.markdown(f"**{redirect}**")
                else:
                    st.markdown(f"**Redirect {i+1}:**")
                    st.markdown(f"{redirect}")
                    st.markdown("---")
        else:
            st.info("No JavaScript redirects found.")
            
    with tabs[12]:
        if len(parking_page_loaders) > 0:
            st.markdown(f"Found **{len(parking_page_loaders)}** parking page loaders")
            
            for i, loader in enumerate(parking_page_loaders):
                if use_expanders:
                    with st.expander(f"Parking Page Loader {i+1}"):
                        # Check if this is a loader with Base64 data
                        if "Base64:" in loader and "Decoded:" in loader:
                            parts = loader.split("Decoded:", 1)
                            header = parts[0].strip()
                            decoded = parts[1].strip()
                            st.markdown(f"**{header}**")
                            st.markdown("**Decoded:**")
                            st.code(decoded, language="json" if decoded.startswith("{") else "text")
                        else:
                            st.markdown(f"**{loader}**")
                else:
                    st.markdown(f"**Parking Page Loader {i+1}:**")
                    # Check if this is a loader with Base64 data
                    if "Base64:" in loader and "Decoded:" in loader:
                        parts = loader.split("Decoded:", 1)
                        header = parts[0].strip()
                        decoded = parts[1].strip()
                        st.markdown(f"**{header}**")
                        st.markdown("**Decoded:**")
                        st.code(decoded, language="json" if decoded.startswith("{") else "text")
                    else:
                        st.markdown(f"**{loader}**")
                    st.markdown("---")
        else:
            st.info("No parking page loaders found.")

def render_raw_html(results, use_expander=True):
    """Render the raw HTML section"""
    st.markdown("### Raw HTML Content")
    
    # Get raw HTML safely
    raw_html = getattr(results, 'RawHTML', '')
    
    if use_expander:
        with st.expander("Show Raw HTML"):
            st.code(raw_html, language="html")
    else:
        toggle = st.checkbox("Show Raw HTML", key=f"raw_html_{id(results)}")
        if toggle:
            st.code(raw_html, language="html")

def analyze_single_url(url):
    """Analyze a single URL and show results"""
    original_url = url
    sanitized_url = sanitize_url(url)
    
    if original_url != sanitized_url:
        st.info(f"🔧 **URL was defanged and cleaned:** `{original_url}` → `{sanitized_url}`")
        url = sanitized_url
    
    with st.spinner(f"Analyzing URL: {url}"):
        results = analyze_url(url)
        
    if not results:
        st.error(f"Error analyzing URL: {url}")
        return
    
    st.markdown(f"## Analysis Results for: [{url}]({url})")
    
    threat_level, badge_class = get_threat_level(results)
    
    # Display the threat score if available
    threat_score = getattr(results, 'ThreatScore', None)
    score_text = f" (Score: {threat_score})" if threat_score is not None else ""
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    # Get attributes safely
    base64_strings = getattr(results, 'Base64Strings', [])
    ps_commands = getattr(results, 'PowerShellCommands', [])
    suspicious_keywords = getattr(results, 'SuspiciousKeywords', [])
    obfuscated_js = getattr(results, 'ObfuscatedJavaScript', [])
    urls = getattr(results, 'URLs', [])
    ip_addresses = getattr(results, 'IPAddresses', [])
    clipboard_cmds = getattr(results, 'ClipboardCommands', [])
    clipboard_manip = getattr(results, 'ClipboardManipulation', [])
    ps_downloads = getattr(results, 'PowerShellDownloads', [])
    suspicious_cmds = getattr(results, 'SuspiciousCommands', [])
    js_redirects = getattr(results, 'JavaScriptRedirects', [])
    parking_page_loaders = getattr(results, 'ParkingPageLoaders', [])
    
    with col1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(base64_strings)}</div>
            <div>Base64 Strings</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(ps_commands)}</div>
            <div>PowerShell Commands</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(js_redirects)}</div>
            <div>JS Redirects</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(parking_page_loaders)}</div>
            <div>Parking Page Loaders</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        st.markdown(f"""
        <div class="stat-card">
            <span class="status-badge {badge_class}">{threat_level} Threat{score_text}</span>
            <div class="stat-number">{sum([
                len(base64_strings),
                len(urls),
                len(ps_commands),
                len(ip_addresses),
                len(clipboard_cmds),
                len(suspicious_keywords),
                len(clipboard_manip),
                len(ps_downloads),
                len(obfuscated_js),
                len(suspicious_cmds),
                len(js_redirects),
                len(parking_page_loaders)
            ])}</div>
            <div>Total Findings</div>
        </div>
        """, unsafe_allow_html=True)
    
    with st.container():
        render_indicators_section(results)
    
    with st.container():
        render_detailed_analysis(results, use_expanders=True)
    
    with st.container():
        render_raw_html(results, use_expander=True)
    
    return results

def analyze_multiple_urls(urls):
    """Analyze multiple URLs and show comparative results"""
    results_list = []
    
    sanitized_count = 0
    sanitized_urls = []
    for i, url in enumerate(urls):
        sanitized = sanitize_url(url)
        if url != sanitized:
            sanitized_count += 1
            sanitized_urls.append((url, sanitized))
        urls[i] = sanitized
    
    if sanitized_count > 0:
        st.info(f"🔧 **{sanitized_count} URL(s) were defanged and cleaned**")
        with st.expander("Show cleaned URLs"):
            for original, cleaned in sanitized_urls:
                st.text(f"{original} → {cleaned}")
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, url in enumerate(urls):
        status_text.text(f"Analyzing URL {i+1}/{len(urls)}: {url}")
        result = analyze_url(url)
        if result:
            results_list.append(result)
        progress_bar.progress((i + 1) / len(urls))
    
    status_text.text("Analysis complete!")
    progress_bar.empty()
    
    if not results_list:
        st.error("No valid results to display.")
        return
    
    st.markdown("## Analysis Summary")
    
    summary_data = []
    for result in results_list:
        url = getattr(result, 'URL', 'Unknown')
        threat_level, _ = get_threat_level(result)
        total_findings = sum([
            len(getattr(result, 'Base64Strings', [])),
            len(getattr(result, 'URLs', [])),
            len(getattr(result, 'PowerShellCommands', [])),
            len(getattr(result, 'IPAddresses', [])),
            len(getattr(result, 'ClipboardCommands', [])),
            len(getattr(result, 'SuspiciousKeywords', [])),
            len(getattr(result, 'ClipboardManipulation', [])),
            len(getattr(result, 'PowerShellDownloads', [])),
            len(getattr(result, 'ObfuscatedJavaScript', [])),
            len(getattr(result, 'SuspiciousCommands', [])),
            len(getattr(result, 'JavaScriptRedirects', [])),
            len(getattr(result, 'ParkingPageLoaders', []))
        ])
        
        summary_data.append({
            'URL': url,
            'Threat Level': threat_level,
            'Total Findings': total_findings,
            'Base64 Strings': len(getattr(result, 'Base64Strings', [])),
            'PowerShell Commands': len(getattr(result, 'PowerShellCommands', [])),
            'PowerShell Downloads': len(getattr(result, 'PowerShellDownloads', [])),
            'Suspicious Keywords': len(getattr(result, 'SuspiciousKeywords', [])),
            'Clipboard Manipulation': len(getattr(result, 'ClipboardManipulation', [])),
            'IP Addresses': len(getattr(result, 'IPAddresses', [])),
            'Obfuscated JS': len(getattr(result, 'ObfuscatedJavaScript', [])),
            'Suspicious Commands': len(getattr(result, 'SuspiciousCommands', [])),
            'JS Redirects': len(getattr(result, 'JavaScriptRedirects', [])),
            'Parking Page Loaders': len(getattr(result, 'ParkingPageLoaders', []))
        })
    
    summary_df = pd.DataFrame(summary_data)
    
    numeric_columns = [col for col in summary_df.columns if col not in ['URL', 'Threat Level']]
    st.dataframe(summary_df.style.background_gradient(cmap='YlOrRd', subset=numeric_columns), use_container_width=True)
    
    for i, result in enumerate(results_list):
        url = getattr(result, 'URL', 'Unknown')
        with st.expander(f"Detailed Analysis for {url}"):
            threat_level, badge_class = get_threat_level(result)
            st.markdown(f"<span class='status-badge {badge_class}'>{threat_level} Threat</span>", unsafe_allow_html=True)
            
            render_indicators_section(result)
            render_detailed_analysis(result, use_expanders=False)
            render_raw_html(result, use_expander=False)
    
    return results_list

def download_report(results, file_format="html"):
    """Create a downloadable report"""
    if file_format == "json":
        # Convert Pydantic models to dictionaries
        if hasattr(results[0], 'model_dump'):
            # Pydantic v2 method
            results_dict = [result.model_dump() for result in results]
        elif hasattr(results[0], 'dict'):
            # Pydantic v1 method (for backward compatibility)
            results_dict = [result.dict() for result in results]
        else:
            # Already dictionaries
            results_dict = results
            
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_base64_strings': sum(len(getattr(site, 'Base64Strings', [])) for site in results),
                'total_urls': sum(len(getattr(site, 'URLs', [])) for site in results),
                'total_powershell_commands': sum(len(getattr(site, 'PowerShellCommands', [])) for site in results),
                'total_ip_addresses': sum(len(getattr(site, 'IPAddresses', [])) for site in results),
                'total_clipboard_commands': sum(len(getattr(site, 'ClipboardCommands', [])) for site in results),
                'total_suspicious_keywords': sum(len(getattr(site, 'SuspiciousKeywords', [])) for site in results),
                'total_clipboard_manipulation': sum(len(getattr(site, 'ClipboardManipulation', [])) for site in results),
                'total_powershell_downloads': sum(len(getattr(site, 'PowerShellDownloads', [])) for site in results),
                'total_captcha_elements': sum(len(getattr(site, 'CaptchaElements', [])) for site in results),
                'total_obfuscated_javascript': sum(len(getattr(site, 'ObfuscatedJavaScript', [])) for site in results),
                'total_suspicious_commands': sum(len(getattr(site, 'SuspiciousCommands', [])) for site in results),
                'total_javascript_redirects': sum(len(getattr(site, 'JavaScriptRedirects', [])) for site in results),
                'total_parking_page_loaders': sum(len(getattr(site, 'ParkingPageLoaders', [])) for site in results)
            },
            'sites': results_dict
        }
        
        json_str = json.dumps(report, indent=2)
        
        b64 = base64.b64encode(json_str.encode()).decode()
        href = f'<a href="data:application/json;base64,{b64}" download="clickgrab_report.json">Download JSON Report</a>'
        return href
    
    elif file_format == "csv":
        data = []
        for site in results:
            data.append({
                'URL': getattr(site, 'URL', 'Unknown'),
                'Base64 Strings Count': len(getattr(site, 'Base64Strings', [])),
                'URLs Count': len(getattr(site, 'URLs', [])),
                'PowerShell Commands Count': len(getattr(site, 'PowerShellCommands', [])),
                'IP Addresses Count': len(getattr(site, 'IPAddresses', [])),
                'Clipboard Commands Count': len(getattr(site, 'ClipboardCommands', [])),
                'Suspicious Keywords Count': len(getattr(site, 'SuspiciousKeywords', [])),
                'Clipboard Manipulation Count': len(getattr(site, 'ClipboardManipulation', [])),
                'PowerShell Downloads Count': len(getattr(site, 'PowerShellDownloads', [])),
                'JavaScript Redirects Count': len(getattr(site, 'JavaScriptRedirects', [])),
                'Parking Page Loaders Count': len(getattr(site, 'ParkingPageLoaders', []))
            })
        
        df = pd.DataFrame(data)
        csv = df.to_csv(index=False)
        
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:text/csv;base64,{b64}" download="clickgrab_report.csv">Download CSV Report</a>'
        return href
    
    else: 
        from clickgrab import generate_html_report, ClickGrabConfig
        
        temp_dir = Path("temp_reports")
        temp_dir.mkdir(exist_ok=True)
        
        # Create a temporary config
        config = ClickGrabConfig(output_dir=str(temp_dir))
        
        # Generate the HTML report
        html_path = generate_html_report(results, config)
        
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()
        
        b64 = base64.b64encode(html_content.encode()).decode()
        href = f'<a href="data:text/html;base64,{b64}" download="clickgrab_report.html">Download HTML Report</a>'
        return href

def main():
    """Main function for the Streamlit app"""
    st.title("🔍 ClickGrab Analyzer")
    st.markdown("""
    Analyze websites for potential ClickFix/FakeCAPTCHA phishing techniques. 
    This tool helps identify malicious web pages that may be attempting to trick users
    with fake CAPTCHA verification or other social engineering techniques.
    """)
    
    st.sidebar.title("ClickGrab Options")
    st.session_state.analysis_option = st.sidebar.radio(
        "Choose Analysis Mode",
        ["Single URL Analysis", "Multiple URL Analysis", "URLhaus Search"],
        index=["Single URL Analysis", "Multiple URL Analysis", "URLhaus Search"].index(st.session_state.analysis_option)
    )
    
    if st.session_state.analysis_option == "Single URL Analysis":
        st.markdown("## Single URL Analysis")
        
        # Use form for better UX with submission
        with st.form(key="single_url_form"):
            st.session_state.url_input = st.text_input(
                "Enter URL to Analyze",
                value=st.session_state.url_input,
                placeholder="https://example.com/suspicious-page.html"
            )
            
            analyze_button = st.form_submit_button("Analyze URL", use_container_width=True)
        
        if analyze_button and st.session_state.url_input:
            results = analyze_single_url(st.session_state.url_input)
            
            if results:
                # Store results in session state
                st.session_state.analysis_results = results
                
                st.markdown("## Download Reports")
                report_format = st.radio(
                    "Select report format:",
                    ["HTML", "JSON", "CSV"],
                    horizontal=True
                )
                
                if report_format == "HTML":
                    download_link = download_report([results], "html")
                elif report_format == "JSON":
                    download_link = download_report([results], "json")
                else:  # CSV
                    download_link = download_report([results], "csv")
                
                st.markdown(download_link, unsafe_allow_html=True)
        elif st.session_state.analysis_results and st.session_state.analysis_option == "Single URL Analysis":
            # Display cached results if they exist
            results = st.session_state.analysis_results
            render_indicators_section(results)
            render_detailed_analysis(results, use_expanders=True)
            render_raw_html(results, use_expander=True)
            
            st.markdown("## Download Reports")
            report_format = st.radio(
                "Select report format:",
                ["HTML", "JSON", "CSV"],
                horizontal=True
            )
            
            if report_format == "HTML":
                download_link = download_report([results], "html")
            elif report_format == "JSON":
                download_link = download_report([results], "json")
            else:  # CSV
                download_link = download_report([results], "csv")
            
            st.markdown(download_link, unsafe_allow_html=True)
    
    elif st.session_state.analysis_option == "Multiple URL Analysis":
        st.markdown("## Multiple URL Analysis")
        
        # Use form for better UX with submission
        with st.form(key="multi_url_form"):
            st.session_state.urls_text = st.text_area(
                "Enter URLs (one per line)",
                value=st.session_state.urls_text,
                placeholder="https://example1.com/page.html\nhttps://example2.com/page.html"
            )
            
            analyze_button = st.form_submit_button("Analyze URLs", use_container_width=True)
        
        if analyze_button and st.session_state.urls_text:
            urls = [url.strip() for url in st.session_state.urls_text.split('\n') if url.strip()]
            if urls:
                results_list = analyze_multiple_urls(urls)
                
                if results_list:
                    st.session_state.multi_analysis_results = results_list
                    
                    st.markdown("## Download Reports")
                    report_format = st.radio(
                        "Select report format:",
                        ["HTML", "JSON", "CSV"],
                        horizontal=True
                    )
                    
                    if report_format == "HTML":
                        download_link = download_report(results_list, "html")
                    elif report_format == "JSON":
                        download_link = download_report(results_list, "json")
                    else:
                        download_link = download_report(results_list, "csv")
                    
                    st.markdown(download_link, unsafe_allow_html=True)
            else:
                st.error("Please enter at least one valid URL.")
        elif st.session_state.multi_analysis_results and st.session_state.analysis_option == "Multiple URL Analysis":
            # Display cached results if they exist
            results_list = st.session_state.multi_analysis_results
            
            st.markdown("## Analysis Summary")
            
            summary_data = []
            for result in results_list:
                url = getattr(result, 'URL', 'Unknown')
                threat_level, _ = get_threat_level(result)
                # Use TotalIndicators field if available, otherwise calculate
                if hasattr(result, 'TotalIndicators'):
                    total_findings = result.TotalIndicators
                else:
                    total_findings = sum([
                        len(getattr(result, 'Base64Strings', [])),
                        len(getattr(result, 'PowerShellCommands', [])),
                            len(getattr(result, 'EncodedPowerShell', [])),
                        len(getattr(result, 'ClipboardCommands', [])),
                        len(getattr(result, 'ClipboardManipulation', [])),
                        len(getattr(result, 'PowerShellDownloads', [])),
                            len(getattr(result, 'CaptchaElements', [])),
                        len(getattr(result, 'ObfuscatedJavaScript', [])),
                        len(getattr(result, 'SuspiciousCommands', []))
                    ])
                
                summary_data.append({
                    'URL': url,
                    'Threat Level': threat_level,
                    'Total Findings': total_findings,
                    'Base64 Strings': len(getattr(result, 'Base64Strings', [])),
                    'PowerShell Commands': len(getattr(result, 'PowerShellCommands', [])),
                    'PowerShell Downloads': len(getattr(result, 'PowerShellDownloads', [])),
                    'Suspicious Keywords': len(getattr(result, 'SuspiciousKeywords', [])),
                    'Clipboard Manipulation': len(getattr(result, 'ClipboardManipulation', [])),
                    'IP Addresses': len(getattr(result, 'IPAddresses', [])),
                    'Obfuscated JS': len(getattr(result, 'ObfuscatedJavaScript', [])),
                    'Suspicious Commands': len(getattr(result, 'SuspiciousCommands', []))
                })
            
            summary_df = pd.DataFrame(summary_data)
            
            numeric_columns = [col for col in summary_df.columns if col not in ['URL', 'Threat Level']]
            # Use the new toolbar feature
            st.dataframe(
                summary_df.style.background_gradient(cmap='YlOrRd', subset=numeric_columns),
                use_container_width=True, 
                column_config={"Threat Level": st.column_config.TextColumn("Threat Level", help="Risk assessment level")},
                hide_index=True
            )
            
            for i, result in enumerate(results_list):
                with st.expander(f"Detailed Analysis for {getattr(result, 'URL', 'Unknown')}"):
                    threat_level, badge_class = get_threat_level(result)
                    st.markdown(f"<span class='status-badge {badge_class}'>{threat_level} Threat</span>", unsafe_allow_html=True)
                    
                    render_indicators_section(result)
                    render_detailed_analysis(result, use_expanders=False)
                    render_raw_html(result, use_expander=False)
            
            st.markdown("## Download Reports")
            report_format = st.radio(
                "Select report format:",
                ["HTML", "JSON", "CSV"],
                horizontal=True
            )
            
            if report_format == "HTML":
                download_link = download_report(results_list, "html")
            elif report_format == "JSON":
                download_link = download_report(results_list, "json")
            else:
                download_link = download_report(results_list, "csv")
            
            st.markdown(download_link, unsafe_allow_html=True)
    
    elif st.session_state.analysis_option == "URLhaus Search":
        st.markdown("## URLhaus Search")
        st.info("Search and analyze recent URLs from URLhaus tagged as ClickFix or FakeCaptcha")
        
        # Use form for better UX with submission
        with st.form(key="urlhaus_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                # Use session state for the tags input
                st.session_state.urlhaus_tags = st.text_input(
                    "Tags (comma-separated)",
                    value=st.session_state.urlhaus_tags
                )
            
            with col2:
                # Use session state for the limit
                st.session_state.urlhaus_limit = st.number_input(
                    "Limit results",
                    min_value=1,
                    max_value=100,
                    value=st.session_state.urlhaus_limit
                )
            
            search_button = st.form_submit_button("Search URLhaus", use_container_width=True)
        
        if search_button:
            tags = [tag.strip() for tag in st.session_state.urlhaus_tags.split(',') if tag.strip()]
            
            with st.spinner("Searching URLhaus database..."):
                urls = download_urlhaus_data(limit=st.session_state.urlhaus_limit, tags=tags)
            
            if urls:
                # Store results in session state
                st.session_state.urlhaus_results = urls
                
                st.success(f"Found {len(urls)} matching URLs")
                
                # Use the new toolbar feature with search and download
                urls_df = pd.DataFrame({"URLs": urls})
                st.dataframe(
                    urls_df, 
                    use_container_width=True, 
                    column_config={"URLs": st.column_config.LinkColumn("URLs")},
                    hide_index=True
                )
                
                analyze_found = st.checkbox("Analyze found URLs")
                
                if analyze_found:
                    results_list = analyze_multiple_urls(urls)
                    
                    if results_list:
                        # Store results in session state
                        st.session_state.multi_analysis_results = results_list
                        
                        st.markdown("## Download Reports")
                        report_format = st.radio(
                            "Select report format:",
                            ["HTML", "JSON", "CSV"],
                            horizontal=True
                        )
                        
                        if report_format == "HTML":
                            download_link = download_report(results_list, "html")
                        elif report_format == "JSON":
                            download_link = download_report(results_list, "json")
                        else: 
                            download_link = download_report(results_list, "csv")
                        
                        st.markdown(download_link, unsafe_allow_html=True)
            else:
                st.error("No URLs found matching the specified tags.")
        elif st.session_state.urlhaus_results:
            # Display cached results if they exist
            urls = st.session_state.urlhaus_results
            
            st.success(f"Found {len(urls)} matching URLs")
            
            urls_df = pd.DataFrame({"URLs": urls})
            st.dataframe(urls_df, use_container_width=True)
            
            analyze_found = st.checkbox("Analyze found URLs")
            
            if analyze_found and st.session_state.multi_analysis_results:
                results_list = st.session_state.multi_analysis_results
                
                st.markdown("## Analysis Summary")
                
                summary_data = []
                for result in results_list:
                    url = getattr(result, 'URL', 'Unknown')
                    threat_level, _ = get_threat_level(result)
                    total_findings = sum([
                        len(getattr(result, 'Base64Strings', [])),
                        len(getattr(result, 'URLs', [])),
                        len(getattr(result, 'PowerShellCommands', [])),
                        len(getattr(result, 'IPAddresses', [])),
                        len(getattr(result, 'ClipboardCommands', [])),
                        len(getattr(result, 'ClipboardManipulation', [])),
                        len(getattr(result, 'PowerShellDownloads', [])),
                        len(getattr(result, 'ObfuscatedJavaScript', [])),
                        len(getattr(result, 'SuspiciousCommands', []))
                    ])
                    
                    summary_data.append({
                        'URL': url,
                        'Threat Level': threat_level,
                        'Total Findings': total_findings,
                        'Base64 Strings': len(getattr(result, 'Base64Strings', [])),
                        'PowerShell Commands': len(getattr(result, 'PowerShellCommands', [])),
                        'PowerShell Downloads': len(getattr(result, 'PowerShellDownloads', [])),
                        'Suspicious Keywords': len(getattr(result, 'SuspiciousKeywords', [])),
                        'Clipboard Manipulation': len(getattr(result, 'ClipboardManipulation', [])),
                        'IP Addresses': len(getattr(result, 'IPAddresses', [])),
                        'Obfuscated JS': len(getattr(result, 'ObfuscatedJavaScript', [])),
                        'Suspicious Commands': len(getattr(result, 'SuspiciousCommands', []))
                    })
                
                summary_df = pd.DataFrame(summary_data)
                
                numeric_columns = [col for col in summary_df.columns if col not in ['URL', 'Threat Level']]
                st.dataframe(summary_df.style.background_gradient(cmap='YlOrRd', subset=numeric_columns), use_container_width=True)
                
                for i, result in enumerate(results_list):
                    with st.expander(f"Detailed Analysis for {getattr(result, 'URL', 'Unknown')}"):
                        threat_level, badge_class = get_threat_level(result)
                        st.markdown(f"<span class='status-badge {badge_class}'>{threat_level} Threat</span>", unsafe_allow_html=True)
                        
                        render_indicators_section(result)
                        render_detailed_analysis(result, use_expanders=False)
                        render_raw_html(result, use_expander=False)
                
                st.markdown("## Download Reports")
                report_format = st.radio(
                    "Select report format:",
                    ["HTML", "JSON", "CSV"],
                    horizontal=True
                )
                
                if report_format == "HTML":
                    download_link = download_report(results_list, "html")
                elif report_format == "JSON":
                    download_link = download_report(results_list, "json")
                else:
                    download_link = download_report(results_list, "csv")
                
                st.markdown(download_link, unsafe_allow_html=True)
            elif analyze_found:
                with st.spinner("Analyzing URLs..."):
                    results_list = analyze_multiple_urls(urls)
                    
                    if results_list:
                        # Store results in session state
                        st.session_state.multi_analysis_results = results_list
                        
                        st.markdown("## Download Reports")
                        report_format = st.radio(
                            "Select report format:",
                            ["HTML", "JSON", "CSV"],
                            horizontal=True
                        )
                        
                        if report_format == "HTML":
                            download_link = download_report(results_list, "html")
                        elif report_format == "JSON":
                            download_link = download_report(results_list, "json")
                        else: 
                            download_link = download_report(results_list, "csv")
                        
                        st.markdown(download_link, unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### About")
    st.sidebar.info(
        "ClickGrab Analyzer is a tool designed to identify and analyze websites "
        "that may be using FakeCAPTCHA or ClickFix techniques to distribute malware "
        "or steal information. It analyzes HTML content for potential threats like "
        "PowerShell commands, suspicious URLs, and clipboard manipulation code."
    )

if __name__ == "__main__":
    main() 