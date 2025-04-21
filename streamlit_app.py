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

# Import functions from clickgrab.py
from clickgrab import (
    analyze_url,
    extract_base64_strings,
    extract_urls,
    extract_powershell_commands,
    extract_ip_addresses,
    extract_clipboard_commands,
    extract_suspicious_keywords,
    extract_clipboard_manipulation,
    extract_powershell_downloads,
    download_urlhaus_data
)

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
</style>
""", unsafe_allow_html=True)

def local_css(file_name):
    """Load and inject local CSS"""
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

def get_threat_level(results):
    """Calculate threat level based on analysis results"""
    score = 0
    
    # PowerShell commands are highly suspicious
    if len(results.get('PowerShellCommands', [])) > 0:
        score += 30
    
    # PowerShell downloads are highly suspicious
    if len(results.get('PowerShellDownloads', [])) > 0:
        score += 30
    
    # Clipboard manipulation is suspicious
    if len(results.get('ClipboardManipulation', [])) > 0:
        score += 20
    
    # Clipboard commands are suspicious
    if len(results.get('ClipboardCommands', [])) > 0:
        score += 20
    
    # Base64 strings might be suspicious
    if len(results.get('Base64Strings', [])) > 0:
        score += min(15, len(results.get('Base64Strings', [])))
    
    # Suspicious keywords
    if len(results.get('SuspiciousKeywords', [])) > 0:
        score += min(30, len(results.get('SuspiciousKeywords', [])) * 3)
    
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
    
    has_indicators = (
        len(results.get('URLs', [])) > 0 or 
        len(results.get('IPAddresses', [])) > 0 or 
        len(results.get('PowerShellDownloads', [])) > 0 or 
        len(results.get('PowerShellCommands', [])) > 0 or
        len(results.get('SuspiciousKeywords', [])) > 0
    )
    
    if not has_indicators:
        st.info("No significant indicators of compromise found.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        if len(results.get('URLs', [])) > 0:
            st.markdown("#### Suspicious URLs")
            for url in results.get('URLs', []):
                if (url.endswith('.ps1') or url.endswith('.exe') or 
                    url.endswith('.bat') or url.endswith('.cmd') or 
                    url.endswith('.hta') or 'cdn' in url or 
                    not url.startswith('http://www.w3.org')):
                    st.markdown(f'<span class="url-badge">URL</span> <a href="{url}" target="_blank">{url}</a>', 
                                unsafe_allow_html=True)
        
        if len(results.get('PowerShellDownloads', [])) > 0:
            st.markdown("#### PowerShell Download URLs")
            for ps_download in results.get('PowerShellDownloads', []):
                if isinstance(ps_download, dict) and 'URL' in ps_download and ps_download['URL']:
                    st.markdown(f'<span class="ps-badge">PS Download</span> {ps_download["URL"]}', 
                                unsafe_allow_html=True)
    
    with col2:
        if len(results.get('IPAddresses', [])) > 0:
            st.markdown("#### IP Addresses")
            for ip in results.get('IPAddresses', []):
                st.markdown(f'<span class="ip-badge">IP</span> {ip}', unsafe_allow_html=True)
        
        if len(results.get('PowerShellCommands', [])) > 0:
            st.markdown("#### PowerShell Commands")
            for cmd in results.get('PowerShellCommands', []):
                st.markdown(f'<span class="ps-badge">PowerShell</span> {cmd}', unsafe_allow_html=True)
    
    if len(results.get('SuspiciousKeywords', [])) > 0:
        st.markdown("#### Suspicious Keywords")
        keywords_cols = st.columns(3)
        for i, keyword in enumerate(results.get('SuspiciousKeywords', [])):
            col_index = i % 3
            with keywords_cols[col_index]:
                st.markdown(f'<span class="suspicious-badge">Suspicious</span> {keyword}', 
                            unsafe_allow_html=True)

def render_detailed_analysis(results, use_expanders=True):
    """Render the detailed analysis section"""
    st.markdown("### Detailed Analysis")
    
    tabs = st.tabs([
        "Base64 Strings", 
        "URLs", 
        "PowerShell Commands",
        "IP Addresses",
        "Clipboard Commands",
        "Suspicious Keywords",
        "Clipboard Manipulation",
        "PowerShell Downloads"
    ])
    
    with tabs[0]:
        if len(results.get('Base64Strings', [])) > 0:
            st.markdown(f"Found **{len(results.get('Base64Strings', []))}** Base64 strings")
            for i, b64 in enumerate(results.get('Base64Strings', [])):
                if isinstance(b64, dict) and 'Base64' in b64 and 'Decoded' in b64:
                    if use_expanders:
                        with st.expander(f"Base64 String {i+1}"):
                            st.code(b64['Base64'], language="text")
                            st.markdown("**Decoded:**")
                            st.code(b64['Decoded'], language="text")
                    else:
                        # Alternative to expanders for nested contexts
                        st.markdown(f"**Base64 String {i+1}:**")
                        st.code(b64['Base64'], language="text")
                        st.markdown("**Decoded:**")
                        st.code(b64['Decoded'], language="text")
                        st.markdown("---")
        else:
            st.info("No Base64 strings found.")
    
    with tabs[1]:
        if len(results.get('URLs', [])) > 0:
            st.markdown(f"Found **{len(results.get('URLs', []))}** URLs")
            for i, url in enumerate(results.get('URLs', [])):
                st.markdown(f"{i+1}. [{url}]({url})")
        else:
            st.info("No URLs found.")
    
    with tabs[2]:
        if len(results.get('PowerShellCommands', [])) > 0:
            st.markdown(f"Found **{len(results.get('PowerShellCommands', []))}** PowerShell commands")
            for i, cmd in enumerate(results.get('PowerShellCommands', [])):
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
        if len(results.get('IPAddresses', [])) > 0:
            st.markdown(f"Found **{len(results.get('IPAddresses', []))}** IP addresses")
            for i, ip in enumerate(results.get('IPAddresses', [])):
                st.markdown(f"{i+1}. `{ip}`")
        else:
            st.info("No IP addresses found.")
    
    with tabs[4]:
        if len(results.get('ClipboardCommands', [])) > 0:
            st.markdown(f"Found **{len(results.get('ClipboardCommands', []))}** clipboard commands")
            for i, cmd in enumerate(results.get('ClipboardCommands', [])):
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
        if len(results.get('SuspiciousKeywords', [])) > 0:
            st.markdown(f"Found **{len(results.get('SuspiciousKeywords', []))}** suspicious keywords")
            for i, keyword in enumerate(results.get('SuspiciousKeywords', [])):
                st.markdown(f"{i+1}. `{keyword}`")
        else:
            st.info("No suspicious keywords found.")
    
    with tabs[6]:
        if len(results.get('ClipboardManipulation', [])) > 0:
            st.markdown(f"Found **{len(results.get('ClipboardManipulation', []))}** clipboard manipulation instances")
            for i, manip in enumerate(results.get('ClipboardManipulation', [])):
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
        if len(results.get('PowerShellDownloads', [])) > 0:
            st.markdown(f"Found **{len(results.get('PowerShellDownloads', []))}** PowerShell download commands")
            for i, download in enumerate(results.get('PowerShellDownloads', [])):
                if isinstance(download, dict):
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
        else:
            st.info("No PowerShell downloads found.")

def render_raw_html(results, use_expander=True):
    """Render the raw HTML section"""
    st.markdown("### Raw HTML Content")
    
    if use_expander:
        with st.expander("Show Raw HTML"):
            st.code(results.get('RawHTML', ''), language="html")
    else:
        toggle = st.checkbox("Show Raw HTML", key=f"raw_html_{id(results)}")
        if toggle:
            st.code(results.get('RawHTML', ''), language="html")

def analyze_single_url(url):
    """Analyze a single URL and show results"""
    with st.spinner(f"Analyzing URL: {url}"):
        results = analyze_url(url)
        
    if not results:
        st.error(f"Error analyzing URL: {url}")
        return
    
    st.markdown(f"## Analysis Results for: [{url}]({url})")
    
    threat_level, badge_class = get_threat_level(results)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(results.get('Base64Strings', []))}</div>
            <div>Base64 Strings</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(results.get('PowerShellCommands', []))}</div>
            <div>PowerShell Commands</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{len(results.get('SuspiciousKeywords', []))}</div>
            <div>Suspicious Keywords</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="stat-card">
            <span class="status-badge {badge_class}">{threat_level} Threat</span>
            <div class="stat-number">{sum([
                len(results.get('Base64Strings', [])),
                len(results.get('URLs', [])),
                len(results.get('PowerShellCommands', [])),
                len(results.get('IPAddresses', [])),
                len(results.get('ClipboardCommands', [])),
                len(results.get('SuspiciousKeywords', [])),
                len(results.get('ClipboardManipulation', [])),
                len(results.get('PowerShellDownloads', []))
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
        url = result.get('URL', 'Unknown')
        threat_level, _ = get_threat_level(result)
        total_findings = sum([
            len(result.get('Base64Strings', [])),
            len(result.get('URLs', [])),
            len(result.get('PowerShellCommands', [])),
            len(result.get('IPAddresses', [])),
            len(result.get('ClipboardCommands', [])),
            len(result.get('SuspiciousKeywords', [])),
            len(result.get('ClipboardManipulation', [])),
            len(result.get('PowerShellDownloads', []))
        ])
        
        summary_data.append({
            'URL': url,
            'Threat Level': threat_level,
            'Total Findings': total_findings,
            'Base64 Strings': len(result.get('Base64Strings', [])),
            'PowerShell Commands': len(result.get('PowerShellCommands', [])),
            'PowerShell Downloads': len(result.get('PowerShellDownloads', [])),
            'Suspicious Keywords': len(result.get('SuspiciousKeywords', [])),
            'Clipboard Manipulation': len(result.get('ClipboardManipulation', [])),
            'IP Addresses': len(result.get('IPAddresses', []))
        })
    
    summary_df = pd.DataFrame(summary_data)
    
    numeric_columns = [col for col in summary_df.columns if col not in ['URL', 'Threat Level']]
    st.dataframe(summary_df.style.background_gradient(cmap='YlOrRd', subset=numeric_columns), use_container_width=True)
    
    for i, result in enumerate(results_list):
        with st.expander(f"Detailed Analysis for {result.get('URL', 'Unknown')}"):
            threat_level, badge_class = get_threat_level(result)
            st.markdown(f"<span class='status-badge {badge_class}'>{threat_level} Threat</span>", unsafe_allow_html=True)
            
            render_indicators_section(result)
            render_detailed_analysis(result, use_expanders=False)
            render_raw_html(result, use_expander=False)
    
    return results_list

def download_report(results, file_format="html"):
    """Create a downloadable report"""
    if file_format == "json":
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_base64_strings': sum(len(site.get('Base64Strings', [])) for site in results),
                'total_urls': sum(len(site.get('URLs', [])) for site in results),
                'total_powershell_commands': sum(len(site.get('PowerShellCommands', [])) for site in results),
                'total_ip_addresses': sum(len(site.get('IPAddresses', [])) for site in results),
                'total_clipboard_commands': sum(len(site.get('ClipboardCommands', [])) for site in results),
                'total_suspicious_keywords': sum(len(site.get('SuspiciousKeywords', [])) for site in results)
            },
            'sites': results
        }
        
        json_str = json.dumps(report, indent=2)
        
        b64 = base64.b64encode(json_str.encode()).decode()
        href = f'<a href="data:application/json;base64,{b64}" download="clickgrab_report.json">Download JSON Report</a>'
        return href
    
    elif file_format == "csv":
        data = []
        for site in results:
            data.append({
                'URL': site.get('URL', 'Unknown'),
                'Base64 Strings Count': len(site.get('Base64Strings', [])),
                'URLs Count': len(site.get('URLs', [])),
                'PowerShell Commands Count': len(site.get('PowerShellCommands', [])),
                'IP Addresses Count': len(site.get('IPAddresses', [])),
                'Clipboard Commands Count': len(site.get('ClipboardCommands', [])),
                'Suspicious Keywords Count': len(site.get('SuspiciousKeywords', [])),
                'Clipboard Manipulation Count': len(site.get('ClipboardManipulation', [])),
                'PowerShell Downloads Count': len(site.get('PowerShellDownloads', []))
            })
        
        df = pd.DataFrame(data)
        csv = df.to_csv(index=False)
        
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:text/csv;base64,{b64}" download="clickgrab_report.csv">Download CSV Report</a>'
        return href
    
    else: 
        from clickgrab import create_html_report
        
        temp_dir = Path("temp_reports")
        temp_dir.mkdir(exist_ok=True)
        
        html_path = create_html_report(results, temp_dir)
        
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
        
        st.session_state.url_input = st.text_input(
            "Enter URL to Analyze",
            value=st.session_state.url_input,
            placeholder="https://example.com/suspicious-page.html"
        )
        
        analyze_button = st.button("Analyze URL")
        
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
        
        st.session_state.urls_text = st.text_area(
            "Enter URLs (one per line)",
            value=st.session_state.urls_text,
            placeholder="https://example1.com/page.html\nhttps://example2.com/page.html"
        )
        
        analyze_button = st.button("Analyze URLs")
        
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
                url = result.get('URL', 'Unknown')
                threat_level, _ = get_threat_level(result)
                total_findings = sum([
                    len(result.get('Base64Strings', [])),
                    len(result.get('URLs', [])),
                    len(result.get('PowerShellCommands', [])),
                    len(result.get('IPAddresses', [])),
                    len(result.get('ClipboardCommands', [])),
                    len(result.get('SuspiciousKeywords', [])),
                    len(result.get('ClipboardManipulation', [])),
                    len(result.get('PowerShellDownloads', []))
                ])
                
                summary_data.append({
                    'URL': url,
                    'Threat Level': threat_level,
                    'Total Findings': total_findings,
                    'Base64 Strings': len(result.get('Base64Strings', [])),
                    'PowerShell Commands': len(result.get('PowerShellCommands', [])),
                    'PowerShell Downloads': len(result.get('PowerShellDownloads', [])),
                    'Suspicious Keywords': len(result.get('SuspiciousKeywords', [])),
                    'Clipboard Manipulation': len(result.get('ClipboardManipulation', [])),
                    'IP Addresses': len(result.get('IPAddresses', []))
                })
            
            summary_df = pd.DataFrame(summary_data)
            
            numeric_columns = [col for col in summary_df.columns if col not in ['URL', 'Threat Level']]
            st.dataframe(summary_df.style.background_gradient(cmap='YlOrRd', subset=numeric_columns), use_container_width=True)
            
            for i, result in enumerate(results_list):
                with st.expander(f"Detailed Analysis for {result.get('URL', 'Unknown')}"):
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
        
        search_button = st.button("Search URLhaus")
        
        if search_button:
            tags = [tag.strip() for tag in st.session_state.urlhaus_tags.split(',') if tag.strip()]
            
            with st.spinner("Searching URLhaus database..."):
                urls = download_urlhaus_data(limit=st.session_state.urlhaus_limit, tags=tags)
            
            if urls:
                # Store results in session state
                st.session_state.urlhaus_results = urls
                
                st.success(f"Found {len(urls)} matching URLs")
                
                urls_df = pd.DataFrame({"URLs": urls})
                st.dataframe(urls_df, use_container_width=True)
                
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
                    url = result.get('URL', 'Unknown')
                    threat_level, _ = get_threat_level(result)
                    total_findings = sum([
                        len(result.get('Base64Strings', [])),
                        len(result.get('URLs', [])),
                        len(result.get('PowerShellCommands', [])),
                        len(result.get('IPAddresses', [])),
                        len(result.get('ClipboardCommands', [])),
                        len(result.get('SuspiciousKeywords', [])),
                        len(result.get('ClipboardManipulation', [])),
                        len(result.get('PowerShellDownloads', []))
                    ])
                    
                    summary_data.append({
                        'URL': url,
                        'Threat Level': threat_level,
                        'Total Findings': total_findings,
                        'Base64 Strings': len(result.get('Base64Strings', [])),
                        'PowerShell Commands': len(result.get('PowerShellCommands', [])),
                        'PowerShell Downloads': len(result.get('PowerShellDownloads', [])),
                        'Suspicious Keywords': len(result.get('SuspiciousKeywords', [])),
                        'Clipboard Manipulation': len(result.get('ClipboardManipulation', [])),
                        'IP Addresses': len(result.get('IPAddresses', []))
                    })
                
                summary_df = pd.DataFrame(summary_data)
                
                numeric_columns = [col for col in summary_df.columns if col not in ['URL', 'Threat Level']]
                st.dataframe(summary_df.style.background_gradient(cmap='YlOrRd', subset=numeric_columns), use_container_width=True)
                
                for i, result in enumerate(results_list):
                    with st.expander(f"Detailed Analysis for {result.get('URL', 'Unknown')}"):
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