# ClickGrab

<p align="center">
  <img src="assets/logo.png?v=2" alt="ClickGrab Logo" width="400">
</p>


> **✨ NEW: ClickGrab now has a full Python rewrite!** 

## Python

The new Python version of ClickGrab offers enhanced capabilities with simplified usage. Below are the available options and common usage scenarios.

### Command-Line Options

```
python clickgrab.py [URL or file] [options]
```

* **Positional argument**:
  * `URL or file` - A URL to analyze or a path to a file containing URLs (one per line)

* **Options**:
  * `--limit N` - Limit the number of URLs to process
  * `--debug` - Enable detailed debug output
  * `--output-dir DIR` - Specify directory for report output (default: "reports")
  * `--format {html,json,csv,all}` - Report format (default: "all")
  * `--tags TAGS` - Comma-separated list of tags to filter by (default: "FakeCaptcha,ClickFix,click")
  * `--download` - Download and analyze URLs from URLhaus
  * `--otx` - Download and analyze URLs from AlienVault OTX
  * `--days N` - Number of days to look back in AlienVault OTX (default: 30)

### Example Commands

```bash
# Analyze a single URL
python clickgrab.py https://suspicious-site.example.com

# Analyze multiple URLs from a file
python clickgrab.py urls.txt

# Download and analyze recent URLhaus samples
python clickgrab.py --download --limit 10

# Download from AlienVault OTX, looking for specific tags
python clickgrab.py --otx --tags "FakeCaptcha,CloudflarePhish" --days 15

# Analyze from URLhaus with specific output format
python clickgrab.py --download --format json --output-dir custom_reports

# Combine sources (URLhaus + OTX)
python clickgrab.py --download --otx --limit 20

# Debug mode for verbose output
python clickgrab.py suspicious_urls.txt --debug
```

### Output

By default, ClickGrab generates three types of reports in the `reports` directory:

1. **HTML Report** - Interactive report with color-coded threat scores, expandable sections, and IOC highlighting
2. **JSON Report** - Complete analysis data in JSON format for programmatic processing
3. **CSV Report** - Tabular summary of key findings for spreadsheet analysis


## PowerShell

This script performs the following actions:

1.  **Downloads Data:** Fetches the latest online URL data (CSV format) from URLhaus (`https://urlhaus.abuse.ch/downloads/csv_online/`).
2.  **Filters URLs:** Filters the downloaded data based on specified tags (defaulting to `FakeCaptcha`, `ClickFix`, `click`) and recent submission dates (last 7 days, unless disabled). It also applies a basic URL pattern filter (`/`, `.html`, `.htm`).
3.  **Operates in Two Modes:**
    *   **Browser Mode (Default):** Opens the filtered URLs one by one in the specified browser. It waits for user interaction (presumably clicking a fake CAPTCHA) and captures the clipboard content afterwards.
    *   **Analyze Mode (`-Analyze`):** Downloads the HTML content of each filtered URL without opening a browser. It analyzes the HTML for potential indicators of compromise (IOCs) such as:
        *   Base64 encoded strings (and attempts decoding)
        *   Embedded URLs and IP addresses
        *   Potential PowerShell commands
        *   JavaScript clipboard manipulation patterns
        *   PowerShell download commands (IWR, DownloadString, BitsTransfer)
        *   Links to `.ps1` or `.hta` files
        *   Suspicious keywords (malware terms, execution commands, etc.)
4.  **Generates Output:**
    *   **Browser Mode:** Creates a CSV file (`clickygrab_browser_output_*.csv`) containing the URL, date added, tags, and the captured clipboard content.
    *   **Analyze Mode:** Creates an output directory (`ClickFix_Output_*`) containing:
        *   `RawHtml/`: Raw HTML content for each analyzed URL.
        *   `Analysis/`: Detailed JSON analysis reports for each URL.
        *   `Summaries/`: Plain text summaries for each URL.
        *   `Downloads/`: Any `.ps1` or `.hta` files successfully downloaded during analysis.
        *   `consolidated_report.json`: A single JSON file containing the analysis results for all processed URLs.
        *   `consolidated_report.html`: An HTML report summarizing the findings across all analyzed URLs, with links to individual reports.
        *   A main CSV file (`clickygrab_analysis_output_*.csv`) listing the URLs processed and referencing their summary files.

## Parameters

*   `-Test`: (Switch) Run in test mode. Does not open/download real URLs, uses placeholder data/actions.
*   `-Limit <Int>`: Limit the number of URLs to process.
*   `-UseBrowser <String>`: Specify the browser ("firefox", "edge", "chrome"). Defaults to "firefox". Only used in Browser Mode.
*   `-Tags <String>`: Comma-separated list of tags to filter for (e.g., "FakeCaptcha,ClickFix"). Use `"*"` to match any tag. Defaults to "FakeCaptcha,ClickFix,click".
*   `-Debug`: (Switch) Enable verbose debug output during filtering and processing.
*   `-IgnoreDateCheck`: (Switch) Disable the 7-day date filter, processing older URLs.
*   `-Original`: (Switch) Use the original, simpler filtering logic (tags contain "click", URL ends with `/`, `html`, or `htm`).
*   `-Analyze`: (Switch) Run in Analyze mode instead of Browser mode.


## Usage Examples

```powershell
# Default run: Open URLs in Firefox, capture clipboard after interaction
.\clickgrab.ps1

# Analyze mode: Download HTML, analyze, create reports (no browser interaction)
.\clickgrab.ps1 -Analyze

# Analyze mode, only process 5 URLs, ignore date limits
.\clickgrab.ps1 -Analyze -Limit 5 -IgnoreDateCheck

# Test mode with Edge browser, filter only for "FakeCaptcha"
.\clickgrab.ps1 -Test -UseBrowser edge -Tags "FakeCaptcha"

# Analyze mode, include all tags, enable debug output
.\clickgrab.ps1 -Analyze -Tags "*" -Debug
```

The tool also creates a consolidated `latest_consolidated_report.json` in the root directory for GitHub Actions integration.

## Automated Nightly Analysis

This repository includes a GitHub Actions workflow (`.github/workflows/nightly_run.yml`) that runs the script in `-Analyze` mode every night. The workflow:

1. Runs the full analysis on the latest URLhaus data
2. Maintains two types of reports:
   - `latest_consolidated_report.json` - Always contains the most recent analysis
   - Date-stamped reports in the `nightly_reports/` directory (e.g., `clickgrab_report_2023-04-18.json`)

## Online Reports

We host the HTML analysis reports via GitHub Pages:

**[View Latest FakeCAPTCHA Analysis Report](https://mhaggis.github.io/ClickGrab/)**

These auto-updated reports provide:
- The most current analysis of ClickFix/FakeCAPTCHA URLs
- A searchable historical archive of previous reports
- Direct access to the extracted IOCs and malicious code samples

This allows security researchers to quickly assess current FakeCAPTCHA trends without running the tool locally.

## Interactive Streamlit App

We now offer an interactive web application for analyzing and exploring FakeCAPTCHA/ClickFix URLs:

**[ClickGrab Interactive Analyzer](https://clickgrab.streamlit.app/)**

The Streamlit app provides:
- Real-time analysis of suspicious URLs
- Interactive exploration of malicious indicators
- Detailed visual reports of findings
- Multiple analysis modes (single URL, batch analysis, URLhaus integration)
- Downloadable reports in HTML, JSON, and CSV formats

This makes ClickGrab's powerful analysis capabilities accessible to everyone without needing to run any code locally.

## Special Thanks

This was not possible without the initial tag from @nterl0k

# CAPTCHA Detection Enhancements

The latest update includes significant improvements to the CAPTCHA and phishing detection capabilities:

1. **Enhanced PowerShell Command Detection**
   - Improved detection of base64-encoded PowerShell commands
   - Better identification of obfuscated commands using `cmd /c start` patterns
   - Added support for detecting PowerShell commands in clipboard copy operations

2. **Improved Base64 Detection**
   - Now detects JavaScript `atob()` function calls specifically
   - Better handling of base64 strings passed to DOM elements
   - Enhanced context tracking for base64 encoded content

3. **Expanded Fake CAPTCHA Element Patterns**
   - Added detection for common fake Cloudflare captcha UI elements
   - Enhanced detection of "Fix It" button patterns common in phishing pages
   - Added support for detecting modal dialogs masquerading as security checks

4. **Clipboard Manipulation Detection**
   - Better detection of clipboard writes that contain malicious commands
   - Enhanced tracking of DOM select/copy patterns used in phishing attacks
   - Improved detection of hidden textarea elements used for storing commands

5. **Additional Social Engineering Indicators**
   - Added patterns for detecting "Press Windows+R" instructions
   - Enhanced detection of fake security messages
   - Added patterns for identifying fake Cloudflare security headers and Ray IDs

6. **Obfuscated JavaScript Detection**
   - Detection of variable obfuscation patterns (e.g., `var _0x2a=['Y21k','L2M=']`)
   - Identification of script tags with suspicious attributes or external references
   - Recognition of common JavaScript obfuscation techniques and patterns
   - Detection of encoded arrays used to store obfuscated commands
   - Improved analysis of dynamically constructed JavaScript execution paths

These improvements significantly increase the tool's ability to detect sophisticated phishing attacks that utilize fake CAPTCHA verification, clipboard hijacking techniques, and obfuscated JavaScript to evade detection.