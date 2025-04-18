# ClickGrab


<p align="center">
  <img src="assets/logo.png" alt="ClickGrab Logo" width="400">
</p>



A PowerShell script to download and analyze potential ClickFix URLs (ClickFix, FakeCAPTCHA, etc.) reported to URLhaus.

## Description

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

## Special Thanks

This was not possible without the initial tag from @nterl0k
