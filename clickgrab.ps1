<#
.SYNOPSIS
    URLhaus ClickFix URL Grabber

.DESCRIPTION
    This script downloads data from URLhaus and filters for ClickFix URLs with specific tags
    (such as FakeCaptcha, ClickFix, click). It provides two operational modes:

    1. Browser Mode (Default):
       - Opens filtered URLs in a specified browser (Firefox, Edge, or Chrome)
       - Waits for user interaction with fake CAPTCHA pages
       - Captures clipboard content after interaction
       - Saves results to a CSV file

    2. Analyze Mode (-Analyze):
       - Downloads HTML content from filtered URLs without opening a browser
       - Analyzes content for potential threats:
         * Base64 encoded strings (with decoding attempts)
         * Embedded URLs and IP addresses
         * PowerShell commands and download instructions
         * JavaScript clipboard manipulation code
         * Links to potentially malicious files (.ps1, .hta)
         * Suspicious keywords and commands
       - Generates detailed HTML and JSON reports with the findings

    The script provides extensive filtering options, including tag-based filtering, 
    date restrictions, and URL pattern matching.

.PARAMETER Test
    Run in test mode without opening actual URLs

.PARAMETER Limit
    Limit number of URLs to process

.PARAMETER UseBrowser
    Specify the browser to use (default is "firefox"). Options: firefox, edge, chrome

.PARAMETER Tags
    Comma-separated list of tags to filter for. Default is "FakeCaptcha,ClickFix,click"
    Use '*' to match any ClickFix URL regardless of tags

.PARAMETER Debug
    Enable debug mode to show extra information

.PARAMETER IgnoreDateCheck
    Disable date check for URLs

.PARAMETER Original
    Use original filter logic instead of the new one

.PARAMETER Analyze
    Enable analyze mode to download and analyze HTML content instead of opening in browser

.EXAMPLE
    # Normal run (opens URLs in Firefox)
    .\clickgrab.ps1

.EXAMPLE
    # Test run with sample data (no actual URLs opened)
    .\clickgrab.ps1 -Test -Sample

.EXAMPLE
    # Process only first 3 URLs
    .\clickgrab.ps1 -Limit 3

.EXAMPLE
    # Use Microsoft Edge browser
    .\clickgrab.ps1 -UseBrowser edge

.EXAMPLE
    # Filter for specific tags
    .\clickgrab.ps1 -Tags "FakeCaptcha,ClickFix"

.NOTES
    Author: The Haag
    Special Thanks: nterl0k
    
    When running normally (not in test mode), you'll need to manually
    interact with each fake CAPTCHA page. The script waits 10 seconds
    for you to do this before capturing the clipboard content.
#>

param (
    [switch]$Test,
    [int]$Limit,
    [string]$UseBrowser = "firefox",
    [string]$Tags = "FakeCaptcha,ClickFix,click",
    [switch]$Debug,
    [switch]$IgnoreDateCheck,
    [switch]$Original,
    [switch]$Analyze
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "Starting URLhaus ClickFix URL grabber..." -ForegroundColor Cyan

function Ensure-TempDir {
    $tempDir = "C:\Temp"
    if (-not (Test-Path $tempDir)) {
        New-Item -ItemType Directory -Path $tempDir | Out-Null
        Write-Host "Created temp directory at $tempDir" -ForegroundColor Yellow
    }
    return $tempDir
}

function Ensure-OutputDir {
    $currentDir = Get-Location
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputDir = Join-Path $currentDir "ClickFix_Output_$timestamp"
    
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
        Write-Host "Created output directory at $outputDir" -ForegroundColor Yellow
    }
    
    $rawHtmlDir = Join-Path $outputDir "RawHtml"
    $analysisDir = Join-Path $outputDir "Analysis"
    $summaryDir = Join-Path $outputDir "Summaries"
    
    New-Item -ItemType Directory -Path $rawHtmlDir -Force | Out-Null
    New-Item -ItemType Directory -Path $analysisDir -Force | Out-Null
    New-Item -ItemType Directory -Path $summaryDir -Force | Out-Null
    
    return [PSCustomObject]@{
        MainDir = $outputDir
        RawHtmlDir = $rawHtmlDir
        AnalysisDir = $analysisDir
        SummaryDir = $summaryDir
    }
}

function Get-FakeCaptchaResponse {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $verificationId = -join ((1..8) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    
    $responses = @(
        "I am not a robot - reCAPTCHA Verification ID: $verificationId",
        "✅ Verification successful - Hash: $verificationId",
        "Ray ID: $verificationId • Human verification complete",
        "I am human - Verification ID: $verificationId"
    )
    
    return $responses | Get-Random
}

function Extract-Base64Strings {
    param (
        [string]$Text
    )
    
    $base64Pattern = '[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    $matches = [regex]::Matches($Text, $base64Pattern)
    
    $results = @()
    foreach ($match in $matches) {
        if ($match.Length -gt 16) {  # Only consider strings that are reasonably long
            try {
                $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($match))
                if ($decoded -match '[\x20-\x7E]{8,}') {
                    $results += [PSCustomObject]@{
                        Base64 = $match.Value
                        Decoded = $decoded
                    }
                }
            }
            catch {}
        }
    }
    
    return $results
}

function Extract-Urls {
    param (
        [string]$Text
    )
    
    $urlPattern = '(https?:\/\/[^\s"''<>\)\(]+)'
    $matches = [regex]::Matches($Text, $urlPattern)
    
    $results = @()
    foreach ($match in $matches) {
        $results += $match.Value
    }
    
    return $results
}

function Extract-PowerShellCommands {
    param (
        [string]$Text
    )
    
    $cmdPatterns = @(
        'powershell(?:.exe)?\s+(?:-\w+\s+)*.*',
        'iex\s*\(.*\)',
        'invoke-expression.*',
        'invoke-webrequest.*',
        'wget\s+.*',
        'curl\s+.*',
        'net\s+use.*',
        'new-object\s+.*'
    )
    
    $results = @()
    foreach ($pattern in $cmdPatterns) {
        $matches = [regex]::Matches($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $results += $match.Value
        }
    }
    
    return $results
}

function Extract-IpAddresses {
    param (
        [string]$Text
    )
    
    $ipPattern = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    $matches = [regex]::Matches($Text, $ipPattern)
    
    $results = @()
    foreach ($match in $matches) {
        $results += $match.Value
    }
    
    return $results
}

function Extract-ClipboardCommands {
    param (
        [string]$Html
    )
    
    $results = @()
    
    $clipboardFuncPattern = 'function\s+(?:setClipboard|copyToClipboard|stageClipboard).*?\{(.*?)\}'
    $clipboardFuncMatches = [regex]::Matches($Html, $clipboardFuncPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    
    foreach ($match in $clipboardFuncMatches) {
        $funcBody = $match.Groups[1].Value
        $varAssignPattern = 'const\s+(\w+)\s*=\s*[''"](.+?)[''"]'
        $varMatches = [regex]::Matches($funcBody, $varAssignPattern)
        
        $vars = @{}
        foreach ($varMatch in $varMatches) {
            $vars[$varMatch.Groups[1].Value] = $varMatch.Groups[2].Value
        }
        
        $copyPattern = 'textToCopy\s*=\s*(.+)'
        $copyMatches = [regex]::Matches($funcBody, $copyPattern)
        
        foreach ($copyMatch in $copyMatches) {
            $copyExpr = $copyMatch.Groups[1].Value.Trim()
            foreach ($var in $vars.Keys) {
                if ($copyExpr -eq $var) {
                    $results += $vars[$var]
                }
            }
        }
    }
    
    $cmdPattern = 'const\s+commandToRun\s*=\s*[`''"](.+?)[`''"]'
    $cmdMatches = [regex]::Matches($Html, $cmdPattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
    
    foreach ($match in $cmdMatches) {
        $results += $match.Groups[1].Value
    }
    
    return $results
}

function Extract-SuspiciousKeywords {
    param (
        [string]$Text
    )
    
    $suspiciousPatterns = @(
        # Command execution
        'cmd(?:.exe)?\s+(?:/\w+\s+)*.*',
        'command(?:.com)?\s+(?:/\w+\s+)*.*',
        'bash\s+-c\s+.*',
        'sh\s+-c\s+.*',
        'exec\s+.*',
        'system\s*\(.*\)',
        'exec\s*\(.*\)',
        'eval\s*\(.*\)',
        'execSync\s*\(.*\)',
        
        # Scripting languages
        'python(?:3)?\s+.*',
        'ruby\s+.*',
        'perl\s+.*',
        'php\s+.*',
        'node\s+.*',
        
        # Download and execution patterns
        'wget\s+.*\s+\|\s+bash',
        'curl\s+.*\s+\|\s+sh',
        'curl\s+.*\s+-o\s+.*',
        'wget\s+.*\s+-O\s+.*',
        'certutil\s+-urlcache\s+-f\s+.*',
        'bitsadmin\s+/transfer\s+.*',
        
        # Registry modification
        'reg(?:.exe)?\s+(?:add|delete|query)\s+.*',
        'regedit\s+.*',
        
        # Process manipulation
        'taskkill\s+.*',
        'tasklist\s+.*',
        'wmic\s+process\s+.*',
        'sc\s+(?:create|config|start|stop)\s+.*',
        
        # Privilege escalation
        'sudo\s+.*',
        'runas\s+.*',
        
        # Network commands
        'netsh\s+.*',
        'nslookup\s+.*',
        'ipconfig\s+.*',
        'ifconfig\s+.*',
        'nmap\s+.*',
        'net\s+(?:user|group|localgroup)\s+.*',
        
        # Evasion techniques
        'timeout\s+\d+',
        'sleep\s+\d+',
        'ping\s+-n\s+\d+',
        'attrib\s+[+\-][rhs]',
        'icacls\s+.*',
        'cacls\s+.*',
        
        # Common malware keywords
        'bypass',
        'shellcode',
        'payload',
        'exploit',
        'keylogger',
        'rootkit',
        'backdoor',
        'trojan',
        'ransomware',
        'exfiltration',
        'obfuscated',
        'encrypted',
        
        # Cryptocurrency
        'bitcoin',
        'wallet',
        'miner',
        'monero',
        'ethereum',
        'crypto',
        
        # CAPTCHA verification phrases
        '✓',
        '✅',
        'white_check_mark',
        'I am not a robot',
        'I am human',
        'Ray ID',
        'Verification ID',
        'Verification Hash',
        'Human verification complete',
        'reCAPTCHA Verification',
        'Verification successful',
        
        # Cloud identifiers observed in malicious code
        'Cloud ID(?:entifier)?:?\s*\d+',
        'Cloud Identifier:?\s*\d+',
        'Cloud ID:?\s*\d+',
        
        'Press Win\+R',
        'Press Windows\+R',
        'Copy and paste this code',
        'To verify you''re human',
        'Type the following command',
        'To confirm you are not a bot',
        'Verification session',
        'Verification token:',
        'Security verification required',
        'Anti-bot verification',
        'Solve this CAPTCHA by',
        'Complete verification by typing',
        'Bot detection bypassed',
        'Human verification complete',
        'Copy this command to proceed',
        'Paste in command prompt',
        'Paste in PowerShell',
        'Start\s+->?\s+Run',
        'Press\s+Ctrl\+C\s+to\s+copy',
        'Press\s+Ctrl\+V\s+to\s+paste',
        
        'Press\s+(?:Ctrl|Alt|Shift|Win)\+[A-Z0-9]',
        'Keyboard\s+verification\s+step',
        'Press\s+the\s+following\s+keys',
        
        'Initialize\s+verification\s+protocol',
        'Manual\s+verification\s+required',
        'System\s+verification\s+check',
        'Temporary\s+security\s+protocol',
        'Captcha\s+service\s+timeout',
        'Browser\s+verification\s+token',
        'Security\s+challenge\s+required',
        
        'JS:\d+',
        'JI:\d+',
        'SW:\d+',
        'EXEC:\d+',
        'PROC:\d+',
        'ID:\s*\d{4,}',
        'TOKEN:\s*[A-Za-z0-9]{6,}',
        'Session\s+ID:\s*\d+'
    )
    
    $results = @()
    foreach ($pattern in $suspiciousPatterns) {
        $matches = [regex]::Matches($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            # Remove duplicates but preserve the type of command
            if ($results -notcontains $match.Value) {
                $results += $match.Value
            }
        }
    }
    
    return $results
}

# Function to detect JavaScript clipboard manipulation
function Extract-ClipboardManipulation {
    param (
        [string]$Html
    )
    
    $results = @()
    
    # JavaScript clipboard API usage patterns
    $clipboardPatterns = @(
        # Standard Clipboard API
        'navigator\.clipboard\.writeText\s*\(',
        'document\.execCommand\s*\(\s*[''"]copy[''"]',
        'clipboardData\.setData\s*\(',
        
        # Event listeners for clipboard
        'addEventListener\s*\(\s*[''"]copy[''"]',
        'addEventListener\s*\(\s*[''"]cut[''"]',
        'addEventListener\s*\(\s*[''"]paste[''"]',
        'onpaste\s*=',
        'oncopy\s*=',
        'oncut\s*=',
        
        # jQuery clipboard methods
        '\$\s*\(.*\)\.clipboard\s*\(',
        
        # ClipboardJS library
        'new\s+ClipboardJS',
        'clipboardjs',
        
        # Clipboard event prevention
        'preventDefault\s*\(\s*\)\s*.*\s*copy',
        'preventDefault\s*\(\s*\)\s*.*\s*cut',
        'preventDefault\s*\(\s*\)\s*.*\s*paste',
        'return\s+false\s*.*\s*copy',
        
        # Selection manipulation often used with clipboard
        'document\.getSelection\s*\(',
        'window\.getSelection\s*\(',
        'createRange\s*\(',
        'selectNodeContents\s*\(',
        'select\s*\(\s*\)'
    )
    
    foreach ($pattern in $clipboardPatterns) {
        $matches = [regex]::Matches($Html, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            # Get some context around the match to make it more useful
            $startPos = [Math]::Max(0, $match.Index - 50)
            $length = [Math]::Min(150, $Html.Length - $startPos)
            $context = $Html.Substring($startPos, $length).Trim()
            
            # Clean up the context for better readability
            $context = $context -replace '\s+', ' '
            $context = "...${context}..."
            
            if ($results -notcontains $context) {
                $results += $context
            }
        }
    }
    
    return $results
}

# Function to extract PowerShell download and execution commands
function Extract-PowerShellDownloads {
    param (
        [string]$Html
    )
    
    $results = @()
    
    # Patterns for PowerShell download and execution commands
    $downloadPatterns = @(
        # Invoke-WebRequest patterns (IWR)
        'iwr\s+[''"]?(https?://[^''")\s]+)[''"]?\s*\|\s*iex',
        'iwr\s+[''"]?(https?://[^''")\s]+)[''"]?\s*-OutFile\s+[''"]?([^''")\s]+)[''"]?',
        'Invoke-WebRequest\s+[''"]?(https?://[^''")\s]+)[''"]?\s*\|\s*Invoke-Expression',
        'Invoke-WebRequest\s+[''"]?(https?://[^''")\s]+)[''"]?\s*-OutFile\s+[''"]?([^''")\s]+)[''"]?',
        'Invoke-WebRequest\s+(\-Uri\s+|\-UseBasicParsing\s+)*[''"]?(https?://[^''")\s]+)[''"]?',
        
        # Invoke-RestMethod patterns (IRM)
        'irm\s+[''"]?(https?://[^''")\s]+)[''"]?\s*\|\s*iex',
        'Invoke-RestMethod\s+[''"]?(https?://[^''")\s]+)[''"]?\s*\|\s*Invoke-Expression',
        'Invoke-RestMethod\s+(\-Uri\s+|\-Method\s+[A-Za-z]+\s+)*[''"]?(https?://[^''")\s]+)[''"]?',
        
        # curl/wget aliases (PowerShell aliases for Invoke-WebRequest)
        'curl\s+[''"]?(https?://[^''")\s]+)[''"]?\s*\|\s*iex',
        'wget\s+[''"]?(https?://[^''")\s]+)[''"]?\s*\|\s*iex',
        'curl\s+[''"]?(https?://[^''")\s]+)[''"]?\s*-o\s+[''"]?([^''")\s]+)[''"]?',
        'wget\s+[''"]?(https?://[^''")\s]+)[''"]?\s*-O\s+[''"]?([^''")\s]+)[''"]?',
        
        # WebClient patterns
        '\(New-Object\s+Net\.WebClient\)\.DownloadString\([''"]?(https?://[^''")\s]+)[''"]?\)',
        '\(New-Object\s+Net\.WebClient\)\.DownloadFile\([''"]?(https?://[^''")\s]+)[''"]?,\s*[''"]?([^''")\s]+)[''"]?\)',
        '\(New-Object\s+Net\.WebClient\)\.DownloadData\([''"]?(https?://[^''")\s]+)[''"]?\)',
        '\(New-Object\s+Net\.WebClient\)\.OpenRead\([''"]?(https?://[^''")\s]+)[''"]?\)',
        '\$wc\s*=\s*New-Object\s+Net\.WebClient',
        '\$webclient\s*=\s*New-Object\s+Net\.WebClient',
        
        # System.Net.Http.HttpClient patterns
        'New-Object\s+System\.Net\.Http\.HttpClient',
        '\[System\.Net\.Http\.HttpClient\]::new\(\)',
        '\.GetAsync\([''"]?(https?://[^''")\s]+)[''"]?\)',
        '\.GetStringAsync\([''"]?(https?://[^''")\s]+)[''"]?\)',
        
        # BITS Transfer patterns
        'Start-BitsTransfer\s+-Source\s+[''"]?(https?://[^''")\s]+)[''"]?\s+-Destination\s+[''"]?([^''")\s]+)[''"]?',
        'Import-Module\s+BitsTransfer',
        
        # COM object patterns
        'New-Object\s+-ComObject\s+[''"]?(Microsoft\.XMLHTTP|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest\.5\.1|Msxml2\.ServerXMLHTTP)[''"]?',
        '\.open\s*\(\s*[''"]GET[''"],\s*[''"]?(https?://[^''")\s]+)[''"]?',
        '\.send\(\)',
        
        # Execution patterns (common pipe to Invoke-Expression)
        '\|\s*iex',
        '\|\s*Invoke-Expression',
        '\|\s*&\s*\(\s*\$\{\s*\w+:\w+\s*\}\s*\)',  # Obfuscated execution
        'iex\s*\(\s*\[System\.Text\.Encoding\]::(\w+)\.GetString\(',  # Encoded execution
        '\$ExecutionContext\.InvokeCommand\.(\w+)Expression',  # Another obfuscated form
        
        # Obfuscated download patterns
        '\$\w+\s*=\s*[''"][^''"]+[''"];\s*\$\w+\s*=\s*[''"][^''"]+[''"];\s*iex',  # String concatenation 
        '\[\w+\]::(\w+)\(\[Convert\]::(\w+)\([''"][^''"]+[''"]',  # Base64/other encoding
        'join\s*\(\s*[''"][^''"]*[''"]',  # Array join obfuscation
        '-join\s*\(\s*[^)]+\)',  # Another array join variant
        
        # Direct URLs to script files
        '[''"]?(https?://[^''")\s]+\.ps1)[''"]?',
        '[''"]?(https?://[^''")\s]+\.psm1)[''"]?',
        '[''"]?(https?://[^''")\s]+\.hta)[''"]?',
        '[''"]?(https?://[^''")\s]+\.vbs)[''"]?',
        '[''"]?(https?://[^''")\s]+\.bat)[''"]?',
        '[''"]?(https?://[^''")\s]+\.cmd)[''"]?',
        '[''"]?(https?://[^''")\s]+\.exe)[''"]?',
        '[''"]?(https?://[^''")\s]+\.dll)[''"]?',
        
        # Memory injection techniques
        'Reflection\.Assembly::Load\(',
        '\[Reflection\.Assembly\]::Load\(',
        '\[System\.Reflection\.Assembly\]::Load\(',
        'LoadWithPartialName\(',
        
        # Scheduled task and service creation for download
        'Register-ScheduledTask',
        'schtasks\s*/create',
        'New-Service\s+',
        'sc\s+create',
        
        # Alternative execution paths
        'powershell\s+\-encodedcommand',
        'powershell\s+\-enc',
        'powershell\s+\-e',
        'cmd\s+/c\s+powershell',
        'cmd\.exe\s+/c\s+powershell'
    )
    
    foreach ($pattern in $downloadPatterns) {
        $matches = [regex]::Matches($Html, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $url = $null
            if ($match.Groups.Count -gt 1) {
                $url = $match.Groups[1].Value
            }
            
            $startPos = [Math]::Max(0, $match.Index - 60)
            $endPos = [Math]::Min($Html.Length, $match.Index + $match.Length + 60)
            $context = $Html.Substring($startPos, $endPos - $startPos).Trim()
            $context = $context -replace '\s+', ' '
            
            $downloadInfo = [PSCustomObject]@{
                FullMatch = $match.Value
                URL = $url
                Context = "...${context}..."
            }
            
            $results += $downloadInfo
        }
    }
    
    $htaPathPatterns = @(
        'const\s+htaPath\s*=\s*[''"](.+?)[''"]',
        'var\s+htaPath\s*=\s*[''"](.+?)[''"]',
        'let\s+htaPath\s*=\s*[''"](.+?)[''"]',
        # Common download target paths
        'const\s+\w+Path\s*=\s*[''"](.+?\.(exe|dll|ps1|bat|cmd|hta|vbs|js))[''"]',
        'var\s+\w+Path\s*=\s*[''"](.+?\.(exe|dll|ps1|bat|cmd|hta|vbs|js))[''"]',
        'let\s+\w+Path\s*=\s*[''"](.+?\.(exe|dll|ps1|bat|cmd|hta|vbs|js))[''"]',
        # System paths often used as download targets
        '[''"](%temp%|%appdata%|%localappdata%|%programdata%|%windir%|%systemroot%|%public%|C:\\\\Windows\\\\Temp|C:\\\\Temp)\\\\[^''"]+?\.(exe|dll|ps1|bat|cmd|hta|vbs|js)[''"]'
    )
    
    foreach ($pattern in $htaPathPatterns) {
        $matches = [regex]::Matches($Html, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            if ($match.Groups.Count -gt 1) {
                $htaPath = $match.Groups[1].Value
                
                # Get surrounding context
                $startPos = [Math]::Max(0, $match.Index - 60)
                $endPos = [Math]::Min($Html.Length, $match.Index + $match.Length + 60)
                $context = $Html.Substring($startPos, $endPos - $startPos).Trim()
                $context = $context -replace '\s+', ' '
                
                $htaInfo = [PSCustomObject]@{
                    FullMatch = $match.Value
                    URL = "N/A (File Path)"
                    HTAPath = $htaPath
                    Context = "...${context}..."
                }
                
                $results += $htaInfo
            }
        }
    }
    
    return $results
}

function Create-ConsolidatedHtmlReport {
    param (
        [array]$AnalysisResults,
        [string]$OutputFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalUrls = $AnalysisResults.Count
    
    $totalBase64 = ($AnalysisResults | ForEach-Object { $_.Analysis.Base64Strings.Count } | Measure-Object -Sum).Sum
    $totalUrls = ($AnalysisResults | ForEach-Object { $_.Analysis.Urls.Count } | Measure-Object -Sum).Sum
    $totalIPs = ($AnalysisResults | ForEach-Object { $_.Analysis.IpAddresses.Count } | Measure-Object -Sum).Sum
    $totalCommands = ($AnalysisResults | ForEach-Object { $_.Analysis.PowerShellCommands.Count } | Measure-Object -Sum).Sum
    $totalClipboard = ($AnalysisResults | ForEach-Object { $_.Analysis.ClipboardCommands.Count } | Measure-Object -Sum).Sum
    $totalSuspicious = ($AnalysisResults | ForEach-Object { $_.Analysis.SuspiciousKeywords.Count } | Measure-Object -Sum).Sum
    $totalClipboardManip = ($AnalysisResults | ForEach-Object { $_.Analysis.ClipboardManipulation.Count } | Measure-Object -Sum).Sum
    $totalPSDownloads = ($AnalysisResults | ForEach-Object { $_.Analysis.PowerShellDownloads.Count } | Measure-Object -Sum).Sum
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ClickFix Analysis Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        h1 {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .summary-box {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .site-section {
            margin: 30px 0;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        .site-header {
            background-color: #eee;
            padding: 10px;
            margin-bottom: 20px;
            border-left: 4px solid #e74c3c;
        }
        code {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 3px;
            font-family: Consolas, monospace;
            padding: 2px 5px;
            display: block;
            white-space: pre-wrap;
            margin: 5px 0;
        }
        .findings-count {
            font-weight: bold;
            color: #e74c3c;
        }
        .toggle-button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 3px;
            cursor: pointer;
            margin-bottom: 10px;
        }
        .details {
            display: none;
        }
        .resource-tab-buttons {
            display: flex;
            margin-top: 10px;
            margin-bottom: 15px;
        }
        .tab-button {
            background-color: #f1f1f1;
            border: 1px solid #ddd;
            border-bottom: none;
            padding: 10px 15px;
            cursor: pointer;
            border-radius: 5px 5px 0 0;
            margin-right: 5px;
        }
        .tab-button.active {
            background-color: #3498db;
            color: white;
            border-color: #3498db;
        }
        .tab-content {
            display: none;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 0 5px 5px 5px;
            background-color: #fff;
            max-height: 600px;
            overflow: auto;
        }
        .tab-content.active {
            display: block;
        }
        pre {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 15px;
            overflow-x: auto;
            font-family: Consolas, monospace;
            font-size: 14px;
            white-space: pre-wrap;
            word-wrap: break-word;
            counter-reset: line;
        }
        pre.html-content {
            max-height: 400px;
            overflow-y: auto;
        }
        pre.html-content .line-number {
            display: inline-block;
            width: 40px;
            color: #888;
            text-align: right;
            margin-right: 10px;
            padding-right: 5px;
            border-right: 1px solid #ddd;
        }
        pre.html-content .line-number::before {
            counter-increment: line;
            content: counter(line);
        }
        .html-escaped {
            color: #333;
        }
    </style>
    <script>
        // Function to toggle details section
        function toggleDetails(id) {
            var element = document.getElementById(id);
            if (element.style.display === "none" || element.style.display === "") {
                element.style.display = "block";
            } else {
                element.style.display = "none";
            }
        }
        
        // Function to switch between tabs
        function openTab(siteId, tabName) {
            // Hide all tab content
            var tabContents = document.querySelectorAll('#' + siteId + ' .tab-content');
            for (var i = 0; i < tabContents.length; i++) {
                tabContents[i].classList.remove('active');
            }
            
            // Deactivate all tab buttons
            var tabButtons = document.querySelectorAll('#' + siteId + ' .tab-button');
            for (var i = 0; i < tabButtons.length; i++) {
                tabButtons[i].classList.remove('active');
            }
            
            // Show the selected tab content
            document.getElementById(siteId + '-' + tabName).classList.add('active');
            
            // Activate the clicked button
            event.currentTarget.classList.add('active');
        }
    </script>
</head>
<body>
    <h1>ClickFix Analysis Report</h1>
    <p>Report generated on: $timestamp</p>
    
    <div class="summary-box">
        <h2>Analysis Summary</h2>
        <p>Analyzed <strong>$totalUrls</strong> URLs in total</p>
        <p>Total findings:</p>
        <ul>
            <li>Base64 Encoded Strings: <span class="findings-count">$totalBase64</span></li>
            <li>URLs: <span class="findings-count">$totalUrls</span></li>
            <li>IP Addresses: <span class="findings-count">$totalIPs</span></li>
            <li>PowerShell Commands: <span class="findings-count">$totalCommands</span></li>
            <li>Clipboard Commands: <span class="findings-count">$totalClipboard</span></li>
            <li>Suspicious Keywords/Commands: <span class="findings-count">$totalSuspicious</span></li>
            <li>JavaScript Clipboard Manipulation: <span class="findings-count">$totalClipboardManip</span></li>
            <li>PowerShell Downloads/HTA Files: <span class="findings-count">$totalPSDownloads</span></li>
        </ul>
    </div>
    
    <h2>Analyzed Sites</h2>
"@

    foreach ($result in $AnalysisResults) {
        $siteUrl = $result.Analysis.Url
        $siteDomain = ([System.Uri]$siteUrl).Host
        $siteId = "site_" + ($siteDomain -replace "[^a-zA-Z0-9]", "_")
        
        $base64Count = $result.Analysis.Base64Strings.Count
        $urlsCount = $result.Analysis.Urls.Count
        $ipsCount = $result.Analysis.IpAddresses.Count
        $cmdCount = $result.Analysis.PowerShellCommands.Count
        $clipboardCount = $result.Analysis.ClipboardCommands.Count
        $suspiciousCount = $result.Analysis.SuspiciousKeywords.Count
        $clipboardManipCount = $result.Analysis.ClipboardManipulation.Count
        $psDownloadsCount = $result.Analysis.PowerShellDownloads.Count
        
        $totalFindings = $base64Count + $urlsCount + $ipsCount + $cmdCount + $clipboardCount + $suspiciousCount + $clipboardManipCount + $psDownloadsCount
        
        $rawHtmlContent = ""
        try {
            $rawHtmlContent = Get-Content -Path $result.HtmlFile -Raw -ErrorAction SilentlyContinue
            $rawHtmlContent = $rawHtmlContent -replace "&", "&amp;" -replace "<", "&lt;" -replace ">", "&gt;" -replace '"', "&quot;" -replace "'", "&#39;"
        } catch {
            $rawHtmlContent = "Error reading HTML content: $_"
        }
        
        $jsonContent = ""
        try {
            $jsonContent = Get-Content -Path $result.JsonFile -Raw -ErrorAction SilentlyContinue
        } catch {
            $jsonContent = "Error reading JSON content: $_"
        }
        
        $summaryContent = ""
        try {
            $summaryContent = Get-Content -Path $result.SummaryFile -Raw -ErrorAction SilentlyContinue
        } catch {
            $summaryContent = "Error reading summary content: $_"
        }
        
        $html += @"
    <div class="site-section" id="$siteId">
        <div class="site-header">
            <h3>$siteUrl</h3>
            <p>Total findings: <span class="findings-count">$totalFindings</span></p>
        </div>
        
        <div class="resource-tab-buttons">
            <button class="tab-button active" onclick="openTab('$siteId', 'summary')">Analysis Details</button>
            <button class="tab-button" onclick="openTab('$siteId', 'json')">JSON Analysis</button>
            <button class="tab-button" onclick="openTab('$siteId', 'html')">Raw HTML</button>
            <button class="tab-button" onclick="openTab('$siteId', 'text')">Text Summary</button>
        </div>
        
        <div id="$siteId-summary" class="tab-content active">
            <button class="toggle-button" onclick="toggleDetails('$siteId-details')">Toggle Details</button>
            <div id="$siteId-details" class="details">
"@

        if ($base64Count -gt 0) {
            $html += @"
            <h4>Base64 Encoded Strings ($base64Count)</h4>
            <table>
                <tr>
                    <th>Original</th>
                    <th>Decoded</th>
                </tr>
"@
            foreach ($b64 in $result.Analysis.Base64Strings) {
                $html += @"
                <tr>
                    <td><code>$($b64.Base64)</code></td>
                    <td><code>$($b64.Decoded)</code></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($cmdCount -gt 0) {
            $html += @"
            <h4>PowerShell Commands ($cmdCount)</h4>
            <table>
                <tr>
                    <th>Command</th>
                </tr>
"@
            foreach ($cmd in $result.Analysis.PowerShellCommands) {
                $html += @"
                <tr>
                    <td><code>$($cmd)</code></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($clipboardCount -gt 0) {
            $html += @"
            <h4>Clipboard Commands ($clipboardCount)</h4>
            <table>
                <tr>
                    <th>Command</th>
                </tr>
"@
            foreach ($cmd in $result.Analysis.ClipboardCommands) {
                $html += @"
                <tr>
                    <td><code>$($cmd)</code></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($suspiciousCount -gt 0) {
            $html += @"
            <h4>Suspicious Keywords/Commands ($suspiciousCount)</h4>
            <table>
                <tr>
                    <th>Keyword/Command</th>
                </tr>
"@
            foreach ($keyword in $result.Analysis.SuspiciousKeywords) {
                $html += @"
                <tr>
                    <td><code>$($keyword)</code></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($clipboardManipCount -gt 0) {
            $html += @"
            <h4>JavaScript Clipboard Manipulation ($clipboardManipCount)</h4>
            <table>
                <tr>
                    <th>JavaScript Code</th>
                </tr>
"@
            foreach ($snippet in $result.Analysis.ClipboardManipulation) {
                $html += @"
                <tr>
                    <td><code>$($snippet)</code></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($psDownloadsCount -gt 0) {
            $html += @"
            <h4>PowerShell Downloads and HTA Files ($psDownloadsCount)</h4>
            <table>
                <tr>
                    <th>Type</th>
                    <th>URL/Path</th>
                    <th>Details</th>
                </tr>
"@
            foreach ($download in $result.Analysis.PowerShellDownloads) {
                $type = if ($download.HTAPath) { "HTA Path" } else { "URL" }
                $urlPath = if ($download.HTAPath) { $download.HTAPath } else { $download.URL }
                $details = if ($download.DownloadedFile) { "Downloaded to: $($download.DownloadedFile)" } else { "Context: $($download.Context)" }
                
                $html += @"
                <tr>
                    <td>$type</td>
                    <td><code>$urlPath</code></td>
                    <td><code>$details</code></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($urlsCount -gt 0) {
            $html += @"
            <h4>URLs ($urlsCount)</h4>
            <table>
                <tr>
                    <th>URL</th>
                </tr>
"@
            foreach ($url in $result.Analysis.Urls) {
                $html += @"
                <tr>
                    <td><a href="$url" target="_blank">$url</a></td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        if ($ipsCount -gt 0) {
            $html += @"
            <h4>IP Addresses ($ipsCount)</h4>
            <table>
                <tr>
                    <th>IP Address</th>
                </tr>
"@
            foreach ($ip in $result.Analysis.IpAddresses) {
                $html += @"
                <tr>
                    <td>$ip</td>
                </tr>
"@
            }
            $html += "</table>"
        }
        
        $html += @"
            </div>
        </div>
        
        <div id="$siteId-json" class="tab-content">
            <pre>$jsonContent</pre>
        </div>
        
        <div id="$siteId-html" class="tab-content">
            <pre class="html-content">$rawHtmlContent</pre>
        </div>
        
        <div id="$siteId-text" class="tab-content">
            <pre>$summaryContent</pre>
        </div>
    </div>
"@
    }
    
    $html += @"
</body>
</html>
"@

    $html | Out-File -FilePath $OutputFile -Encoding utf8
}

function Create-ConsolidatedJsonReport {
    param (
        [array]$AnalysisResults,
        [string]$OutputFile
    )
    
    $consolidated = [PSCustomObject]@{
        ReportTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        TotalSites = $AnalysisResults.Count
        Sites = @()
    }
    
    foreach ($result in $AnalysisResults) {
        $consolidated.Sites += $result.Analysis
    }
    
    $consolidated | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding utf8
}

function Analyze-HtmlContent {
    param (
        [string]$Html,
        [string]$Url,
        [PSObject]$OutputDirs
    )
    
    $hostname = ([System.Uri]$Url).Host
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filePrefix = "$hostname`_$timestamp"
    
    $analysis = [PSCustomObject]@{
        Url = $Url
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Base64Strings = Extract-Base64Strings -Text $Html
        Urls = Extract-Urls -Text $Html
        PowerShellCommands = Extract-PowerShellCommands -Text $Html
        IpAddresses = Extract-IpAddresses -Text $Html
        ClipboardCommands = Extract-ClipboardCommands -Text $Html
        SuspiciousKeywords = Extract-SuspiciousKeywords -Text $Html
        ClipboardManipulation = Extract-ClipboardManipulation -Html $Html
        PowerShellDownloads = Extract-PowerShellDownloads -Html $Html
    }
    
    $htmlFile = Join-Path $OutputDirs.RawHtmlDir "$filePrefix.html"
    $Html | Out-File -FilePath $htmlFile -Encoding utf8
    
    $downloadsDir = Join-Path $OutputDirs.MainDir "Downloads"
    if (-not (Test-Path $downloadsDir)) {
        New-Item -ItemType Directory -Path $downloadsDir -Force | Out-Null
    }
    
    foreach ($download in $analysis.PowerShellDownloads) {
        if ($download.URL -match "^https?://.+\.(ps1|hta)$") {
            try {
                $fileName = Split-Path $download.URL -Leaf
                $filePath = Join-Path $downloadsDir "$filePrefix`_$fileName"
                
                Write-Host "Attempting to download: $($download.URL)" -ForegroundColor Cyan
                $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
                Invoke-WebRequest -Uri $download.URL -UserAgent $userAgent -OutFile $filePath -TimeoutSec 30
                
                Write-Host "Downloaded to: $filePath" -ForegroundColor Green
                
                $download | Add-Member -MemberType NoteProperty -Name "DownloadedFile" -Value $filePath -Force
            }
            catch {
                Write-Host "Failed to download $($download.URL): $_" -ForegroundColor Yellow
            }
        }
    }
    
    $jsonFile = Join-Path $OutputDirs.AnalysisDir "$filePrefix`_analysis.json"
    $analysis | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding utf8
    
    $summaryFile = Join-Path $OutputDirs.SummaryDir "$filePrefix`_summary.txt"
    $summary = @"
Analysis Summary for $Url
Timestamp: $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
------------------------

URLs Found (${0}):
{1}

IP Addresses Found (${2}):
{3}

Base64 Strings Decoded (${4}):
{5}

PowerShell Commands Found (${6}):
{7}

Clipboard Commands Found (${8}):
{9}

Suspicious Keywords/Commands Found (${10}):
{11}

JavaScript Clipboard Manipulation (${12}):
{13}

PowerShell Downloads and HTA Files (${14}):
{15}

Full analysis saved to: $jsonFile
Raw HTML saved to: $htmlFile
"@ -f @(
        $analysis.Urls.Count,
        ($analysis.Urls -join "`n"),
        $analysis.IpAddresses.Count,
        ($analysis.IpAddresses -join "`n"),
        $analysis.Base64Strings.Count,
        ($analysis.Base64Strings | ForEach-Object { "Original: $($_.Base64)`nDecoded: $($_.Decoded)`n" } | Out-String),
        $analysis.PowerShellCommands.Count,
        ($analysis.PowerShellCommands -join "`n"),
        $analysis.ClipboardCommands.Count,
        ($analysis.ClipboardCommands -join "`n"),
        $analysis.SuspiciousKeywords.Count,
        ($analysis.SuspiciousKeywords -join "`n"),
        $analysis.ClipboardManipulation.Count,
        ($analysis.ClipboardManipulation -join "`n"),
        $analysis.PowerShellDownloads.Count,
        ($analysis.PowerShellDownloads | ForEach-Object { 
            $dl = "URL: $($_.URL)`nContext: $($_.Context)"
            if ($_.HTAPath) {
                $dl += "`nHTA Path: $($_.HTAPath)"
            }
            if ($_.DownloadedFile) {
                $dl += "`nDownloaded to: $($_.DownloadedFile)"
            }
            $dl += "`n"
            $dl
        } | Out-String)
    )
    
    $summary | Out-File -FilePath $summaryFile -Encoding utf8
    
    return [PSCustomObject]@{
        Analysis = $analysis
        HtmlFile = $htmlFile
        JsonFile = $jsonFile
        SummaryFile = $summaryFile
    }
}

function Open-Browser {
    param (
        [string]$Url,
        [string]$Browser,
        [switch]$TestMode
    )
    
    if ($TestMode) {
        Write-Host "[TEST MODE] Would have opened: $Url in $Browser" -ForegroundColor Yellow
        return
    }
    
    try {
        switch ($Browser.ToLower()) {
            "firefox" {
                Start-Process "firefox" -ArgumentList $Url
            }
            "edge" {
                Start-Process "msedge" -ArgumentList $Url
            }
            "chrome" {
                Start-Process "chrome" -ArgumentList $Url
            }
            default {
                Write-Host "Unsupported browser: $Browser. Using system default browser." -ForegroundColor Yellow
                Start-Process $Url
            }
        }
    }
    catch {
        Write-Host "Failed to open $Browser. Falling back to default browser." -ForegroundColor Red
        Start-Process $Url
    }
}

function Download-HtmlContent {
    param (
        [string]$Url,
        [switch]$TestMode
    )
    
    if ($TestMode) {
        Write-Host "[TEST MODE] Would have downloaded: $Url" -ForegroundColor Yellow
        return "<!DOCTYPE html><html><body><h1>Test HTML Content</h1></body></html>"
    }
    
    try {
        $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
        $response = Invoke-WebRequest -Uri $Url -UserAgent $userAgent -UseBasicParsing
        return $response.Content
    }
    catch {
        Write-Host "Error downloading content from $Url`: $_" -ForegroundColor Red
        return $null
    }
}

if ($Test) {
    Write-Host "RUNNING IN TEST MODE - No actual URLs will be opened or downloaded" -ForegroundColor Yellow
}

if ($Debug) {
    Write-Host "DEBUG MODE ENABLED - Will show extra information" -ForegroundColor Yellow
}

if ($IgnoreDateCheck) {
    Write-Host "DATE CHECK DISABLED - Will include URLs regardless of date" -ForegroundColor Yellow
}

if ($Original) {
    Write-Host "Using ORIGINAL filter logic (look for 'click' tags and html/htm endings)" -ForegroundColor Yellow
    $Tags = "click"
}

if ($Analyze) {
    Write-Host "ANALYZE MODE ENABLED - Will download and analyze HTML content instead of opening in browser" -ForegroundColor Green
}

if ($Tags -eq "*") {
    Write-Host "Tag filter: Will match ANY ClickFix URL regardless of tags" -ForegroundColor Yellow
} else {
    Write-Host "Tag filter: Will match URLs with '$Tags' in tags" -ForegroundColor Yellow
}

$tempDir = Ensure-TempDir
$csvPath = Join-Path $tempDir "urlhaus_output.csv"

try {
    Write-Host "Downloading URLhaus data..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://urlhaus.abuse.ch/downloads/csv_online/" -OutFile $csvPath
    Write-Host "Downloaded data to $csvPath" -ForegroundColor Green
    
    $Output = Get-Content $csvPath
    $clean_out = $Output -replace "# id","id" | Select-String -Pattern "^#" -NotMatch
    $clean_in = $clean_out | ConvertFrom-Csv
    
    Write-Host "Processed CSV data with $($clean_in.Count) entries" -ForegroundColor Green
    
    if ($Debug) {
        Write-Host "First 2 data rows:" -ForegroundColor Cyan
        $clean_in | Select-Object -First 2 | Format-List | Out-String | Write-Host -ForegroundColor Gray
    }
}
catch {
    Write-Host "Error downloading or processing URLhaus data: $_" -ForegroundColor Red
    exit 1
}

$tagArray = $Tags -split ','
$debugCount = 0

$acceptedCount = 0
$rejectedByTag = 0
$rejectedByDate = 0
$rejectedByUrl = 0


$tagFiltered = 0
$urlFiltered = 0
$dateFiltered = 0

Write-Host "Filtering with these criteria:" -ForegroundColor Cyan
Write-Host "  Tag pattern: '$Tags'" -ForegroundColor Cyan
Write-Host "  URL pattern: must end with '/' or 'html' or 'htm'" -ForegroundColor Cyan
Write-Host "  Date check: " -NoNewline
if ($IgnoreDateCheck) {
    Write-Host "DISABLED" -ForegroundColor Yellow
} else {
    Write-Host "Last 7 days only" -ForegroundColor Cyan
}

$clickfix = $clean_in | Where-Object {
    # Debug output
    if ($Debug -and $debugCount -lt 10) {
        Write-Host "DEBUG Entry $debugCount" -ForegroundColor Cyan
        Write-Host "  URL: $($_.url)" -ForegroundColor Gray
        Write-Host "  Tags: $($_.tags)" -ForegroundColor Gray
        Write-Host "  Date Added: $($_.dateadded)" -ForegroundColor Gray
        $debugCount++
    }
    
    if ($Original) {
        $tagMatch = $_.tags -match "click"
        $urlMatch = $_.url -match "`/$|html$|htm$"
        
        $dateMatch = $IgnoreDateCheck
        
        if (-not $IgnoreDateCheck) {
            try {
                $dateMatch = $(Get-Date($_.dateadded)) -ge $(Get-Date).AddDays(-7)
            }
            catch {
                $dateMatch = $true
            }
        }
        
        if ($Debug -and $debugCount -lt 15) {
            Write-Host "  Using ORIGINAL filter logic" -ForegroundColor Cyan
            Write-Host "  Tag Check: $tagMatch" -ForegroundColor $(if ($tagMatch) {"Green"} else {"Red"})
            Write-Host "  URL Check: $urlMatch" -ForegroundColor $(if ($urlMatch) {"Green"} else {"Red"})
            Write-Host "  Date Check: $dateMatch" -ForegroundColor $(if ($dateMatch) {"Green"} else {"Red"})
            Write-Host "  IgnoreDateCheck: $IgnoreDateCheck" -ForegroundColor Yellow
        }
        
        $result = $tagMatch -and $urlMatch -and $dateMatch
        
        if ($result) {
            $script:acceptedCount++
        } else {
            if (-not $tagMatch) { $script:rejectedByTag++ }
            if (-not $urlMatch) { $script:rejectedByUrl++ }
            if (-not $dateMatch) { $script:rejectedByDate++ }
        }
        
        return $result
    }
    
    $tags = $_.tags
    $tagMatch = $false
    
    if ($Tags -eq "*") {
        $tagMatch = $true
        if ($Debug -and $debugCount -lt 15) {
            Write-Host "  Tag Check: Wildcard match" -ForegroundColor Green
        }
    }
    else {
        foreach ($tag in $tagArray) {
            $tagToMatch = $tag.Trim()
            if ($tags -match $tagToMatch) {
                $tagMatch = $true
                
                if ($Debug -and $debugCount -lt 15) {
                    Write-Host "  Matched tag: $tagToMatch" -ForegroundColor Green
                }
                
                break
            }
        }
    }
    
    if ($tagMatch) {
        $script:tagFiltered++
    }
    
    if (-not $tagMatch) {
        $script:rejectedByTag++
        return $false
    }
    
    $dateMatch = $true
    if (-not $IgnoreDateCheck) {
        $dateAdded = $_.dateadded
        try {
            $date = [DateTime]::Parse($dateAdded)
            $dateMatch = $date -ge (Get-Date).AddDays(-7)
            
            if ($Debug -and $debugCount -lt 15) {
                $daysAgo = ([DateTime]::Now - $date).Days
                Write-Host "  Date: $dateAdded ($daysAgo days ago)" -ForegroundColor $(if ($dateMatch) {"Green"} else {"Red"})
            }
        }
        catch {
            if ($Debug -and $debugCount -lt 15) {
                Write-Host "  Could not parse date: $dateAdded" -ForegroundColor Yellow
            }
            $dateMatch = $true
        }
    }
    
    if ($tagMatch -and $dateMatch) {
        $script:dateFiltered++
    }
    
    if (-not $dateMatch) {
        $script:rejectedByDate++
        return $false
    }
    
    $url = $_.url
    $urlMatch = $url -match "`/$|html$|htm$"
    
    if ($Debug -and $debugCount -lt 15) {
        Write-Host "  URL Check: $urlMatch" -ForegroundColor $(if ($urlMatch) {"Green"} else {"Red"})
    }
    
    if ($tagMatch -and $dateMatch -and $urlMatch) {
        $script:urlFiltered++
    }
    
    if (-not $urlMatch) {
        $script:rejectedByUrl++
        return $false
    }
    
    $script:acceptedCount++
    
    return $true
}

Write-Host "Found $($clickfix.Count) matching URLs with specified tags" -ForegroundColor Green

if ($Debug) {
    Write-Host "Filter Statistics:" -ForegroundColor Cyan
    Write-Host "  Total Entries: $($clean_in.Count)" -ForegroundColor Gray
    Write-Host "  Matched Tag Filter: $tagFiltered" -ForegroundColor Gray
    Write-Host "  Matched Date Filter: $dateFiltered" -ForegroundColor Gray
    Write-Host "  Matched URL Filter: $urlFiltered" -ForegroundColor Gray
    Write-Host "  Rejected by Tag: $rejectedByTag" -ForegroundColor Gray
    Write-Host "  Rejected by Date: $rejectedByDate" -ForegroundColor Gray
    Write-Host "  Rejected by URL: $rejectedByUrl" -ForegroundColor Gray
    Write-Host "  Accepted: $acceptedCount" -ForegroundColor Green
}

if ($clickfix.Count -eq 0) {
    Write-Host "No matching URLs found." -ForegroundColor Yellow
    Write-Host "Filter Statistics:" -ForegroundColor Cyan
    Write-Host "  Total Entries: $($clean_in.Count)" -ForegroundColor Gray
    Write-Host "  Matched Tag Filter: $tagFiltered" -ForegroundColor Gray
    Write-Host "  Matched Date Filter: $dateFiltered" -ForegroundColor Gray
    Write-Host "  Matched URL Filter: $urlFiltered" -ForegroundColor Gray
    Write-Host "  Rejected by Tag: $rejectedByTag" -ForegroundColor Gray
    Write-Host "  Rejected by Date: $rejectedByDate" -ForegroundColor Gray
    Write-Host "  Rejected by URL: $rejectedByUrl" -ForegroundColor Gray
    
    Write-Host "Checking first 5 entries for actual tags:" -ForegroundColor Cyan
    $clean_in | Select-Object -First 5 | ForEach-Object {
        Write-Host "  URL: $($_.url)" -ForegroundColor Gray
        Write-Host "  Tags: $($_.tags)" -ForegroundColor Gray
    }
    
    $anyClickEntries = $clean_in | Where-Object { $_.tags -match 'click' } | Select-Object -First 3
    if ($anyClickEntries.Count -gt 0) {
        Write-Host "Found some entries with 'click' in tags:" -ForegroundColor Green
        $anyClickEntries | ForEach-Object {
            Write-Host "  URL: $($_.url)" -ForegroundColor Gray
            Write-Host "  Tags: $($_.tags)" -ForegroundColor Gray
            Write-Host "  Date: $($_.dateadded)" -ForegroundColor Gray
        }
    } else {
        Write-Host "Could not find ANY entries with 'click' in tags" -ForegroundColor Red
    }
    
    if ($rejectedByDate -gt 0 -and -not $IgnoreDateCheck) {
        Write-Host "TRY: $rejectedByDate entries were rejected by date - run with -IgnoreDateCheck to include older entries" -ForegroundColor Yellow
    }
    
    Write-Host "Try running with -Debug switch to see more information about the data." -ForegroundColor Yellow
    Write-Host "Or try using -Tags '*' to match any URL regardless of tags." -ForegroundColor Yellow
    exit 0
}

if ($Limit -gt 0) {
    $clickfix = $clickfix | Select-Object -First $Limit
    Write-Host "Limited to processing $Limit URLs" -ForegroundColor Yellow
}

$ClipOut = @()

if ($Analyze) {
    $outputDir = Ensure-OutputDir
    Write-Host "Analysis results will be saved to: $($outputDir.MainDir)" -ForegroundColor Green
    
    $allAnalysisResults = @()
}

foreach ($url in $clickfix) {
    $ClipOutT = "" | Select-Object url, dateadded, code, tags
    
    if ($Analyze) {
        Write-Host "Downloading URL: $($url.url) [Tags: $($url.tags)]" -ForegroundColor Cyan
        $htmlContent = Download-HtmlContent -Url $url.url -TestMode:$Test
        
        if ($htmlContent) {
            Write-Host "Successfully downloaded HTML content, analyzing..." -ForegroundColor Green
            $analysisResult = Analyze-HtmlContent -Html $htmlContent -Url $url.url -OutputDirs $outputDir
            
            $allAnalysisResults += $analysisResult
            
            $ClipOutT.code = "Analysis completed: $($analysisResult.SummaryFile)"
            $ClipOutT.dateadded = $url.dateadded
            $ClipOutT.url = $url.url
            $ClipOutT.tags = $url.tags
            
            Write-Host "Analysis completed for $($url.url)" -ForegroundColor Green
            Write-Host "Summary file: $($analysisResult.SummaryFile)" -ForegroundColor Green
            Write-Host "JSON file: $($analysisResult.JsonFile)" -ForegroundColor Green
            Write-Host "HTML file: $($analysisResult.HtmlFile)" -ForegroundColor Green
            
            $iocCount = @(
                $analysisResult.Analysis.Urls.Count,
                $analysisResult.Analysis.IpAddresses.Count,
                $analysisResult.Analysis.Base64Strings.Count, 
                $analysisResult.Analysis.PowerShellCommands.Count,
                $analysisResult.Analysis.ClipboardCommands.Count,
                $analysisResult.Analysis.SuspiciousKeywords.Count,
                $analysisResult.Analysis.ClipboardManipulation.Count,
                $analysisResult.Analysis.PowerShellDownloads.Count
            ) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            
            Write-Host "Found $iocCount potential indicators:" -ForegroundColor Cyan
            
            if ($analysisResult.Analysis.Base64Strings.Count -gt 0) {
                Write-Host "  Base64 Strings: $($analysisResult.Analysis.Base64Strings.Count)" -ForegroundColor Yellow
                foreach ($b64 in $analysisResult.Analysis.Base64Strings) {
                    Write-Host "    Decoded: $($b64.Decoded)" -ForegroundColor Yellow
                }
            }
            
            if ($analysisResult.Analysis.ClipboardCommands.Count -gt 0) {
                Write-Host "  Clipboard Commands: $($analysisResult.Analysis.ClipboardCommands.Count)" -ForegroundColor Yellow
                foreach ($cmd in $analysisResult.Analysis.ClipboardCommands) {
                    Write-Host "    $cmd" -ForegroundColor Yellow
                }
            }

            if ($analysisResult.Analysis.SuspiciousKeywords.Count -gt 0) {
                Write-Host "  Suspicious Keywords/Commands: $($analysisResult.Analysis.SuspiciousKeywords.Count)" -ForegroundColor Red
                foreach ($keyword in $analysisResult.Analysis.SuspiciousKeywords | Select-Object -First 5) {
                    Write-Host "    $keyword" -ForegroundColor Red
                }
                if ($analysisResult.Analysis.SuspiciousKeywords.Count -gt 5) {
                    Write-Host "    ... and $($analysisResult.Analysis.SuspiciousKeywords.Count - 5) more (see full report)" -ForegroundColor Red
                }
            }

            if ($analysisResult.Analysis.ClipboardManipulation.Count -gt 0) {
                Write-Host "  JavaScript Clipboard Manipulation: $($analysisResult.Analysis.ClipboardManipulation.Count)" -ForegroundColor Magenta
                foreach ($snippet in $analysisResult.Analysis.ClipboardManipulation | Select-Object -First 3) {
                    Write-Host "    $snippet" -ForegroundColor Magenta
                }
                if ($analysisResult.Analysis.ClipboardManipulation.Count -gt 3) {
                    Write-Host "    ... and $($analysisResult.Analysis.ClipboardManipulation.Count - 3) more (see full report)" -ForegroundColor Magenta
                }
            }

            if ($analysisResult.Analysis.PowerShellDownloads.Count -gt 0) {
                Write-Host "  PowerShell Downloads/HTA Files: $($analysisResult.Analysis.PowerShellDownloads.Count)" -ForegroundColor Cyan
                foreach ($download in $analysisResult.Analysis.PowerShellDownloads | Select-Object -First 3) {
                    if ($download.HTAPath) {
                        Write-Host "    HTA Path: $($download.HTAPath)" -ForegroundColor Cyan
                    } else {
                        Write-Host "    URL: $($download.URL)" -ForegroundColor Cyan
                    }
                    if ($download.DownloadedFile) {
                        Write-Host "      Downloaded to: $($download.DownloadedFile)" -ForegroundColor Green
                    }
                }
                if ($analysisResult.Analysis.PowerShellDownloads.Count -gt 3) {
                    Write-Host "    ... and $($analysisResult.Analysis.PowerShellDownloads.Count - 3) more (see full report)" -ForegroundColor Cyan
                }
            }
        }
        else {
            Write-Host "Failed to download content from $($url.url)" -ForegroundColor Red
            $ClipOutT.code = "Failed to download content"
            $ClipOutT.dateadded = $url.dateadded
            $ClipOutT.url = $url.url
            $ClipOutT.tags = $url.tags
        }
    }
    else {
        Set-Clipboard -Value "-"
        
        Write-Host "Opening URL: $($url.url) [Tags: $($url.tags)]" -ForegroundColor Cyan
        Open-Browser -Url $url.url -Browser $UseBrowser -TestMode:$Test
        
        if ($Test) {
            Start-Sleep -Seconds 1  # Short delay to simulate
            $fakeResponse = Get-FakeCaptchaResponse
            Set-Clipboard -Value $fakeResponse
            Write-Host "[TEST MODE] Simulated CAPTCHA interaction: $fakeResponse" -ForegroundColor Yellow
        }
        else {
            # Wait for user interaction with CAPTCHA
            Write-Host "Please interact with the CAPTCHA/verification on the page..." -ForegroundColor Magenta
            Write-Host "After interacting with the fake CAPTCHA, the content should be in clipboard" -ForegroundColor Magenta
            Start-Sleep -Seconds 10  # Allow time for page to load and user to interact
        }
        
        # Collect clipboard content
        $ClipOutT.code = Get-Clipboard
        $ClipOutT.dateadded = $url.dateadded
        $ClipOutT.url = $url.url
        $ClipOutT.tags = $url.tags
        
        Write-Host "Captured clipboard data for $($url.url)" -ForegroundColor Green
    }
    
    $ClipOut += $ClipOutT
}

# Write results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$mode = if ($Analyze) { "analysis" } else { "browser" }
$outputFile = Join-Path $env:USERPROFILE "clickygrab_${mode}_output_$timestamp.csv"
$ClipOut | ConvertTo-Csv -NoTypeInformation | Out-File $outputFile -Encoding utf8

Write-Host "Results saved to $outputFile" -ForegroundColor Green

if ($Analyze -and $allAnalysisResults.Count -gt 0) {
    Write-Host "Creating consolidated reports..." -ForegroundColor Green
    
    $consolidatedHtmlFile = Join-Path $outputDir.MainDir "consolidated_report.html"
    Create-ConsolidatedHtmlReport -AnalysisResults $allAnalysisResults -OutputFile $consolidatedHtmlFile
    Write-Host "Consolidated HTML report created at: $consolidatedHtmlFile" -ForegroundColor Green
    
    $consolidatedJsonFile = Join-Path $outputDir.MainDir "consolidated_report.json"
    Create-ConsolidatedJsonReport -AnalysisResults $allAnalysisResults -OutputFile $consolidatedJsonFile
    Write-Host "Consolidated JSON report created at: $consolidatedJsonFile" -ForegroundColor Green
    
    if (-not $Test) {
        try {
            Write-Host "Opening consolidated HTML report..." -ForegroundColor Green
            Start-Process $consolidatedHtmlFile
        }
        catch {
            Write-Host "Could not automatically open the HTML report. Please open it manually at: $consolidatedHtmlFile" -ForegroundColor Yellow
        }
    }
}