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
        'powershell(?:\.exe)?\s+(?:-\w+\s+)*.*',
        'iex\s*\(.*\)',
        'invoke-expression.*?',
        'invoke-webrequest.*?',
        'wget\s+.*?',
        'curl\s+.*?',
        'net\s+use.*?',
        'new-object\s+.*?',
        'powershell\s+\-encodedcommand\s+',
        'powershell\s+\-enc\s+',
        'powershell\s+\-e\s+'
    )
    
    $results = @()
    foreach ($pattern in $cmdPatterns) {
        try {
            $matches = [regex]::Matches($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                if ($results -notcontains $match.Value) {
                    $results += $match.Value
                }
            }
        } catch {
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
        # Command execution patterns
        'cmd(?:.exe)?\s+(?:/\w+\s+)*',
        'command(?:.com)?\s+(?:/\w+\s+)*',
        'bash\s+-c\s+',
        'sh\s+-c\s+',
        'exec\s+',
        'system\s*\(',
        'exec\s*\(',
        'eval\s*\(',
        'execSync\s*\(',
        
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
        
        # CAPTCHA verification
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
        
        # Social engineering phrases
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
        
        # Fake CAPTCHA verification keywords
        'Checking if you are human',
        'Verify you are human',
        'Cloudflare verification',
        'To better prove you are not a robot',
        'I''m not a robot',
        'navigator\.clipboard\.writeText',
        'const command = ',
        'powershell -w 1 ',
        
        # Obfuscated JavaScript detection patterns (verified reasonable)
        '<script src=',
        '<script>',
        '_0x',
        'eval\(',
        'atob\(',
        'unescape\(',
        'fromCharCode',
        '\\x[0-9a-fA-F]{2}', # Adjusted case insensitivity in regex options instead
        '\\u00[0-9a-fA-F]{2}', # Adjusted case insensitivity in regex options instead
        'document\.write',
        'noindex,nofollow',
        'display:none',
        'position:absolute;left:-9999px',
        'createElement\(script\)',
        'Array\.prototype',
        'constructor',
        'window\.location\.replace'
    )
    
    $results = @()
    foreach ($pattern in $suspiciousPatterns) {
        try {
            # Use IgnoreCase for patterns like hex escapes
            $matches = [regex]::Matches($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                if ($results -notcontains $match.Value) {
                    $results += $match.Value
                }
            }
        } catch {
            # Continue with next pattern
        }
    }
    
    return $results
}

function Extract-CaptchaElements {
    param (
        [string]$HtmlContent
    )
    
    $captchaPatterns = @(
        # Element IDs
        'id\s*=\s*"captcha[a-zA-Z0-9_-]*"',
        'id\s*=\s*''captcha[a-zA-Z0-9_-]*''',
        'id\s*=\s*"robot(OrHuman)?"',
        'id\s*=\s*''robot(OrHuman)?''',
        'id\s*=\s*"verification[a-zA-Z0-9_-]*"',
        'id\s*=\s*''verification[a-zA-Z0-9_-]*''',
        'id\s*=\s*"step[0-9]"',
        'id\s*=\s*''step[0-9]''',
        'id\s*=\s*"fixit"',
        'id\s*=\s*''fixit''',
        'id\s*=\s*"prompt[0-9]"',
        'id\s*=\s*''prompt[0-9]''',
        'id\s*=\s*"code"',
        'id\s*=\s*''code''',
        'id\s*=\s*"retry"',
        'id\s*=\s*''retry''',
        # Suspicious single letter or short IDs
        'id\s*=\s*"[a-z]{1,2}"',
        'id\s*=\s*''[a-z]{1,2}''',
        
        # Element classes
        'class\s*=\s*"captcha[a-zA-Z0-9_-]*"',
        'class\s*=\s*''captcha[a-zA-Z0-9_-]*''',
        'class\s*=\s*"verification[a-zA-Z0-9_-]*"',
        'class\s*=\s*''verification[a-zA-Z0-9_-]*''',
        'class\s*=\s*"modal-[a-zA-Z0-9_-]*"',
        'class\s*=\s*''modal-[a-zA-Z0-9_-]*''',
        'class\s*=\s*"button[a-zA-Z0-9_-]*"',
        'class\s*=\s*''button[a-zA-Z0-9_-]*''',
        'class\s*=\s*"step[a-zA-Z0-9_-]*"',
        'class\s*=\s*''step[a-zA-Z0-9_-]*''',
        # Suspicious single letter class names
        'class\s*=\s*"[a-z]{1,2}"',
        'class\s*=\s*''[a-z]{1,2}''',
        
        # Function attributes
        'onclick\s*=\s*"[a-zA-Z]+Click\(\)"',
        'onclick\s*=\s*''[a-zA-Z]+Click\(\)''',
        'onclick\s*=\s*"location\.reload\(\)"',
        'onclick\s*=\s*''location\.reload\(\)''',
        
        # Script content
        'function\s+[a-zA-Z]+Click\s*\(',
        'function\s+hide[a-zA-Z]+\s*\(',
        'function\s+fallback[a-zA-Z]+\s*\(',
        '[a-zA-Z]+OperationActive\s*=',
        'document\.getElementById\("[a-zA-Z0-9_-]+"',
        'document\.getElementById\(''[a-zA-Z0-9_-]+''',
        
        # Clipboard operations
        'document\.execCommand\("copy',
        'document\.execCommand\(''copy',
        'document\.execCommand\("cut',
        'document\.execCommand\(''cut',
        'document\.execCommand\("paste',
        'document\.execCommand\(''paste',
        'navigator\.clipboard\.writeText',
        'select\(\)',
        'window\.getSelection\(\)',
        
        # Base64 operations
        'atob\(',
        'document\.getElementById\("code"\)\.value\s*=\s*atob',
        'document\.getElementById\(''code''\)\.value\s*=\s*atob',
        
        # Fix-it button
        'fixit"\.addEventListener\("click',
        'fixit''\.addEventListener\(''click',
        
        # Common fake security headers
        'Ray ID:',
        'Performance',
        'security by',
        'needs to review the security',
        
        # Cloudflare specific elements
        'cloudflare',
        
        # Obfuscated JavaScript patterns
        '<script src=',
        '<script>',
        '_0x',
        'eval\(',
        'unescape\(',
        'fromCharCode',
        'document\.write',
        'noindex,nofollow',
        'display:none',
        'position:absolute;left:-9999'
    )
    
    $results = @()
    foreach ($pattern in $captchaPatterns) {
        try {
            $matches = [regex]::Matches($HtmlContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                $startIndex = [Math]::Max(0, $match.Index - 20)
                $endIndex = [Math]::Min($HtmlContent.Length, $match.Index + $match.Length + 20)
                $contextLength = $endIndex - $startIndex
                $context = $HtmlContent.Substring($startIndex, $contextLength).Trim()
                $context = [regex]::Replace($context, '\s+', ' ')
                
                if ($results -notcontains $context) {
                    $results += $context
                }
            }
        }
        catch {
            # Continue with next pattern
        }
    }
    
    return $results
}

function Extract-ObfuscatedJavaScript {
    param (
        [string]$HtmlContent
    )
    
    $results = @()
    
    # Patterns for detecting obfuscated JavaScript
    $obfuscationPatterns = @(
        # Hexadecimal variable naming pattern (_0x1234) - strong indicator of obfuscation
        '_0x[a-f0-9]{4,6}\s*=',
        '_0x[a-f0-9]{4,6}\[.*?\]',
        '_0x[a-f0-9]{2,6}\s*=\s*function',
        '\(function\s*\(\s*_0x[a-f0-9]{2,6}\s*,\s*_0x[a-f0-9]{2,6}\s*\)',
        
        # Array/string manipulation often used in deobfuscation routines
        'String\.fromCharCode\.apply\(null,',
        '\[\]\["constructor"\]\["constructor"\]',
        '\[\]\."filter"\."constructor"\(',
        'atob\(.*?\)\."replace"\(',
        
        # Nested string indexing operations common in obfuscated code
        '\[\(![!][""]\+[""]\)\[[\d]+\]\]',
        '\("\\"\[\"constructor"\]\("return escape"\)\(\)\+"\\"\)\[\d+\]',
        
        # Self-modifying function detection
        'function\s*\(\)\s*\{\s*return\s*function\s*\(\)\s*\{\s*',
        'new Function\(\s*[\w\s,]+\,\s*atob\s*\(',
        
        # Extremely long strings with repeated patterns (BASE64, etc.)
        '["'']((?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))[''"]',
        
        # Object property access obfuscation
        '[''"`][a-zA-Z0-9_$]{1,3}[''"`]\s*in\s*window',
        'window\[[''"`][a-zA-Z0-9_$]{1,3}[''"`]\]',
        
        # Packed JavaScript indicators
        'eval\(function\(p,a,c,k,e,(?:r|d)?\)',
        'eval\(function\(p,a,c,k,e,r\)',
        
        # JJEncoder/Dean Edwards packer detection
        '\$=~\[\];\$=\{___:\+\$,\$\$\$\$',
        '__=\[\]\[''fill''\]'
    )
    
    foreach ($pattern in $obfuscationPatterns) {
        try {
            $matches = [regex]::Matches($HtmlContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($match in $matches) {
                # Get context around the match
                $startPos = [Math]::Max(0, $match.Index - 40)
                $endPos = [Math]::Min($HtmlContent.Length, $match.Index + $match.Length + 40)
                $context = $HtmlContent.Substring($startPos, $endPos - $startPos).Trim()
                
                # Clean up the context
                $context = $context -replace '\s+', ' '
                $context = "...${context}..."
                
                if ($results -notcontains $context) {
                    $results += $context
                }
            }
        } catch {
            # Continue silently if regex fails
            continue
        }
    }
    
    # Additional check for script density/complexity indicators
    $scriptTags = [regex]::Matches($HtmlContent, '<script[^>]*>(.*?)</script>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    foreach ($script in $scriptTags) {
        $scriptContent = $script.Groups[1].Value
        # Check for high symbol-to-character ratio (indicator of obfuscation)
        if ($scriptContent.Length -gt 100) {  # Only check substantial scripts
            $symbols = [regex]::Matches($scriptContent, '[\(\)\[\]\{\}+\-*/=!<>?:;,.]').Count
            $scriptLength = $scriptContent.Length
            $symbolRatio = $symbols / $scriptLength
            
            # High ratio of symbols to characters suggests obfuscation
            if ($symbolRatio -gt 0.25) {  # Threshold determined empirically
                $snippet = if ($scriptContent.Length -gt 100) { $scriptContent.Substring(0, 100) + "..." } else { $scriptContent }
                $context = "High symbol density ($([Math]::Round($symbolRatio, 2))): $snippet"
                if ($results -notcontains $context) {
                    $results += $context
                }
            }
        }
    }
    
    return $results
}

function Extract-ClipboardManipulation {
    param (
        [string]$HtmlContent
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
        try {
            $matches = [regex]::Matches($HtmlContent, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                # Get some context around the match to make it more useful
                $startPos = [Math]::Max(0, $match.Index - 50)
                $length = [Math]::Min(150, $HtmlContent.Length - $startPos)
                $context = $HtmlContent.Substring($startPos, $length).Trim()
                
                # Clean up the context for better readability
                $context = $context -replace '\s+', ' '
                $context = "...${context}..."
                
                if ($results -notcontains $context) {
                    $results += $context
                }
            }
        } catch {
            # Continue silently if regex fails
            continue
        }
    }
    
    return $results
}

function Extract-PowerShellDownloads {
    param (
        [string]$Html
    )
    
    $results = @()
    
    # Patterns for PowerShell download and execution commands
    $downloadPatterns = @(
        # Invoke-WebRequest patterns (IWR)
        'iwr\s+["'']?(https?://[^"'')\s]+)["'']?\s*\|\s*iex',
        'iwr\s+["'']?(https?://[^"'')\s]+)["'']?\s*-OutFile\s+["'']?([^"'')\s]+)["'']?',
        'Invoke-WebRequest\s+["'']?(https?://[^"'')\s]+)["'']?\s*\|\s*Invoke-Expression',
        'Invoke-WebRequest\s+["'']?(https?://[^"'')\s]+)["'']?\s*-OutFile\s+["'']?([^"'')\s]+)["'']?',
        'Invoke-WebRequest\s+(\-Uri\s+|\-UseBasicParsing\s+)*["'']?(https?://[^"'')\s]+)["'']?',
        
        # Invoke-RestMethod patterns (IRM) - Added
        'irm\s+["'']?(https?://[^"'')\s]+)["'']?\s*\|\s*iex',
        'Invoke-RestMethod\s+["'']?(https?://[^"'')\s]+)["'']?\s*\|\s*Invoke-Expression',
        'Invoke-RestMethod\s+(\-Uri\s+|\-Method\s+[A-Za-z]+\s+)*["'']?(https?://[^"'')\s]+)["'']?',
        
        # curl/wget aliases (PowerShell aliases for Invoke-WebRequest)
        'curl\s+["'']?(https?://[^"'')\s]+)["'']?\s*\|\s*iex',
        'wget\s+["'']?(https?://[^"'')\s]+)["'']?\s*\|\s*iex',
        'curl\s+["'']?(https?://[^"'')\s]+)["'']?\s*-o\s+["'']?([^"'')\s]+)["'']?',
        'wget\s+["'']?(https?://[^"'')\s]+)["'']?\s*-O\s+["'']?([^"'')\s]+)["'']?',
        
        # WebClient patterns
        '\(New-Object\s+Net\.WebClient\)\.DownloadString\(["'']?(https?://[^"'')\s]+)["'']?\)',
        '\(New-Object\s+Net\.WebClient\)\.DownloadFile\(["'']?(https?://[^"'')\s]+)["'']?,\s*["'']?([^"'')\s]+)["'']?\)',
        '\(New-Object\s+Net\.WebClient\)\.DownloadData\(["'']?(https?://[^"'')\s]+)["'']?\)',
        '\(New-Object\s+Net\.WebClient\)\.OpenRead\(["'']?(https?://[^"'')\s]+)["'']?\)',
        '\$wc\s*=\s*New-Object\s+Net\.WebClient',
        '\$webclient\s*=\s*New-Object\s+Net\.WebClient',
        
        # System.Net.Http.HttpClient patterns
        'New-Object\s+System\.Net\.Http\.HttpClient',
        '\[System\.Net\.Http\.HttpClient\]::new\(\)',
        '\.GetAsync\(["'']?(https?://[^"'')\s]+)["'']?\)',
        '\.GetStringAsync\(["'']?(https?://[^"'')\s]+)["'']?\)',
        
        # BITS Transfer patterns
        'Start-BitsTransfer\s+-Source\s+["'']?(https?://[^"'')\s]+)["'']?\s+-Destination\s+["'']?([^"'')\s]+)["'']?',
        'Import-Module\s+BitsTransfer',
        
        # COM object patterns
        'New-Object\s+-ComObject\s+["'']?(Microsoft\.XMLHTTP|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest\.5\.1|Msxml2\.ServerXMLHTTP)["'']?',
        '\.open\s*\(\s*["'']GET["''],\s*["'']?(https?://[^"'')\s]+)["'']?',
        '\.send\(\)',
        
        # Execution patterns (common pipe to Invoke-Expression)
        '\|\s*iex',
        '\|\s*Invoke-Expression',
        '\|\s*&\s*\(\s*\$\{\s*\w+:\w+\s*\}\s*\)',
        'iex\s*\(\s*\[System\.Text\.Encoding\]::(\w+)\.GetString\(',
        '\$ExecutionContext\.InvokeCommand\.([A-Za-z]+)Expression',
        
        # Obfuscated download patterns
        '\$\w+\s*=\s*["''][^"'']+["''];\s*\$\w+\s*=\s*["''][^"'']+["''"];\s*iex',
        '\[\w+\]::(\w+)\(.*\(.*\[Convert\]::(\w+)\(.*["''][^"'']+["'']',
        'join\s*\(\s*["''][^"'']*["'']',
        '-join\s*\(\s*[^)]+\)',
        
        # Direct URLs to script files
        '["'']?(https?://[^"'')\s]+\.ps1)["'']?',
        '["'']?(https?://[^"'')\s]+\.psm1)["'']?',
        '["'']?(https?://[^"'')\s]+\.hta)["'']?',
        '["'']?(https?://[^"'')\s]+\.vbs)["'']?',
        '["'']?(https?://[^"'')\s]+\.bat)["'']?',
        '["'']?(https?://[^"'')\s]+\.cmd)["'']?',
        '["'']?(https?://[^"'')\s]+\.exe)["'']?',
        '["'']?(https?://[^"'')\s]+\.dll)["'']?',
        
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
        
        # Alternative execution paths - Added EncodedCommand
        'powershell\s+\-encodedcommand',
        'powershell\s+\-enc',
        'powershell\s+\-e',
        'cmd\s+/c\s+powershell',
        'cmd\.exe\s+/c\s+powershell'
    )
    
    foreach ($pattern in $downloadPatterns) {
        try {
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
        } catch {
            # Silently continue
            continue
        }
    }
    
    # Also check for HTA file paths explicitly defined in JavaScript
    $htaPathPatterns = @(
        'const\s+htaPath\s*=\s*["''](.+?\.hta)["'']',
        'var\s+htaPath\s*=\s*["''](.+?\.hta)["'']',
        'let\s+htaPath\s*=\s*["''](.+?\.hta)["'']'
    )
    
    foreach ($pattern in $htaPathPatterns) {
        try {
            $matches = [regex]::Matches($Html, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            foreach ($match in $matches) {
                if ($match.Groups.Count -gt 1) {
                    $htaPath = $match.Groups[1].Value
                    
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
        } catch {
            # Silently continue
            continue
        }
    }
    
    return $results
}

function Analyze-HtmlContent {
    param (
        [string]$Url,
        [string]$HtmlContent
    )
    
    # Extract and analyze different elements
    $base64Strings = Extract-Base64Strings -Text $HtmlContent
    $urls = Extract-Urls -Text $HtmlContent
    $powerShellCommands = Extract-PowerShellCommands -Text $HtmlContent
    $ipAddresses = Extract-IpAddresses -Text $HtmlContent
    $clipboardCommands = Extract-ClipboardCommands -Html $HtmlContent
    $suspiciousKeywords = Extract-SuspiciousKeywords -Text $HtmlContent
    $clipboardManipulation = Extract-ClipboardManipulation -HtmlContent $HtmlContent
    $powerShellDownloads = Extract-PowerShellDownloads -Html $HtmlContent
    $captchaElements = Extract-CaptchaElements -HtmlContent $HtmlContent
    
    # Determine threat level
    $threatLevel = Get-ThreatLevel -Analysis @{
        "Base64Strings" = $base64Strings
        "URLs" = $urls
        "PowerShellCommands" = $powerShellCommands
        "IPAddresses" = $ipAddresses
        "ClipboardCommands" = $clipboardCommands
        "SuspiciousKeywords" = $suspiciousKeywords
        "ClipboardManipulation" = $clipboardManipulation
        "PowerShellDownloads" = $powerShellDownloads
        "CaptchaElements" = $captchaElements
    }
    
    # Create a result object
    $result = [PSCustomObject]@{
        URL = $Url
        Base64Strings = $base64Strings
        URLs = $urls
        PowerShellCommands = $powerShellCommands
        IPAddresses = $ipAddresses
        ClipboardCommands = $clipboardCommands
        SuspiciousKeywords = $suspiciousKeywords
        ClipboardManipulation = $clipboardManipulation
        PowerShellDownloads = $powerShellDownloads
        CaptchaElements = $captchaElements
        HTML = $HtmlContent
        ThreatLevel = $threatLevel
    }
    
    return $result
}

function Get-ThreatLevel {
    param (
        [PSCustomObject]$Analysis
    )
    
    $score = 0
    
    # PowerShell commands are highly suspicious
    if ($Analysis.PowerShellCommands.Count -gt 0) {
        $score += 30
    }
    
    # PowerShell downloads are highly suspicious
    if ($Analysis.PowerShellDownloads.Count -gt 0) {
        $score += 30
    }
    
    # Clipboard manipulation is suspicious
    if ($Analysis.ClipboardManipulation.Count -gt 0) {
        $score += 20
    }
    
    # Clipboard commands are suspicious
    if ($Analysis.ClipboardCommands.Count -gt 0) {
        $score += 20
    }
    
    # Obfuscated JavaScript is highly suspicious
    if ($Analysis.ObfuscatedJavaScript.Count -gt 0) {
        $obfuscationCount = $Analysis.ObfuscatedJavaScript.Count
        $score += [Math]::Min(40, $obfuscationCount * 8)  # Higher weight than other indicators
    }
    
    # Base64 strings might be suspicious
    if ($Analysis.Base64Strings.Count -gt 0) {
        $score += [Math]::Min(15, $Analysis.Base64Strings.Count)
    }
    
    # Suspicious keywords
    if ($Analysis.SuspiciousKeywords.Count -gt 0) {
        $score += [Math]::Min(30, $Analysis.SuspiciousKeywords.Count * 3)
    }
    
    # CAPTCHA elements are suspicious
    if ($Analysis.CaptchaElements.Count -gt 0) {
        $score += [Math]::Min(20, $Analysis.CaptchaElements.Count * 2)
    }
    
    if ($score -ge 60) {
        return "High"
    }
    elseif ($score -ge 30) {
        return "Medium"
    }
    elseif ($score -gt 0) {
        return "Low"
    }
    else {
        return "None"
    }
}

function Create-ConsolidatedHtmlReport {
    param (
        [array]$AnalysisResults,
        [string]$OutputFile
    )
    
    # Filter out any null results
    $validResults = @($AnalysisResults | Where-Object { $_ -ne $null })
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalSites = $validResults.Count
    
    # Count totals
    $totalBase64 = ($validResults | ForEach-Object { $_.Analysis.Base64Strings.Count } | Measure-Object -Sum).Sum
    $totalUrls = ($validResults | ForEach-Object { $_.Analysis.URLs.Count } | Measure-Object -Sum).Sum
    $totalIPs = ($validResults | ForEach-Object { $_.Analysis.IPAddresses.Count } | Measure-Object -Sum).Sum
    $totalCommands = ($validResults | ForEach-Object { $_.Analysis.PowerShellCommands.Count } | Measure-Object -Sum).Sum
    $totalClipboard = ($validResults | ForEach-Object { $_.Analysis.ClipboardCommands.Count } | Measure-Object -Sum).Sum
    $totalSuspicious = ($validResults | ForEach-Object { $_.Analysis.SuspiciousKeywords.Count } | Measure-Object -Sum).Sum
    $totalClipboardManip = ($validResults | ForEach-Object { $_.Analysis.ClipboardManipulation.Count } | Measure-Object -Sum).Sum
    $totalPSDownloads = ($validResults | ForEach-Object { $_.Analysis.PowerShellDownloads.Count } | Measure-Object -Sum).Sum
    
    # Create simple HTML report
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
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1, h2, h3, h4 {
            color: #333;
        }
        .report-header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-box {
            background-color: #fff;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }
        .site-section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background-color: #fff;
        }
        .site-header {
            background-color: #f8f9fa;
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 4px;
            border-left: 4px solid #3498db;
        }
        .tab-buttons {
            display: flex;
            margin-bottom: 15px;
            border-bottom: 1px solid #ddd;
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
        .tab-button:hover {
            background-color: #ddd;
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
            border-radius: 0 0 5px 5px;
        }
        .tab-content.active {
            display: block;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .finding-type {
            font-weight: bold;
        }
        .finding-count {
            text-align: center;
            font-weight: bold;
            color: #3498db;
        }
        pre {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            max-height: 400px;
        }
    </style>
    <script>
        function openTab(siteId, tabName) {
            // Hide all tab content
            const contents = document.querySelectorAll('#' + siteId + ' .tab-content');
            for (let content of contents) {
                content.classList.remove('active');
            }
            
            // Deactivate all buttons
            const buttons = document.querySelectorAll('#' + siteId + ' .tab-button');
            for (let button of buttons) {
                button.classList.remove('active');
            }
            
            // Activate the selected tab and button
            document.getElementById(siteId + '-' + tabName).classList.add('active');
            document.querySelector('#' + siteId + ' .tab-button[data-tab="' + tabName + '"]').classList.add('active');
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="report-header">
            <h1>ClickFix Analysis Report</h1>
            <p>Report generated on: $timestamp</p>
        </div>
        
        <h2>Analysis Summary</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <span class="stat-value">$totalSites</span>
                <div>Sites Analyzed</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalBase64</span>
                <div>Base64 Strings</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalUrls</span>
                <div>URLs</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalIPs</span>
                <div>IP Addresses</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalCommands</span>
                <div>PowerShell Commands</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalClipboard</span>
                <div>Clipboard Commands</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalSuspicious</span>
                <div>Suspicious Keywords</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalClipboardManip</span>
                <div>Clipboard Manipulation</div>
            </div>
            <div class="stat-box">
                <span class="stat-value">$totalPSDownloads</span>
                <div>PowerShell Downloads</div>
            </div>
        </div>
        
        <h2>Analyzed Sites</h2>
"@

    # Add section for each analyzed site
    $siteCounter = 0
    foreach ($result in $validResults) {
        $siteId = "site-$siteCounter"
        $siteCounter++
        
        $siteUrl = $result.Analysis.URL
        
        # Skip sites with no data
        if (-not $siteUrl) {
            continue
        }
        
        # Count findings for this site
        $base64Count = $result.Analysis.Base64Strings.Count
        $urlsCount = $result.Analysis.URLs.Count
        $ipsCount = $result.Analysis.IPAddresses.Count
        $cmdCount = $result.Analysis.PowerShellCommands.Count
        $clipboardCount = $result.Analysis.ClipboardCommands.Count
        $suspiciousCount = $result.Analysis.SuspiciousKeywords.Count
        $clipboardManipCount = $result.Analysis.ClipboardManipulation.Count
        $psDownloadsCount = $result.Analysis.PowerShellDownloads.Count
        
        $totalFindings = $base64Count + $urlsCount + $ipsCount + $cmdCount + $clipboardCount + $suspiciousCount + $clipboardManipCount + $psDownloadsCount
        
        # Get HTML, JSON, and summary content
        $rawHtmlContent = "HTML file not available or could not be read"
        try {
            if (Test-Path $result.HtmlFile) {
                $rawHtmlContent = Get-Content -Path $result.HtmlFile -Raw -ErrorAction Stop
                $rawHtmlContent = $rawHtmlContent -replace "&", "&amp;" -replace "<", "&lt;" -replace ">", "&gt;" -replace '"', "&quot;" -replace "'", "&#39;"
            }
        } catch {
            $rawHtmlContent = "Error reading HTML content: $_"
        }
        
        $jsonContent = "JSON file not available or could not be read"
        try {
            if (Test-Path $result.JsonFile) {
                $jsonContent = Get-Content -Path $result.JsonFile -Raw -ErrorAction Stop
            }
        } catch {
            $jsonContent = "Error reading JSON content: $_"
        }
        
        $summaryContent = "Summary file not available or could not be read"
        try {
            if (Test-Path $result.SummaryFile) {
                $summaryContent = Get-Content -Path $result.SummaryFile -Raw -ErrorAction Stop
            }
        } catch {
            $summaryContent = "Error reading summary content: $_"
        }
        
        # Add site section to HTML
        $html += @"
        <div class="site-section" id="$siteId">
            <div class="site-header">
                <h3>$([System.Web.HttpUtility]::HtmlEncode($siteUrl))</h3>
                <p>Total findings: <strong>$totalFindings</strong></p>
            </div>
            
            <div class="tab-buttons">
                <button class="tab-button active" data-tab="details" onclick="openTab('$siteId', 'details')">Analysis Details</button>
                <button class="tab-button" data-tab="json" onclick="openTab('$siteId', 'json')">JSON Analysis</button>
                <button class="tab-button" data-tab="html" onclick="openTab('$siteId', 'html')">Raw HTML</button>
                <button class="tab-button" data-tab="text" onclick="openTab('$siteId', 'text')">Text Summary</button>
            </div>
            
            <div id="$siteId-details" class="tab-content active">
                <h4>Analysis Details</h4>
                <table>
                    <tr>
                        <th>Finding Type</th>
                        <th>Count</th>
                        <th>Details</th>
                    </tr>
"@
        
        # Add Base64 Strings
        if ($base64Count -gt 0) {
            $detailsHtml = ""
            foreach ($b64 in $result.Analysis.Base64Strings | Select-Object -First 3) {
                $encodedBase64 = [System.Web.HttpUtility]::HtmlEncode($b64.Base64)
                $encodedDecoded = [System.Web.HttpUtility]::HtmlEncode($b64.Decoded)
                $detailsHtml += "Base64: $encodedBase64<br>Decoded: $encodedDecoded<br><br>"
            }
            if ($base64Count -gt 3) {
                $detailsHtml += "... and $($base64Count - 3) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">Base64 Strings</td>
                        <td class="finding-count">$base64Count</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add URLs
        if ($urlsCount -gt 0) {
            $detailsHtml = ""
            foreach ($url in $result.Analysis.URLs | Select-Object -First 5) {
                $encodedUrl = [System.Web.HttpUtility]::HtmlEncode($url)
                $detailsHtml += "$encodedUrl<br>"
            }
            if ($urlsCount -gt 5) {
                $detailsHtml += "... and $($urlsCount - 5) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">URLs</td>
                        <td class="finding-count">$urlsCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add PowerShell Commands
        if ($cmdCount -gt 0) {
            $detailsHtml = ""
            foreach ($cmd in $result.Analysis.PowerShellCommands | Select-Object -First 3) {
                $encodedCmd = [System.Web.HttpUtility]::HtmlEncode($cmd)
                $detailsHtml += "$encodedCmd<br>"
            }
            if ($cmdCount -gt 3) {
                $detailsHtml += "... and $($cmdCount - 3) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">PowerShell Commands</td>
                        <td class="finding-count">$cmdCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add IP Addresses
        if ($ipsCount -gt 0) {
            $detailsHtml = ""
            foreach ($ip in $result.Analysis.IPAddresses | Select-Object -First 5) {
                $encodedIp = [System.Web.HttpUtility]::HtmlEncode($ip)
                $detailsHtml += "$encodedIp<br>"
            }
            if ($ipsCount -gt 5) {
                $detailsHtml += "... and $($ipsCount - 5) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">IP Addresses</td>
                        <td class="finding-count">$ipsCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add Clipboard Commands
        if ($clipboardCount -gt 0) {
            $detailsHtml = ""
            foreach ($cmd in $result.Analysis.ClipboardCommands | Select-Object -First 3) {
                $encodedCmd = [System.Web.HttpUtility]::HtmlEncode($cmd)
                $detailsHtml += "$encodedCmd<br>"
            }
            if ($clipboardCount -gt 3) {
                $detailsHtml += "... and $($clipboardCount - 3) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">Clipboard Commands</td>
                        <td class="finding-count">$clipboardCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add Suspicious Keywords
        if ($suspiciousCount -gt 0) {
            $detailsHtml = ""
            foreach ($keyword in $result.Analysis.SuspiciousKeywords | Select-Object -First 5) {
                $encodedKeyword = [System.Web.HttpUtility]::HtmlEncode($keyword)
                $detailsHtml += "$encodedKeyword<br>"
            }
            if ($suspiciousCount -gt 5) {
                $detailsHtml += "... and $($suspiciousCount - 5) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">Suspicious Keywords</td>
                        <td class="finding-count">$suspiciousCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add Clipboard Manipulation
        if ($clipboardManipCount -gt 0) {
            $detailsHtml = ""
            foreach ($snippet in $result.Analysis.ClipboardManipulation | Select-Object -First 3) {
                $encodedSnippet = [System.Web.HttpUtility]::HtmlEncode($snippet)
                $detailsHtml += "$encodedSnippet<br>"
            }
            if ($clipboardManipCount -gt 3) {
                $detailsHtml += "... and $($clipboardManipCount - 3) more"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">Clipboard Manipulation</td>
                        <td class="finding-count">$clipboardManipCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        # Add PowerShell Downloads
        if ($psDownloadsCount -gt 0) {
            $detailsHtml = ""
            foreach ($download in $result.Analysis.PowerShellDownloads | Select-Object -First 3) {
                if ($download.HTAPath) {
                    $encodedPath = [System.Web.HttpUtility]::HtmlEncode($download.HTAPath)
                    $detailsHtml += "HTA Path: $encodedPath<br>"
                } else {
                    $encodedUrl = [System.Web.HttpUtility]::HtmlEncode($download.URL)
                    $detailsHtml += "URL: $encodedUrl<br>"
                }
            }
            if ($psDownloadsCount -gt 3) {
                $detailsHtml += "... and $($psDownloadsCount - 3) more (see full report)"
            }
            
            $html += @"
                    <tr>
                        <td class="finding-type">PowerShell Downloads</td>
                        <td class="finding-count">$psDownloadsCount</td>
                        <td>$detailsHtml</td>
                    </tr>
"@
        }
        
        $html += @"
                </table>
            </div>
            
            <div id="$siteId-json" class="tab-content">
                <h4>JSON Analysis</h4>
                <pre>$([System.Web.HttpUtility]::HtmlEncode($jsonContent))</pre>
            </div>
            
            <div id="$siteId-html" class="tab-content">
                <h4>Raw HTML Content</h4>
                <pre>$rawHtmlContent</pre>
            </div>
            
            <div id="$siteId-text" class="tab-content">
                <h4>Text Summary</h4>
                <pre>$([System.Web.HttpUtility]::HtmlEncode($summaryContent))</pre>
            </div>
        </div>
"@
    }
    
    # Close the HTML
    $html += @"
    </div>
</body>
</html>
"@

    # Save the HTML report
    $html | Out-File -FilePath $OutputFile -Encoding utf8
    
    return $OutputFile
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
        # Use the Analysis property from the result object
        if ($result.Analysis -ne $null) {
            $consolidated.Sites += $result.Analysis
        }
    }
    
    # Filter out any null entries that might have been added
    $consolidated.Sites = @($consolidated.Sites | Where-Object { $_ -ne $null })
    
    # Update the count to reflect actual sites after filtering out nulls
    $consolidated.TotalSites = $consolidated.Sites.Count
    
    $consolidated | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding utf8
    
    return $consolidated
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
            $analysisResult = Analyze-HtmlContent -Url $url.url -HtmlContent $htmlContent
            
            # Save files for this analysis
            $safeDomain = ($url.url -replace "https?://", "" -replace "[^a-zA-Z0-9]", "_") -replace "_+", "_"
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            
            # Save raw HTML
            $htmlFileName = Join-Path $outputDir.RawHtmlDir "$($safeDomain)_$timestamp.html"
            $htmlContent | Out-File -FilePath $htmlFileName -Encoding utf8
            
            # Save JSON analysis
            $jsonFileName = Join-Path $outputDir.AnalysisDir "$($safeDomain)_$timestamp.json"
            $analysisResult | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonFileName -Encoding utf8
            
            # Save summary
            $summaryFileName = Join-Path $outputDir.SummaryDir "$($safeDomain)_$timestamp.txt"
            $summary = @"
URL: $($url.url)
Analysis Timestamp: $timestamp
Base64 Strings: $($analysisResult.Base64Strings.Count)
URLs: $($analysisResult.URLs.Count)
PowerShell Commands: $($analysisResult.PowerShellCommands.Count)
IP Addresses: $($analysisResult.IPAddresses.Count)
Clipboard Commands: $($analysisResult.ClipboardCommands.Count)
Suspicious Keywords: $($analysisResult.SuspiciousKeywords.Count)
"@
            $summary | Out-File -FilePath $summaryFileName -Encoding utf8
            
            # Add file paths to the result object
            $resultWithFiles = [PSCustomObject]@{
                Analysis = $analysisResult
                HtmlFile = $htmlFileName
                JsonFile = $jsonFileName
                SummaryFile = $summaryFileName
            }
            
            $allAnalysisResults += $resultWithFiles
            
            $ClipOutT.code = "Analysis completed and saved to $($outputDir.MainDir)"
            $ClipOutT.dateadded = $url.dateadded
            $ClipOutT.url = $url.url
            $ClipOutT.tags = $url.tags
            
            Write-Host "Analysis completed for $($url.url)" -ForegroundColor Green
            Write-Host "HTML file: $htmlFileName" -ForegroundColor Green
            Write-Host "JSON file: $jsonFileName" -ForegroundColor Green
            Write-Host "Summary file: $summaryFileName" -ForegroundColor Green
            
            # Display findings
            $iocCount = @(
                $analysisResult.URLs.Count,
                $analysisResult.IPAddresses.Count,
                $analysisResult.Base64Strings.Count, 
                $analysisResult.PowerShellCommands.Count,
                $analysisResult.ClipboardCommands.Count,
                $analysisResult.SuspiciousKeywords.Count,
                $analysisResult.ClipboardManipulation.Count,
                $analysisResult.PowerShellDownloads.Count
            ) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
            
            Write-Host "Found $iocCount potential indicators:" -ForegroundColor Cyan
            
            if ($analysisResult.Base64Strings.Count -gt 0) {
                Write-Host "  Base64 Strings: $($analysisResult.Base64Strings.Count)" -ForegroundColor Yellow
                foreach ($b64 in $analysisResult.Base64Strings | Select-Object -First 3) {
                    Write-Host "    Decoded: $($b64.Decoded)" -ForegroundColor Yellow
                }
                if ($analysisResult.Base64Strings.Count -gt 3) {
                    Write-Host "    ... and $($analysisResult.Base64Strings.Count - 3) more (see full report)" -ForegroundColor Yellow
                }
            }
            
            if ($analysisResult.PowerShellCommands.Count -gt 0) {
                Write-Host "  PowerShell Commands: $($analysisResult.PowerShellCommands.Count)" -ForegroundColor Red
                foreach ($cmd in $analysisResult.PowerShellCommands | Select-Object -First 3) {
                    Write-Host "    $cmd" -ForegroundColor Red
                }
                if ($analysisResult.PowerShellCommands.Count -gt 3) {
                    Write-Host "    ... and $($analysisResult.PowerShellCommands.Count - 3) more (see full report)" -ForegroundColor Red
                }
            }
            
            if ($analysisResult.ClipboardCommands.Count -gt 0) {
                Write-Host "  Clipboard Commands: $($analysisResult.ClipboardCommands.Count)" -ForegroundColor Yellow
                foreach ($cmd in $analysisResult.ClipboardCommands | Select-Object -First 3) {
                    Write-Host "    $cmd" -ForegroundColor Yellow
                }
                if ($analysisResult.ClipboardCommands.Count -gt 3) {
                    Write-Host "    ... and $($analysisResult.ClipboardCommands.Count - 3) more (see full report)" -ForegroundColor Yellow
                }
            }
            
            if ($analysisResult.SuspiciousKeywords.Count -gt 0) {
                Write-Host "  Suspicious Keywords: $($analysisResult.SuspiciousKeywords.Count)" -ForegroundColor Magenta
                foreach ($keyword in $analysisResult.SuspiciousKeywords | Select-Object -First 5) {
                    Write-Host "    $keyword" -ForegroundColor Magenta
                }
                if ($analysisResult.SuspiciousKeywords.Count -gt 5) {
                    Write-Host "    ... and $($analysisResult.SuspiciousKeywords.Count - 5) more (see full report)" -ForegroundColor Magenta
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
    
    # Count total findings
    $totalFindings = ($allAnalysisResults | ForEach-Object { 
        $_.Analysis.Base64Strings.Count + 
        $_.Analysis.URLs.Count + 
        $_.Analysis.PowerShellCommands.Count + 
        $_.Analysis.IPAddresses.Count + 
        $_.Analysis.ClipboardCommands.Count + 
        $_.Analysis.SuspiciousKeywords.Count + 
        $_.Analysis.ClipboardManipulation.Count + 
        $_.Analysis.PowerShellDownloads.Count 
    } | Measure-Object -Sum).Sum
    
    Write-Host "Found $totalFindings potential indicators:" -ForegroundColor Cyan
    
    # Create consolidated HTML report
    $consolidatedHtmlFile = Join-Path $outputDir.MainDir "consolidated_report.html"
    Create-ConsolidatedHtmlReport -AnalysisResults $allAnalysisResults -OutputFile $consolidatedHtmlFile
    Write-Host "Consolidated HTML report created at: $consolidatedHtmlFile" -ForegroundColor Green
    
    # Create consolidated JSON report
    $consolidatedJsonFile = Join-Path $outputDir.MainDir "consolidated_report.json"
    Create-ConsolidatedJsonReport -AnalysisResults $allAnalysisResults -OutputFile $consolidatedJsonFile
    Write-Host "Consolidated JSON report created with $($allAnalysisResults.Count) sites at: $consolidatedJsonFile" -ForegroundColor Green
    
    # Open the HTML report
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