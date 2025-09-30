from typing import List, Optional, Dict, Any, Set, Union, Tuple
from enum import Enum, auto
from pydantic import BaseModel, Field, HttpUrl, field_validator, computed_field, field_serializer, ConfigDict
import re
from datetime import datetime


class ReportFormat(str, Enum):
    """Report output formats supported by ClickGrab."""
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    ALL = "all"


class CommandRiskLevel(str, Enum):
    """Risk level classification for detected commands."""
    LOW = "Low Risk"
    MEDIUM = "Medium Risk"
    HIGH = "High Risk"
    CRITICAL = "Critical Risk"


class CommandType(str, Enum):
    """Types of suspicious commands that can be detected."""
    POWERSHELL = "PowerShell"
    COMMAND_PROMPT = "Command Prompt"
    MSHTA = "MSHTA"
    DLL_LOADING = "DLL Loading"
    FILE_DOWNLOAD = "File Download"
    CERTIFICATE_UTILITY = "Certificate Utility"
    SCRIPT_ENGINE = "Script Engine"
    SYSTEM_CONFIG = "System Configuration"
    ENCODED_POWERSHELL = "Encoded PowerShell"
    MALICIOUS_BATCH = "Malicious Batch File"
    FAKE_MEDIA = "Fake Media/Document File"
    TEMP_SCRIPT = "Temporary Script File"
    FAKE_GOOGLE = "Fake Google Verification"
    HIDDEN_POWERSHELL = "Hidden PowerShell"
    FILE_WRITE = "File Write Operation"
    EXECUTION_POLICY_BYPASS = "Execution Policy Bypass"
    URL_WITH_COMMENT = "Command with URL and Comment"
    SUSPICIOUS = "Suspicious Command"
    JAVASCRIPT = "JavaScript Command Execution"
    VBSCRIPT = "VBScript Command"
    CLIPBOARD_MANIPULATION = "Clipboard Manipulation"
    CAPTCHA_ELEMENT = "CAPTCHA Element"
    OBFUSCATED_JS = "Obfuscated JavaScript"
    SUSPICIOUS_REDIRECT = "Suspicious JavaScript Redirect"


class AnalysisVerdict(str, Enum):
    """Analysis verdict classifications."""
    SUSPICIOUS = "Suspicious"
    LIKELY_SAFE = "Likely Safe"
    UNKNOWN = "Unknown"


# Shared constants and patterns
class CommonPatterns:
    """Central repository for patterns shared across the codebase.
    
    This class organizes all regex patterns and constants used for detection.
    These patterns are used in extractors.py for consistent pattern matching.
    """
    
    # Benign URL patterns for filtering (used in URL validation)
    BENIGN_URL_PATTERNS = [
        r'https?://www\.w3\.org/',
        r'https?://schemas\.microsoft\.com/',
        r'https?://fonts\.googleapis\.com/',
        r'https?://fonts\.gstatic\.com/',
        r'https?://ajax\.googleapis\.com/',
        r'https?://cdnjs\.cloudflare\.com/ajax/libs/',
        r'https?://maxcdn\.bootstrapcdn\.com/',
        r'https?://stackpath\.bootstrapcdn\.com/',
        r'https?://unpkg\.com/',
    ]
    
    # Simple strings for content matching (used in quick string checks)
    BENIGN_URL_STRINGS = [
        'www.w3.org',
        'schemas.microsoft.com',
        'fonts.googleapis.com',
        'fonts.gstatic.com',
        'ajax.googleapis.com',
        'cdnjs.cloudflare.com',
        'maxcdn.bootstrapcdn.com',
        'stackpath.bootstrapcdn.com',
        'unpkg.com'
    ]
    
    # Parking page and loader patterns
    PARKING_PAGE_PATTERNS = [
        r'window\.park\s*=\s*["\']([A-Za-z0-9+/=]+)["\']',
        r'<html[^>]*data-adblockkey\s*=\s*["\'][^"\']+["\']',
        r'<div[^>]*id\s*=\s*["\']target["\'][^>]*style\s*=\s*["\'][^"\']*opacity:\s*0[^"\']*["\']',
        r'<script[^>]*src\s*=\s*["\']\/[a-zA-Z0-9]{8,10}\.js["\']'
    ]
    
    # Suspicious terms to check in content (used in keyword detection)
    SUSPICIOUS_TERMS = [
        'powershell',
        'cmd',
        'iex',
        'invoke',
        'eval(',
        'exec(',
        '.ps1',
        '.bat',
        '.exe',
        '.hta',
        'downloadstring',
        'invoke-expression',
        'invoke-webrequest',
        'webclient',
        'bypass',
        'hidden',
        'invoke-obfuscation',
        'out-file',
        'system.net.webclient',
        'get-content',
        'mshta',
        'certutil',
        'regsvr32',
        'rundll32',
        'bitsadmin',
        'wscript',
        'cscript',
        'add-type',
        'system.drawing',
        'bitmap',
        'getpixel',
        'lockbits',
        'memorystream',
        'image.fromstream',
        'exif',
        'steganography',
    ]
    
    # PowerShell dangerous indicators (used in risk assessment)
    DANGEROUS_PS_INDICATORS = [
        'iex', 
        'invoke-expression', 
        '-enc', 
        '-e ', 
        '-encodedcommand',
        '-ep',
        'executionpolicy bypass',
        'bypass', 
        'hidden',
        'system.net.webclient',
        'downloadstring',
        'downloadfile',
        'frombase64string',
        'invoke-webrequest',
        'invoke-restmethod',
        'webclient',
        'net.webclient',
        'bitstransfer'
    ]
    
    POWERSHELL_COMMAND_PATTERNS = [
        r'powershell(?:\.exe)?\s+(?:-\w+\s+)*.*',
        r'iex\s*\(.*\)',
        r'invoke-expression.*?',
        r'invoke-webrequest.*?',
        r'iwr\s+.*?',
        r'wget\s+.*?',  # This can be ambiguous in some contexts
        r'curl\s+.*?',  # This can be ambiguous in some contexts
        r'net\s+use.*?',
        r'new-object\s+.*?',
        r'powershell\s+\-w\s+\d+\s+.*',
        r'powershell\s+-w\s+\d+\s+.*',
        r'powershell(?:\.exe)?\s+(?:-\w+\s+)*-ep\s+bypass(?:\s+|$).*',
        r'const\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'const\s+text\s*=\s*["\'\`]powershell.*?["\`]',
        r'const\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+text\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+text\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'cmd\s*/?c\s+start\s+/min\s+//\s*powershell.*',
        r'cmd\s+/c\s+start\s+/min\s+powershell.*',
        r'cmd\s*/c\s+start\s+powershell.*',
        r'cmd\s+/c\s+start\s+/min\s+powershell\s+-w\s+H\s+-c.*',
        r'cmd\s+/c\s+.*powershell.*',
        r'-OutFile\s+\$env:Temp[^;\n]*;\s*&\s*["\']?\$env:Temp\\[^"\']+',
        r'powershell\s+\-encodedcommand',
        r'powershell\s+\-enc',
        r'powershell\s+\-e',
        r'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1\.0\\powershell\.exe\s.*',
        r'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1\.0\\PowerShell\.exe\s.*',
        r'C:\\Windows\\system32\\cmd.exe\s+/c\s+.*powershell.*',
        r'powershell\.exe\s+-w\s+hidden\s+(?:-\w+\s+)*.*',
        r'powershell\.exe\s+-w\s+1\s+(?:-\w+\s+)*.*',
        r'powershell\.exe\s+-noprofile\s+(?:-\w+\s+)*.*',
        r'powershell\.exe\s+-ExecutionPolicy\s+[Bb]ypass\s+(?:-\w+\s+)*.*',
        r'powershell\.exe\s+-hidden\s+(?:-\w+\s+)*.*',
        r'powershell\.exe\s+-Command\s+&\s*\{.*\}',
        r'\$env:TEMP.*\.(?:txt|ps1|bat)',
        r'Join-Path\s+\$env:TEMP.*',
        r'\$\([System\.IO\.Path\]::Combine\(\$env:TEMP.*\)\)',
        r'-OutFile\s+\(\[System\.IO\.Path\]::Combine.*',
        r'C:\\Users\\.*\\AppData\\Local\\Temp\\facedetermines\.bat',
        r'http://195\.82\.147\.86/jemmy/040625-id46/facedetermines\.bat',
        r'\\\\[^\s"\'<>\)\(]+\\[^\s"\'<>\)\(]+\.(?:mp3|bat|cmd|ps1|hta)',
        r'powershell -w hidden -c',
        r'DocumentElement\.innerHTML',
        r'DownloadString',
        r'\.DownloadString',
        r'\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString',
        r'IEX\s+\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString',
        r'\$\w+\s*=\s*New-Object\s+(?:System\.)?Net\.WebClient;\s*\$\w+\.DownloadString'
    ]
    
    # PowerShell download patterns (used in PowerShell download detection)
    POWERSHELL_DOWNLOAD_PATTERNS = [
        r'iwr\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'Invoke-WebRequest\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*Invoke-Expression',
        r'curl\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'wget\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'irm\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*iex',
        r'Invoke-RestMethod\s+["\']?(https?://[^"\'\)\s]+)["\']?\s*\|\s*Invoke-Expression',
        r'\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString\(["\']?(https?://[^"\'\)\s]+)["\']?\)',
        r'\$\w+\s*=\s*New-Object\s+(?:System\.)?Net\.WebClient;\s*\$\w+\.DownloadString\(["\']?(https?://[^"\'\)\s]+)["\']?\)',
        r'obj\.DownloadString\(["\']?(https?://[^"\'\)\s]+)["\']?\)',
        r'\.DownloadString\(["\']?(https?://[^"\'\)\s]+)["\']?\)',
        r'["\']?(https?://[^"\'\)\s]+\.ps1)["\']?',
        r'["\']?(https?://[^"\'\)\s]+\.hta)["\']?',
        r'Invoke-WebRequest\s+(?:-Uri\s+)?["\']?(https?://[^"\'\)\s]+)["\']?\s+-OutFile\s+[^\s;"\']+',
        r'iwr\s+["\']?(https?://[^"\'\)\s]+)["\']?\s+-OutFile\s+[^\s;"\']+',
        r'Invoke-(?:WebRequest|RestMethod)\s+[^\n]*\.(?:jpg|jpeg|png|gif)\b[^\n]*-OutFile\b',
        r'iwr\s+[^\n]*\.(?:jpg|jpeg|png|gif)\b[^\n]*-OutFile\b'
    ]
    
    # JavaScript obfuscation patterns (used in JS obfuscation detection)
    JS_OBFUSCATION_PATTERNS = [
        r'var\s+_0x[a-f0-9]{4,6}\s*=',
        r'_0x[a-f0-9]{4,6}\[.*?\]',
        r'_0x[a-f0-9]{2,6}\s*=\s*function',
        r'\(function\s*\(\s*_0x[a-f0-9]{2,6}\s*,\s*_0x[a-f0-9]{2,6}\s*\)',
        r'function\s+_0x[a-f0-9]{4,8}',
        r'var\s+_0x[a-f0-9]{2,8}\s*=',
        r'let\s+_0x[a-f0-9]{2,8}\s*=',
        r'const\s+_0x[a-f0-9]{2,8}\s*=',
        r'String\.fromCharCode\.apply\(null,',
        r'\[\]\["constructor"\]\["constructor"\]',
        r'\[\]\."filter"\."constructor"\(',
        r'atob\(.*?\)\."replace"\(',
        r'\[\(![!][""]\+[""]\)\[[\d]+\]\]',
        r'\("\\"\[\"constructor"\]\("return escape"\)\(\)\+"\\"\)\[\d+\]',
        r'function\s*\(\)\s*\{\s*return\s*function\s*\(\)\s*\{\s*',
        r'new Function\(\s*[\w\s,]+\,\s*atob\s*\(',
        r'["\']((?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=))["\']',
        r'[\'"`][a-zA-Z0-9_$]{1,3}[\'"`]\s*in\s*window',
        r'window\[[\'"`][a-zA-Z0-9_$]{1,3}[\'"`]\]',
        r'eval\(function\(p,a,c,k,e,(?:r|d)?\)',
        r'eval\(function\(p,a,c,k,e,r\)',
        r'\$=~\[\];\$=\{___:\+\$,\$\$\$\$',
        r'__=\[\]\[\'fill\'\]',
        r'var\s+[a-zA-Z0-9_$]+\s*=\s*\[\s*(?:[\'"`].*?[\'"`]\s*,\s*){10,}',
        r'for\s*\(\s*var\s+[a-zA-Z0-9_$]+\s*=\s*\d+\s*;\s*[a-zA-Z0-9_$]+\s*<\s*[a-zA-Z0-9_$]+\[[\'"`]length[\'"`]\]',
        r'var\s+[a-zA-Z0-9_$]+\s*=\s*[\'"`][^\'"`]{50,}[\'"`]',
        r'function\s+([a-zA-Z0-9_$]{1,3})\s*\(\s*\)\s*{\s*var\s+[a-zA-Z0-9_$]{1,3}\s*=\s*[\'"`][0-9a-fA-F]{20,}[\'"`]',
        r'window\[[\'"`][^\'"`]+[\'"`]\]\s*=\s*window\[[\'"`][^\'"`]+[\'"`]\]\s*\|\|\s*\{\}',
        r'[a-zA-Z0-9_$]{1,3}\s*\.\s*push\s*\(\s*[a-zA-Z0-9_$]{1,3}\s*\.\s*shift\s*\(\s*\)\s*\)',
        r'[a-zA-Z0-9_$]{1,3}\[[\'"`]push[\'"`]\]',
        r'[\'"`]\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}[\'"`]'
    ]
    
    # Clipboard manipulation patterns (used in clipboard manipulation detection)
    CLIPBOARD_PATTERNS = [
        r'navigator\.clipboard\.writeText\s*\(',
        r'document\.execCommand\s*\(\s*[\'"]copy[\'"]',
        r'clipboardData\.setData\s*\(',
        r'addEventListener\s*\(\s*[\'"]copy[\'"]',
        r'addEventListener\s*\(\s*[\'"]cut[\'"]',
        r'addEventListener\s*\(\s*[\'"]paste[\'"]',
        r'onpaste\s*=',
        r'oncopy\s*=',
        r'oncut\s*=',
        r'\$\s*\(.*\)\.clipboard\s*\(',
        r'new\s+ClipboardJS',
        r'clipboardjs',
        r'preventDefault\s*\(\s*\)\s*.*\s*copy',
        r'preventDefault\s*\(\s*\)\s*.*\s*cut',
        r'preventDefault\s*\(\s*\)\s*.*\s*paste',
        r'return\s+false\s*.*\s*copy',
        r'document\.getSelection\s*\(',
        r'window\.getSelection\s*\(',
        r'createRange\s*\(',
        r'selectNodeContents\s*\(',
        r'select\s*\(\s*\)',
        r'navigator\.clipboard\.writeText\(command\)',
        r'const\s+command\s*=.*?clipboard',
        r'const\s+commandToRun\s*='
    ]
    
    # CAPTCHA related patterns (used in CAPTCHA element detection)
    CAPTCHA_PATTERNS = [
        r'<div[^>]*class=["\']\s*(?:g-recaptcha|recaptcha|captcha-container|verification-container)["\'][^>]*>.*?</div>',
        r'<iframe[^>]*src=["\']\s*https?://(?:[^"\'>\s]*\.)?google\.com/recaptcha[^"\'>\s]*["\'][^>]*>',
        r'<iframe[^>]*src=["\']\s*[^"\'>\s]*captcha[^"\'>\s]*["\'][^>]*>',
        r'<img[^>]*src=["\']\s*[^"\'>\s]*captcha[^"\'>\s]*["\'][^>]*>',
        r'<img[^>]*src=["\']\s*[^"\'>\s]*verification[^"\'>\s]*["\'][^>]*>',
        r'<button[^>]*id=["\']\s*(?:captcha-submit|verify-captcha|human-check|verification-button)["\'][^>]*>.*?</button>',
        r'<div[^>]*id=["\']\s*(?:captcha|recaptcha|captcha-container|captcha-box|verification-box)["\'][^>]*>.*?</div>',
        r'<div[^>]*class=["\']\s*[^"\'>\s]*(?:recaptcha|captcha|verify)[^"\'>\s]*["\'][^>]*>.*?</div>',
        r'<div[^>]*class=["\']\s*(?:verify-human|robot-check|captcha-wrapper|captcha-challenge)["\'][^>]*>.*?</div>',
        r'function\s+(?:verifyCaptcha|verifyHuman|checkHuman|captchaCallback|onCaptchaSuccess)\s*\([^)]*\)\s*\{',
        r'const\s+captcha(?:Token|ID|Key|Response)\s*=',
        r'var\s+captcha(?:Token|ID|Key|Response)\s*=',
        r'function\s+on(?:Captcha|Verification)(?:Success|Complete|Done)',
        r'<[^>]*>\s*(?:I\'m not a robot|I am not a robot|Verify you are human|Human verification|Complete verification|CAPTCHA verification)\s*</[^>]*>',
        r'<[^>]*>\s*(?:Click to verify|Press to verify|Solve this CAPTCHA|Complete this challenge|Prove you\'re human)\s*</[^>]*>',
        r'<input[^>]*type=["\']\s*checkbox["\'][^>]*id=["\']\s*(?:captcha-checkbox|robot-checkbox|verification-check)["\'][^>]*>',
        r'<input[^>]*type=["\']\s*checkbox["\'][^>]*class=["\']\s*(?:captcha-checkbox|robot-checkbox|verification-check)["\'][^>]*>',
        r'<div[^>]*class=["\']\s*g-recaptcha\s*["\'][^>]*data-sitekey=["\']\s*[^"\'>\s]*["\'][^>]*></div>',
        r'data-callback=["\'](?:verifyCaptcha|captchaCallback|onCaptchaVerify|onSuccessfulCaptcha)["\']',
        r'var\s+captchaResponse\s*=\s*grecaptcha\.getResponse\(\)',
        r'function\s+[^(]*\([^)]*\)\s*\{\s*grecaptcha\.reset\(\);\s*\}'
    ]
    
    # Bot detection and sandbox evasion patterns
    BOT_DETECTION_PATTERNS = [
        r'turnstile\.js',
        r'cf-turnstile',
        r'data-sitekey=["\'].*?["\']',
        r'cloudflare-static',
        r'hcaptcha\.com',
        r'grecaptcha\.execute',
        r'cf_chl_(?:rc|prog|opt)',
        r'one-time(?:token|link|access)',
        r'function\s+detect(?:Bot|Crawler|Automation)',
        r'navigator\.webdriver',
        r'(?:document|window)\.automated',
        r'selenium',
        r'puppeteer',
        r'phantom',
        r'headless',
        r'wait\s*\(\s*[1-9][0-9]{3,}\s*\)',
        r'setTimeout\s*\(\s*function\s*\(\)\s*\{.{10,}\}\s*,\s*[1-9][0-9]{3,}\s*\)'
    ]
    
    # Session hijacking and cookie theft patterns
    SESSION_HIJACKING_PATTERNS = [
        r'document\.cookie',
        r'localStorage\[[\'"](?:token|session|auth)[\'"]',
        r'sessionStorage\.',
        r'getAuthToken',
        r'__Secure-',
        r'OAuth.*token',
        r'(?:access|refresh|id)Token',
        r'extractTokens',
        r'fetch\([\'"].*?token',
        r'cookie\s*=\s*document\.cookie',
        r'new\s+Image\(\)\.src\s*=\s*["\']https?://[^"\']+["\'].*?cookie',
        r'XMLHttpRequest\(\).*?POST.*?cookie',
        r'fetch\([^)]*\)\s*.\s*then',
        r'navigator\.sendBeacon\(["\']https?://',
        r'WebSocket\(["\']wss?://'
    ]
    
    # Proxy and security tool evasion techniques
    PROXY_EVASION_PATTERNS = [
        r'\.onion',
        r'tor',
        r'proxychains',
        r'cloudfront',
        r'hxxp',
        r'\.top\/',
        r'\.xyz\/',
        r'redirect\?url=',
        r'google\.translate\.com',
        r'archive\.is',
        r'web\.archive\.org',
        r'cloudfronts?\.com',
        r'amazonaws\.com',
        r'document\.referrer\.split\(\/\/\)',
        r'navigator\.userAgent\.indexOf\(["\'](?:headless|phantom|selenium|puppeteer)',
        r'window\[btoa\(["\'](document|window|location)["\']',
        r'RegExp\(["\'](chrome|hasOwnProperty|Sequentum|webdriver)["\']',
        r'while\s*\(\s*1\s*\)\s*\{\s*debugger\s*;',
        r'debugger;for\(let \w=0;\w<\d+;\w\+\+\)',
        r'eval\(function\(\w\){return \w\[\d+\]}'
    ]
    
    # OAuth phishing detection - these patterns focus on the technique, not specific IOCs
    OAUTH_PATTERNS = [
        # OAuth endpoints with authorization flows
        (r'https?://login\.microsoftonline\.com/(?:[^/]+|common)/oauth2/(?:v2\.0/)?authorize', 'OAuth Authorization Flow'),
        
        # Any OAuth URL with suspicious state parameter (typically contains a URL)
        (r'state=https?://', 'OAuth with URL in State Parameter'),
        
        # Microsoft Graph API scope (common in OAuth phishing)
        (r'scope=https?://graph\.microsoft\.com', 'Microsoft Graph API OAuth Scope'),
        
        # OAuth Code Flow - common in phishing for capturing auth codes
        (r'response_type=code', 'OAuth Code Flow'),
        
        # Suspicious redirect URIs - focus on the pattern, not specific URLs
        (r'redirect_uri=https?://[^&]+\.(dev|net)/redirect', 'Suspicious OAuth Redirect URI'),
        
        # Visual Studio-related OAuth flows - technique, not specific client IDs
        (r'client_id=[0-9a-f-]{36}.*vscode', 'Potential Visual Studio OAuth Abuse'),
        
        # Pattern showing full OAuth URL with both code flow and redirection
        (r'https?://login\.microsoftonline\.com/.*response_type=code.*redirect_uri', 'Full OAuth Code Redirection Flow'),
        
        # Suspicious combinations in the same URL  
        (r'oauth2.*response_type=code.*state=https?', 'OAuth Code Flow with URL State'),
    ]
    
    # PowerShell standalone download patterns (without URL extraction)
    POWERSHELL_STANDALONE_DOWNLOAD_PATTERNS = [
        r'DownloadString',
        r'\.DownloadString',
        r'\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString',
        r'IEX\s+\(New-Object\s+(?:System\.)?Net\.WebClient\)\.DownloadString',
        r'\$\w+\s*=\s*New-Object\s+(?:System\.)?Net\.WebClient;\s*\$\w+\.DownloadString'
    ]
    
    # HTA path patterns for detecting HTA file deployment
    HTA_PATH_PATTERNS = [
        r'const\s+htaPath\s*=\s*["\'](.+?\.hta)["\']',
        r'var\s+htaPath\s*=\s*["\'](.+?\.hta)["\']',
        r'let\s+htaPath\s*=\s*["\'](.+?\.hta)["\']'
    ]
    
    # JavaScript command execution patterns
    JS_COMMAND_EXECUTION_PATTERNS = [
        r'WScript\.Shell',
        r'new\s+ActiveXObject\s*\(\s*[\'"]WScript\.Shell[\'"]',
        r'process\.spawn',
        r'child_process',
        r'exec\s*\(',
        r'execSync\s*\(',
        r'subprocess\.',
        r'system\s*\(',
        r'popen\s*\(',
        r'cmd\.exe',
        r'command\.com',
        r'powershell\.exe',
        r'\.exec\(["\'].*?[cmd|powershell]',
        r'ActiveXObject.*?wscript\.shell',
        r'Function\s*\("return.*?process'
    ]
    
    # VBScript command execution patterns
    VBS_COMMAND_PATTERNS = [
        r'Set\s+\w+\s*=\s*CreateObject\s*\(\s*"WScript\.Shell"\s*\)',
        r'<script\s+language\s*=\s*[\'"]vbscript[\'"].*?>.*?</script>',
        r'<script\s+type\s*=\s*[\'"]text/vbscript[\'"].*?>.*?</script>',
        r'\.run\s*\(',
        r'WScript\.Shell.*?\.Run',
        r'WScript\.CreateObject'
    ]
    
    # Clipboard command execution patterns
    CLIPBOARD_COMMAND_PATTERNS = [
        r'navigator\.clipboard\.writeText\s*\(\s*["\']powershell',
        r'navigator\.clipboard\.writeText\s*\(\s*command\s*\)',
        r'const\s+command\s*=\s*["\']powershell[^"\']*["\']\s*;.*\s*navigator\.clipboard\.writeText',
        r'const\s+commandToRun\s*=\s*[`\'\"]powershell[^`\'\"]*[`\'\"]',
        r'commandToRun\s*;?\s*navigator\.clipboard\.writeText\s*\('
    ]
    
    # Command execution patterns for suspicious keyword detection
    SUSPICIOUS_COMMAND_PATTERNS = [
        # Command execution patterns
        r'cmd(?:\.exe)?\s+(?:/\w+\s+)*.*',
        r'command(?:\.com)?\s+(?:/\w+\s+)*.*',
        r'bash\s+-c\s+.*',
        r'sh\s+-c\s+.*',
        r'exec\s+.*',
        r'system\s*\(.*\)',
        r'exec\s*\(.*\)',
        r'eval\s*\(.*\)',
        r'execSync\s*\(.*\)',
        # Image steganography extraction hints in PowerShell/.NET
        r'Add-Type\s+-Assembly(?:Name)?\s+System\.Drawing',
        r'New-Object\s+System\.Drawing\.Bitmap',
        r'\[System\.Drawing\.Bitmap\]::new\(',
        r'GetPixel\s*\(',
        r'LockBits\s*\(',
        r'New-Object\s+System\.IO\.MemoryStream',
        r'(Get-Content|ReadAllBytes)\s+[^\n]*\.(jpg|jpeg|png)'
    ]
    
    # CAPTCHA and human verification patterns
    CAPTCHA_VERIFICATION_PATTERNS = [
        # CAPTCHA verification patterns
        r'verification successful',
        r'human verification complete',
        r'verification code',
        r'captcha verification',
        r'verification hash',
        r'verification id',
        r'ray id',
        r'i am not a robot',
        r'i am human',
        r'verification session',
        r'verification token',
        r'security verification required',
        r'anti-bot verification',
        r'solve this captcha',
        r'complete verification',
        r'bot detection bypassed',
        r'copy this command',
        r'paste in command prompt',
        r'paste in powershell',
        r'start -> run',
        r'press\s+ctrl\s*\+\s*s',
        r'press ctrl\+c to copy',
        r'press ctrl\+v to paste',
        r'press\s+ctrl\s*\+\s*v',
        r'press\s+enter',
        r'(?:win|windows)\s*(?:key|button)\s*\+\s*r',
        r'click to verify',
        r'cloud identification',
        r'cloud identifier',
        r'complete these verification steps',
        r'follow the instructions below',
        r'recaptcha\s+id',
        r'mandatory\s+re?captcha\s+system',
        r'you will\s+(?:observe|accept)'
        
        # More general captcha-related patterns
        r'captcha[a-zA-Z0-9_-]*',
        r'robot(?:OrHuman)?',
        r'verification[a-zA-Z0-9_-]*',
        r'press the key combination',
        
        # Fake CAPTCHA verification keywords
        r'checking if you are human',
        r'verify you are human',
        r'cloudflare verification',
        r'to better prove you are not a robot',
        r'navigator\.clipboard\.writeText',
        r'const command =',
        r'powershell -w 1'
    ]
    
    # Suspicious JavaScript redirect patterns
    SUSPICIOUS_JS_REDIRECT_PATTERNS = [
        r'window\.location\s*=\s*["\'](https?://|\.\./|/)[^"\']+["\']',
        r'window\.location\.href\s*=\s*["\'](https?://|\.\./|/)[^"\']+["\']',
        r'window\.location\.replace\s*\(\s*["\'](https?://|\.\./|/)[^"\']+["\']\s*\)',
        r'document\.location\s*=\s*["\'](https?://|\.\./|/)[^"\']+["\']',
        r'document\.location\.href\s*=\s*["\'](https?://|\.\./|/)[^"\']+["\']',
        r'document\.location\.replace\s*\(\s*["\'](https?://|\.\./|/)[^"\']+["\']\s*\)',
        r'location\.href\s*=\s*["\'](https?://|\.\./|/)[^"\']+["\']',
        r'location\.replace\s*\(\s*["\'](https?://|\.\./|/)[^"\']+["\']\s*\)',
        r'top\.location\s*=\s*["\']https?://[^"\']+["\']',
        r'self\.location\s*=\s*["\']https?://[^"\']+["\']',
        r'parent\.location\s*=\s*["\']https?://[^"\']+["\']',
        r'window\.park\s*=',
        r'window\.__park\s*=',
        r'atob\(\s*["\'][A-Za-z0-9+/=]+["\']\s*\)',
        r'<script[^>]*src\s*=\s*["\'][^"\']*\.[a-zA-Z0-9]{5,}\.js["\']',
        r'<iframe[^>]*src\s*=\s*["\']about:blank["\'][^>]*></iframe>',
        r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\'][^>]*content\s*=\s*["\']0;\s*URL=',
        r'function\s*redirect\s*\([^\)]*\)\s*{\s*(?:window|document|self|top|parent)\.location',
        r'setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*(?:window|document)\.location',
        r'decodeURIComponent\(escape\(atob\(',
        r'\.exec\s*\(\s*atob\s*\(',
        r'JSON\.parse\s*\(\s*atob\s*\(',
        r'\.split\s*\(\s*["\'][^"\']+["\']\s*\)\.join\s*\(\s*["\'][^"\']*["\']\s*\)',
        r'fromCharCode\.apply\s*\(\s*null',
        r'charCodeAt\s*\(\s*\d+\s*\)\s*\^\s*\d+',
        r'charCodeAt\s*\(\s*\d+\s*\)\s*[+-]\s*\d+',
        r'\[\s*["\']\w+["\']\s*\]\s*\[\s*["\']\w+["\']\s*\]',
        r'</body>\s*<script[^>]*></script>$',
        r'eval\s*\(\s*\w+\[\s*["\']\w+["\']\s*\]\s*\+\s*\w+\[\s*["\']\w+["\']\s*\]\s*\)'
    ]

    @classmethod
    def combine_patterns_with_risk(cls, pattern_list: List[str], default_risk: str = CommandRiskLevel.MEDIUM.value) -> List[Tuple[str, str]]:
        """Combine patterns and assign risk levels dynamically based on content.
        
        Args:
            pattern_list: List of regex patterns
            default_risk: Default risk level to assign
            
        Returns:
            List of tuples containing (pattern, risk_level)
        """
        result = []
        
        for pattern in pattern_list:
            # Assign HIGH risk for dangerous PowerShell indicators
            if any(indicator in pattern.lower() for indicator in cls.DANGEROUS_PS_INDICATORS):
                result.append((pattern, CommandRiskLevel.HIGH.value))
            # Assign HIGH risk for evasion techniques
            elif any(evasion in pattern.lower() for evasion in ['hidden', 'bypass', '-w 1', '-noprofile']):
                result.append((pattern, CommandRiskLevel.HIGH.value))
            # Assign CRITICAL risk for certain dangerous commands
            elif any(critical in pattern.lower() for critical in ['iex', 'invoke-expression', 'frombase64string', 'downloadstring']):
                result.append((pattern, CommandRiskLevel.CRITICAL.value))
            else:
                result.append((pattern, default_risk))
                
        return result


class Base64Result(BaseModel):
    """A decoded Base64 string with both original and decoded content."""
    Base64: str = Field(..., description="The original Base64 encoded string")
    Decoded: str = Field(..., description="The decoded content of the Base64 string")
    
    model_config = ConfigDict(frozen=True)
    
    @computed_field
    def Length(self) -> int:
        """Get the length of the Base64 string."""
        return len(self.Base64)
    
    @computed_field
    def ContainsPowerShell(self) -> bool:
        """Check if the decoded content contains PowerShell indicators."""
        return any(indicator.lower() in self.Decoded.lower() 
                   for indicator in ["powershell", "iex", "invoke-expression", "-enc"])
    
    @computed_field
    def ContainsBenignURL(self) -> bool:
        """Check if the decoded content contains only benign URLs."""
        decoded_lower = self.Decoded.lower()
        
        # Check if any benign URL is present in the decoded content
        has_benign_url = any(pattern in decoded_lower for pattern in CommonPatterns.BENIGN_URL_STRINGS)
        
        # Check for absence of suspicious patterns
        has_suspicious = any(term in decoded_lower for term in CommonPatterns.SUSPICIOUS_TERMS)
        
        # Return true if has benign URL and no suspicious patterns
        return has_benign_url and not has_suspicious


class PowerShellDownload(BaseModel):
    """A PowerShell download command with context and target information."""
    FullMatch: str = Field(..., description="The full matching text that was detected")
    URL: Optional[str] = Field(None, description="The URL being downloaded from, if found")
    Context: str = Field(..., description="Context surrounding the download command")
    HTAPath: Optional[str] = Field(None, description="Path to HTA file, if applicable")
    
    @computed_field
    def IsPotentiallyDangerous(self) -> bool:
        """Check if this download appears particularly dangerous."""
        return any(indicator in self.FullMatch.lower() 
                   for indicator in CommonPatterns.DANGEROUS_PS_INDICATORS)
    
    @computed_field
    def RiskLevel(self) -> str:
        """Determine risk level based on content."""
        if self.URL and any(ext in self.URL.lower() for ext in ['.ps1', '.exe', '.bat', '.hta']):
            return CommandRiskLevel.HIGH.value
        elif self.IsPotentiallyDangerous:
            return CommandRiskLevel.HIGH.value
        else:
            return CommandRiskLevel.MEDIUM.value


class SuspiciousCommand(BaseModel):
    """A suspicious command detected in the analysis."""
    Command: str = Field(..., description="The suspicious command that was detected")
    CommandType: str = Field(..., description="Classification of the command type")
    Source: Optional[str] = Field(None, description="Where the command was found")
    RiskLevel: str = Field(CommandRiskLevel.MEDIUM.value, description="Risk level of the command")
    
    @field_validator('CommandType', mode='before')
    @classmethod
    def convert_command_type(cls, v):
        """Convert CommandType enum to string value if needed."""
        if isinstance(v, CommandType):
            return v.value
        return v
    
    @field_validator('RiskLevel', mode='before')
    @classmethod
    def convert_risk_level(cls, v):
        """Convert RiskLevel enum to string value if needed."""
        if isinstance(v, CommandRiskLevel):
            return v.value
        return v
    
    @computed_field
    def is_high_risk(self) -> bool:
        """Check if this is a high-risk command."""
        return CommandRiskLevel.HIGH.value in self.RiskLevel or CommandRiskLevel.CRITICAL.value in self.RiskLevel


class EncodedPowerShellResult(BaseModel):
    """An encoded PowerShell command with its decoded content."""
    EncodedCommand: str = Field(..., description="The Base64 encoded command")
    DecodedCommand: str = Field(..., description="The decoded PowerShell command")
    FullMatch: str = Field(..., description="The full text match containing the encoded command")
    
    @computed_field
    def HasSuspiciousContent(self) -> bool:
        """Check if the decoded command has suspicious content."""
        decoded_lower = self.DecodedCommand.lower()
        return any(term in decoded_lower for term in CommonPatterns.DANGEROUS_PS_INDICATORS) or \
               any(term in decoded_lower for term in ["http", "ftp", "url", ".exe", ".ps1", ".bat", ".hta"])
    
    @computed_field
    def RiskLevel(self) -> str:
        """Determine risk level of the encoded PowerShell."""
        if self.HasSuspiciousContent:
            return CommandRiskLevel.HIGH.value
        return CommandRiskLevel.MEDIUM.value


class ClickGrabConfig(BaseModel):
    """Configuration for ClickGrab URL analyzer."""
    analyze: Optional[str] = Field(None, description="URL to analyze or path to a file containing URLs")
    limit: Optional[int] = Field(None, description="Limit the number of URLs to process")
    debug: bool = Field(False, description="Enable debug output")
    output_dir: str = Field("reports", description="Directory for report output")
    format: str = Field(ReportFormat.ALL.value, description="Report format")
    tags: List[str] = Field(default_factory=lambda: ["FakeCaptcha", "ClickFix", "click"], 
                                     description="List of tags to filter by")
    download: bool = Field(False, description="Download and analyze URLs from URLhaus")
    otx: bool = Field(False, description="Download and analyze URLs from AlienVault OTX")
    days: int = Field(30, description="Number of days to look back in AlienVault OTX")
    clickfix_gist: bool = Field(False, description="Download and analyze domains from the ClickFix gist feed")
    clickfix_gist_id: Optional[str] = Field(
        None,
        description="Override the GitHub Gist ID for the ClickFix feed (default: 9f563dfb78a06fad5db794f33ba93a3f)"
    )

    @field_validator('limit')
    @classmethod
    def check_limit(cls, v):
        """Validate the URL limit."""
        if v is not None and v <= 0:
            raise ValueError("Limit must be greater than 0")
        return v
    
    @field_validator('days')
    @classmethod
    def check_days(cls, v):
        """Validate the number of days."""
        if v <= 0:
            raise ValueError("Days must be greater than 0")
        if v > 90:
            raise ValueError("Days cannot exceed 90")
        return v

    @field_validator('clickfix_gist_id')
    @classmethod
    def validate_clickfix_gist_id(cls, v):
        """Ensure the ClickFix gist ID is valid if provided."""
        if v is None:
            return v
        # Basic validation: gist IDs are hexadecimal strings
        if not v or not all(c in '0123456789abcdef' for c in v.lower()):
            raise ValueError("ClickFix gist ID must be a valid hexadecimal string")
        return v
    
    @field_validator('tags', mode='before')
    @classmethod
    def parse_tags(cls, v):
        """Parse tags from string or list."""
        if v is None:
            return ["FakeCaptcha", "ClickFix", "click"]
        if isinstance(v, str):
            return [t.strip() for t in v.split(',')]
        return v
    
    @field_validator('format', mode='before')
    @classmethod
    def validate_format(cls, v):
        """Validate and convert the report format."""
        if isinstance(v, ReportFormat):
            return v.value
        
        if isinstance(v, str):
            try:
                return ReportFormat(v.lower()).value
            except ValueError:
                raise ValueError(f"Invalid format: {v}. Must be one of: {', '.join([f.value for f in ReportFormat])}")
        return v


class AnalysisResult(BaseModel):
    """Results of analyzing a URL for malicious content."""
    URL: str = Field(..., description="The analyzed URL")
    RawHTML: str = Field(..., description="Raw HTML content from the URL")
    Base64Strings: List[Base64Result] = Field(default_factory=list, description="Base64 encoded strings found")
    URLs: List[str] = Field(default_factory=list, description="URLs found in the content")
    PowerShellCommands: List[str] = Field(default_factory=list, description="PowerShell commands found")
    EncodedPowerShell: List[EncodedPowerShellResult] = Field(default_factory=list, description="Encoded PowerShell commands found")
    IPAddresses: List[str] = Field(default_factory=list, description="IP addresses found in the content")
    ClipboardCommands: List[str] = Field(default_factory=list, description="Commands related to clipboard manipulation")
    SuspiciousKeywords: List[str] = Field(default_factory=list, description="Suspicious keywords found")
    ClipboardManipulation: List[str] = Field(default_factory=list, description="JavaScript code manipulating clipboard")
    PowerShellDownloads: List[PowerShellDownload] = Field(default_factory=list, description="PowerShell download commands")
    CaptchaElements: List[str] = Field(default_factory=list, description="CAPTCHA-related HTML elements")
    ObfuscatedJavaScript: List[str] = Field(default_factory=list, description="Potentially obfuscated JavaScript")
    SuspiciousCommands: List[SuspiciousCommand] = Field(default_factory=list, description="Suspicious commands detected")
    BotDetection: List[str] = Field(default_factory=list, description="Bot detection and sandbox evasion techniques")
    SessionHijacking: List[str] = Field(default_factory=list, description="Session token or cookie theft attempts")
    ProxyEvasion: List[str] = Field(default_factory=list, description="Proxy/security tool evasion techniques")
    JavaScriptRedirects: List[str] = Field(default_factory=list, description="Suspicious JavaScript redirects and loaders")
    ParkingPageLoaders: List[str] = Field(default_factory=list, description="Parking page loaders with window.park patterns")
    
    @field_validator('URLs')
    @classmethod
    def validate_urls(cls, v):
        """Filter out common benign URLs."""
        return [url for url in v if not any(re.match(pattern, url) for pattern in CommonPatterns.BENIGN_URL_PATTERNS)]
    
    @field_serializer('RawHTML')
    def serialize_raw_html(self, value: str):
        """Truncate RawHTML for serialization to avoid huge JSON payloads."""
        if len(value) > 1000:
            return value[:1000] + "... [truncated]"
        return value
    
    @computed_field
    def TotalIndicators(self) -> int:
        """Calculate the total number of indicators found."""
        return (
            len(self.Base64Strings) +
            len(self.URLs) +
            len(self.PowerShellCommands) +
            len(self.EncodedPowerShell) +
            len(self.IPAddresses) +
            len(self.ClipboardCommands) +
            len(self.SuspiciousKeywords) +
            len(self.ClipboardManipulation) +
            len(self.PowerShellDownloads) +
            len(self.CaptchaElements) +
            len(self.ObfuscatedJavaScript) +
            len(self.SuspiciousCommands) +
            len(self.BotDetection) +
            len(self.SessionHijacking) +
            len(self.ProxyEvasion) +
            len(self.JavaScriptRedirects) +
            len(self.ParkingPageLoaders)
        )
    
    @computed_field
    def Verdict(self) -> str:
        """Determine if the URL is suspicious based on indicators."""
        # Check for PowerShell commands (filtered to remove false positives)
        filtered_powershell_commands = [
            cmd for cmd in self.PowerShellCommands 
            if not (cmd.startswith('http') and 
                   not any(term in cmd.lower() for term in ['powershell', 'cmd', 'iex', 'iwr', 'invoke', '.ps1', '.bat', '.hta']))
        ]
        
        if filtered_powershell_commands:
            return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for suspicious Base64 strings
        suspicious_base64 = [
            b64 for b64 in self.Base64Strings 
            if b64.ContainsPowerShell and not b64.ContainsBenignURL
        ]
        if suspicious_base64:
            return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for clipboard manipulation with commands
        if self.ClipboardManipulation and self.ClipboardCommands:
            return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for PowerShell downloads
        if self.PowerShellDownloads:
            return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for encoded PowerShell
        if self.EncodedPowerShell:
            return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for suspicious commands
        if self.SuspiciousCommands:
            # Specifically check for high-risk commands
            high_risk_commands = [cmd for cmd in self.SuspiciousCommands 
                                 if cmd.is_high_risk]
            if high_risk_commands:
                return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for obfuscated JavaScript
        if self.ObfuscatedJavaScript:
            return AnalysisVerdict.SUSPICIOUS.value
        
        # Check for at least 2 of the following:
        indicators = 0
        
        if self.CaptchaElements:
            indicators += 1
        
        if any("captcha" in kw.lower() for kw in self.SuspiciousKeywords):
            indicators += 1
        
        if any("robot" in kw.lower() for kw in self.SuspiciousKeywords):
            indicators += 1
        
        if any("verify" in kw.lower() for kw in self.SuspiciousKeywords):
            indicators += 1
        
        if self.ClipboardManipulation:
            indicators += 1
        
        if indicators >= 2:
            return AnalysisVerdict.SUSPICIOUS.value
            
        return AnalysisVerdict.LIKELY_SAFE.value
    
    @computed_field
    def HighRiskCommands(self) -> List[SuspiciousCommand]:
        """Get only high-risk commands."""
        return [cmd for cmd in self.SuspiciousCommands if cmd.is_high_risk]
    
    @computed_field
    def ThreatScore(self) -> int:
        """Calculate a threat score based on the indicators found."""
        score = 0
        
        # Add points for Base64 strings, with extra for those containing PowerShell
        for b64 in self.Base64Strings:
            score += 5
            if b64.ContainsPowerShell:
                score += 15
                
        # Add points for PowerShell commands
        score += len(self.PowerShellCommands) * 10
        
        # Add points for encoded PowerShell
        for encoded_ps in self.EncodedPowerShell:
            base_points = 15
            if encoded_ps.HasSuspiciousContent:
                base_points += 15
            if CommandRiskLevel.HIGH.value in encoded_ps.RiskLevel:
                base_points += 20
            elif CommandRiskLevel.MEDIUM.value in encoded_ps.RiskLevel:
                base_points += 10
            score += base_points
        
        # Add points for PowerShell downloads
        for download in self.PowerShellDownloads:
            base_points = 15
            if CommandRiskLevel.HIGH.value in download.RiskLevel:
                base_points += 15
            elif CommandRiskLevel.MEDIUM.value in download.RiskLevel:
                base_points += 10
            score += base_points
        
        # Add points for SuspiciousCommands
        for cmd in self.SuspiciousCommands:
            if cmd.RiskLevel == CommandRiskLevel.HIGH.value:
                score += 20
            elif cmd.RiskLevel == CommandRiskLevel.MEDIUM.value:
                score += 10
            else:
                score += 5
        
        # Add points for various other indicators
        score += len(self.ClipboardManipulation) * 15
        score += len(self.ClipboardCommands) * 15
        score += len(self.CaptchaElements) * 5
        score += len(self.ObfuscatedJavaScript) * 10
        score += len(self.SuspiciousKeywords) * 3
        score += len(self.IPAddresses) * 2
        score += len(self.URLs) * 1
        
        # Add points for newer extraction types
        score += len(self.BotDetection) * 5
        score += len(self.SessionHijacking) * 15
        score += len(self.ProxyEvasion) * 10
        score += len(self.JavaScriptRedirects) * 15
        score += len(self.ParkingPageLoaders) * 25  # Add high score for parking page loaders
        
        return score


class AnalysisReport(BaseModel):
    """Consolidated report from multiple URL analyses."""
    timestamp: str = Field(..., description="Time the report was generated")
    total_sites_analyzed: int = Field(..., description="Total number of sites analyzed")
    summary: Dict[str, int] = Field(..., description="Summary statistics of findings")
    sites: List[AnalysisResult] = Field(..., description="Analysis results for each site")
    
    @field_validator('timestamp', mode='before')
    @classmethod
    def validate_timestamp(cls, v):
        """Ensure timestamp is in the correct format."""
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%d %H:%M:%S")
        return v
    
    @computed_field
    def suspicious_sites_percentage(self) -> float:
        """Calculate percentage of suspicious sites."""
        if self.total_sites_analyzed == 0:
            return 0.0
        suspicious_count = sum(1 for site in self.sites if site.Verdict == AnalysisVerdict.SUSPICIOUS.value)
        return round((suspicious_count / self.total_sites_analyzed) * 100, 2)
    
    @computed_field
    def report_date(self) -> str:
        """Get the report date in YYYY-MM-DD format."""
        if '-' in self.timestamp and ' ' in self.timestamp:
            return self.timestamp.split(' ')[0]
        return self.timestamp.split(' ')[0] 
    
    @computed_field
    def high_risk_commands_count(self) -> int:
        """Get the total count of high-risk commands across all sites."""
        return sum(len(site.HighRiskCommands) for site in self.sites) 