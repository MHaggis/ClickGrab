from typing import List, Optional, Dict, Any, Set, Union
from enum import Enum, auto
from pydantic import BaseModel, Field, HttpUrl, field_validator, computed_field, field_serializer, ConfigDict
import re
from datetime import datetime


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
    ]
    
    # PowerShell dangerous indicators (used in risk assessment)
    DANGEROUS_PS_INDICATORS = [
        'iex', 
        'invoke-expression', 
        '-enc', 
        '-e ', 
        '-encodedcommand',
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
        r'const\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'const\s+text\s*=\s*["\'\`]powershell.*?["\`]',
        r'const\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+text\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+text\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'cmd\s+/c\s+start\s+/min\s+powershell.*',
        r'cmd\s*/c\s+start\s+powershell.*',
        r'cmd\s+/c\s+start\s+/min\s+powershell\s+-w\s+H\s+-c.*',
        r'cmd\s+/c\s+.*powershell.*',
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
        r'["\']?(https?://[^"\'\)\s]+\.hta)["\']?'
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
        r'const\s+command\s*=.*?clipboard'
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


class AnalysisVerdict(str, Enum):
    """Analysis verdict classifications."""
    SUSPICIOUS = "Suspicious"
    LIKELY_SAFE = "Likely Safe"
    UNKNOWN = "Unknown"


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
        """Get the total number of indicators detected."""
        return (
            len(self.Base64Strings) +
            len(self.PowerShellCommands) +
            len(self.EncodedPowerShell) +
            len(self.ClipboardCommands) +
            len(self.ClipboardManipulation) +
            len(self.PowerShellDownloads) +
            len(self.CaptchaElements) +
            len(self.ObfuscatedJavaScript) +
            len(self.SuspiciousCommands)
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
        """Calculate threat score based on indicators."""
        score = 0
        
        # PowerShell commands are highly suspicious
        ps_commands = len(self.PowerShellCommands)
        if ps_commands > 0:
            score += min(30, ps_commands * 5)
        
        # PowerShell downloads are highly suspicious
        ps_downloads = len(self.PowerShellDownloads)
        if ps_downloads > 0:
            score += min(30, ps_downloads * 15)
        
        # Clipboard manipulation is suspicious
        clipboard_manip = len(self.ClipboardManipulation)
        if clipboard_manip > 0:
            score += min(20, clipboard_manip * 5)
        
        # Obfuscated JavaScript is highly suspicious
        obfuscated_js = len(self.ObfuscatedJavaScript)
        if obfuscated_js > 0:
            score += min(40, obfuscated_js * 8)
        
        # Suspicious commands are highly suspicious
        suspicious_cmds = len(self.SuspiciousCommands)
        if suspicious_cmds > 0:
            score += min(50, suspicious_cmds * 10)
        
        # Encoded PowerShell is highly suspicious 
        encoded_ps = len(self.EncodedPowerShell)
        if encoded_ps > 0:
            score += min(30, encoded_ps * 15)
        
        # Base64 strings might be suspicious
        base64_strings = len([b for b in self.Base64Strings if b.ContainsPowerShell])
        if base64_strings > 0:
            score += min(15, base64_strings * 3)
        
        # Suspicious keywords
        suspicious_keywords = len(self.SuspiciousKeywords)
        if suspicious_keywords > 0:
            score += min(20, suspicious_keywords * 2)
        
        # CAPTCHA elements are suspicious
        captcha_elements = len(self.CaptchaElements)
        if captcha_elements > 0:
            score += min(15, captcha_elements * 3)
        
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