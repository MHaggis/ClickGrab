"""Finding category definitions — groups 32+ indicator types into 5 scannable sections."""

FINDING_CATEGORIES = {
    "Execution": {
        "icon": ":material/terminal:",
        "color": "#EF5350",
        "fields": [
            ("PowerShellCommands", "PowerShell Commands"),
            ("EncodedPowerShell", "Encoded PowerShell"),
            ("MacOSTerminalCommands", "macOS Terminal"),
            ("DNSClickFix", "DNS ClickFix (nslookup)"),
            ("WindowsTerminalClickFix", "Windows Terminal"),
            ("WebDAVClickFix", "WebDAV net use"),
            ("FingerExeAbuse", "finger.exe / CrashFix"),
            ("WinHttpVBScript", "WinHttp VBScript"),
            ("PowerShellDownloads", "PowerShell Downloads"),
            ("SuspiciousCommands", "Suspicious Commands"),
        ],
    },
    "Social Engineering": {
        "icon": ":material/psychology:",
        "color": "#FF9800",
        "fields": [
            ("ClickFixInstructions", "ClickFix Instructions"),
            ("FakeCloudflare", "Fake Cloudflare"),
            ("FakeVideoConferencing", "Fake Video Conferencing"),
            ("FakeWindowsUpdate", "Fake Windows Update"),
            ("FakeGlitchLures", "Fake Glitch Lures"),
            ("FakeSoftwareDownloads", "Fake Software Downloads"),
            ("ConsentFixIndicators", "ConsentFix OAuth Theft"),
            ("LLMArtifactAbuse", "LLM / AI Artifact Abuse"),
            ("SharedAIChatLinks", "Shared AI Chat Links"),
            ("CaptchaElements", "CAPTCHA Elements"),
        ],
    },
    "Obfuscation": {
        "icon": ":material/visibility_off:",
        "color": "#AB47BC",
        "fields": [
            ("ObfuscatedJavaScript", "Obfuscated JavaScript"),
            ("HeavyObfuscation", "Heavy JS Obfuscation"),
            ("Base64Strings", "Base64 Strings"),
            ("HexEncodedIPs", "Hex-Encoded IPs"),
            ("SteganographyIndicators", "Steganography / Cache Smuggling"),
        ],
    },
    "Infrastructure": {
        "icon": ":material/dns:",
        "color": "#42A5F5",
        "fields": [
            ("URLs", "Extracted URLs"),
            ("IPAddresses", "IP Addresses"),
            ("JavaScriptRedirects", "JS Redirects"),
            ("JavaScriptRedirectChains", "JS Redirect Chains"),
            ("RedirectFollows", "Redirect Follows"),
            ("ParkingPageLoaders", "Parking Page Loaders"),
        ],
    },
    "Data Theft": {
        "icon": ":material/lock_open:",
        "color": "#66BB6A",
        "fields": [
            ("ClipboardManipulation", "Clipboard Manipulation"),
            ("ClipboardCommands", "Clipboard Commands"),
            ("SessionHijacking", "Session Hijacking"),
            ("BotDetection", "Bot Detection Evasion"),
            ("ProxyEvasion", "Proxy Evasion"),
            ("SuspiciousKeywords", "Suspicious Keywords"),
        ],
    },
}
