import re
import base64
from typing import List, Dict, Set, Any, Tuple, Union, Optional

# Python 3.11+ compatibility for StrEnum
try:
    from enum import StrEnum
except ImportError:
    # Fallback for Python < 3.11
    from enum import Enum
    class StrEnum(str, Enum):
        pass
from models import (
    Base64Result, 
    PowerShellDownload, 
    SuspiciousCommand,
    EncodedPowerShellResult,
    CommandType,
    CommandRiskLevel,
    CommonPatterns
)
from enum import auto


class PatternCategory(StrEnum):
    """Categories for different types of PowerShell/command patterns"""
    FLAG = "PowerShell Flag"
    COMPONENT = "PowerShell Component" 
    COMMAND = "PowerShell Command"
    EXECUTION = "Execution Method"
    DOWNLOAD = "Download Method"
    OBFUSCATION = "Obfuscation Technique"
    ENVIRONMENT = "Environment Variable"
    JAVASCRIPT = "JavaScript Execution"
    VBS = "VBScript"
    OAUTH = "OAuth"
    PARKING = "Parking Page"


# Helper functions to reduce duplication

def extract_match_with_context(match: re.Match, content: str, context_length: int = 50) -> str:
    """Extract match with surrounding context, with length limitation.
    
    Args:
        match: The regex match object
        content: The full content string containing the match
        context_length: The number of characters to include before and after the match
        
    Returns:
        The match with surrounding context
    """
    start = max(0, match.start() - context_length)
    end = min(len(content), match.end() + context_length)
    context = content[start:end].strip()
    # Cleanup whitespace
    context = re.sub(r'\s+', ' ', context)
    # If context doesn't include the full content, add ellipsis
    if start > 0 or end < len(content):
        context = f"...{context}..."
    return context


def check_match_overlap(match: re.Match, matched_positions: Set[int]) -> bool:
    """Check if a match overlaps with previously matched positions.
    
    Args:
        match: The regex match object
        matched_positions: Set of already matched positions
        
    Returns:
        True if the match overlaps with already matched positions
    """
    start, end = match.span()
    for pos in range(start, end):
        if pos in matched_positions:
            return True
    return False


def mark_match_positions(match: re.Match, matched_positions: Set[int]) -> None:
    """Mark positions in a match as already matched.
    
    Args:
        match: The regex match object
        matched_positions: Set to add positions to
    """
    start, end = match.span()
    for pos in range(start, end):
        matched_positions.add(pos)


def extract_base64_strings(text: str) -> List[Base64Result]:
    """Extract Base64 strings and attempt to decode them."""
    # Standard Base64 pattern
    base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
    
    # Find potential Base64 strings (at least 16 chars to avoid false positives)
    potential_b64s = []
    
    # Look for standard Base64 strings
    for match in re.finditer(r'[A-Za-z0-9+/=]{16,}', text):
        b64 = match.group()
        # Must match the Base64 pattern
        if re.fullmatch(base64_pattern, b64):
            potential_b64s.append(b64)
    
    # Look specifically for PowerShell EncodedCommand parameters
    encoded_cmd_pattern = r'-EncodedCommand\s+([A-Za-z0-9+/=]+)'
    encoded_commands = re.finditer(encoded_cmd_pattern, text, re.IGNORECASE)
    for match in encoded_commands:
        potential_b64s.append(match.group(1))
    
    # Look for shorter Base64 commands that might be part of a PowerShell script
    short_encoded_pattern = r'(?:-e|-enc|-encode|-encodedcommand)\s+([A-Za-z0-9+/=]{8,})'
    short_encoded = re.finditer(short_encoded_pattern, text, re.IGNORECASE)
    for match in short_encoded:
        potential_b64s.append(match.group(1))
    
    # Look for Base64 strings in FromBase64String calls
    base64_calls = re.finditer(r'FromBase64String\(\s*["\']([A-Za-z0-9+/=]+)["\']', text, re.IGNORECASE)
    for match in base64_calls:
        potential_b64s.append(match.group(1))
    
    nested_base64 = re.finditer(r'GetString\(\s*[^)]*FromBase64String\(\s*["\']([A-Za-z0-9+/=]+)["\']', text, re.IGNORECASE)
    for match in nested_base64:
        potential_b64s.append(match.group(1))
    
    complex_nested = re.finditer(r'iex\(\s*[^)]*GetString\(\s*[^)]*FromBase64String\(\s*["\']([A-Za-z0-9+/=]+)["\']', text, re.IGNORECASE)
    for match in complex_nested:
        potential_b64s.append(match.group(1))
    
    truncated_base64 = re.finditer(r'["\']([A-Za-z0-9+/]{4,}\.\.\.)["\']', text, re.IGNORECASE)
    for match in truncated_base64:
        potential_b64s.append(match.group(1))
    
    abbreviated_base64 = re.finditer(r'FromBase64String\(\s*["\'](aHR0[A-Za-z0-9+/]*(?:\.\.\.)?)["\']', text, re.IGNORECASE)
    for match in abbreviated_base64:
        potential_b64s.append(match.group(1))
    
    results = []
    for b64 in potential_b64s:
        try:
            if b64.endswith('...'):
                results.append(Base64Result(
                    Base64=b64,
                    Decoded="[TRUNCATED BASE64]"
                ))
                continue
                
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            
            if re.search(r'[A-Za-z0-9]{4,}', decoded) and \
               not re.match(r'^[\x00-\x1F\x7F-\xFF]+$', decoded):
                results.append(Base64Result(
                    Base64=b64,
                    Decoded=decoded
                ))
        except:
            # If UTF-8 decode fails, try UTF-16LE (common for PowerShell)
            try:
                decoded = base64.b64decode(b64).decode('utf-16le', errors='ignore')
                if re.search(r'[A-Za-z0-9]{4,}', decoded):
                    results.append(Base64Result(
                        Base64=b64,
                        Decoded=decoded
                    ))
            except:
                continue
    
    return results


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    url_pattern = r'(https?://[^\s"\'<>\)\(]+)'
    urls = [match.group() for match in re.finditer(url_pattern, text)]
    
    # Filter out common benign URLs that are not indicators of compromise
    filtered_urls = []
    
    for url in urls:
        if not any(re.match(pattern, url) for pattern in CommonPatterns.BENIGN_URL_PATTERNS):
            filtered_urls.append(url)
    
    return filtered_urls


def extract_powershell_commands(text: str) -> List[str]:
    """Extract PowerShell commands from text."""
    cmd_patterns = CommonPatterns.POWERSHELL_COMMAND_PATTERNS
    
    def is_likely_false_positive(match_text: str) -> bool:
        if (match_text.startswith('http') and
            not any(cmd in match_text.lower() for cmd in 
                   ['powershell', 'cmd', 'iex', 'iwr', 'invoke', '.ps1', '.bat', '.hta'])):
            return True
        return False
    
    results = []
    for pattern in cmd_patterns:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group()
                
                if pattern.startswith(r'[\'"`]') and pattern.endswith(r'[\'"`]'):
                    string_match = re.search(r'[\'"`](.*?)[\'"`]', matched_text)
                    if string_match:
                        matched_text = "EMBEDDED_IN_JS: " + string_match.group(1)
                
                # For const/var/let command patterns, extract just the PowerShell command
                if pattern.startswith(r'const') or pattern.startswith(r'var') or pattern.startswith(r'let'):
                    string_match = re.search(r'[\'"`](powershell.*?)[\'"`]', matched_text)
                    if string_match:
                        matched_text = "EMBEDDED_IN_JS: " + string_match.group(1)
                
                # For obfuscated variable assignments, try to extract the PowerShell command
                if '_0x' in pattern:
                    string_match = re.search(r'[\'"`](powershell.*?)[\'"`]', matched_text)
                    if string_match:
                        matched_text = "EMBEDDED_IN_OBFUSCATED_JS: " + string_match.group(1)
                
                if matched_text not in results and not is_likely_false_positive(matched_text):
                    results.append(matched_text)
        except re.error:
            continue
    
    # Also check for powershell commands in obfuscated JavaScript
    obfuscated_js_patterns = [
        r'_0x[a-f0-9]{2,6}\([\'"`]powershell[^\'"`]*[\'"`]\)',
        r'_0x[a-f0-9]{2,6}\s*=\s*[\'"`]powershell[^\'"`]*[\'"`]'
    ]
    
    for pattern in obfuscated_js_patterns:
        try:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                ps_cmd_match = re.search(r'[\'"`](powershell[^\'"`]*)[\'"`]', match.group())
                if ps_cmd_match:
                    matched_text = "EMBEDDED_IN_OBFUSCATED_JS: " + ps_cmd_match.group(1)
                    if matched_text not in results:
                        results.append(matched_text)
        except re.error:
            continue
    
    # Also check for PowerShell commands in Base64 encoded strings
    base64_strings = extract_base64_strings(text)
    for b64_obj in base64_strings:
        if hasattr(b64_obj, 'Decoded'):
            decoded_text = b64_obj.Decoded
            for pattern in cmd_patterns:
                try:
                    matches = re.finditer(pattern, decoded_text, re.IGNORECASE)
                    for match in matches:
                        matched_text = match.group()
                        if matched_text not in results and not is_likely_false_positive(matched_text):
                            results.append(matched_text)
                except re.error:
                    continue
    
    return results


def extract_ip_addresses(text: str) -> List[str]:
    """Extract IP addresses from text."""
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    return [match.group() for match in re.finditer(ip_pattern, text)]


def extract_clipboard_commands(html_content: str) -> List[str]:
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


def normalize_unicode_text(text: str) -> str:
    """Normalize Unicode characters to their ASCII equivalents for better detection."""
    unicode_map = {
        'Ⅰ': 'I', 'І': 'I', 'Ι': 'I',
        'ɑ': 'a', 'а': 'a', 'α': 'a',
        'ո': 'n', 'η': 'n',
        'օ': 'o', 'о': 'o', 'ο': 'o',
        'ɾ': 'r', 'г': 'r',
        'Ƅ': 'b', 'Ь': 'b',
        'С': 'C', 'Ϲ': 'C',
        'А': 'A', 'Α': 'A',
        'Р': 'P', 'Ρ': 'P',
        'Т': 'T',
        'Н': 'H',
        'Ⅴ': 'V', 'ν': 'v', 'Ѵ': 'V',
        'і': 'i', 'l': 'i', '1': 'i',
        'с': 'c',
        'Ⅾ': 'D',
        '✓': 'checkmark'
    }
    
    for unicode_char, ascii_char in unicode_map.items():
        text = text.replace(unicode_char, ascii_char)
    
    return text


def extract_suspicious_keywords(text: str) -> List[str]:
    """Extract suspicious keywords and patterns from text."""
    normalized_text = normalize_unicode_text(text)
    
    # Gather all suspicious patterns from CommonPatterns
    suspicious_patterns = []
    suspicious_patterns.extend(CommonPatterns.SUSPICIOUS_COMMAND_PATTERNS)
    suspicious_patterns.extend(CommonPatterns.CAPTCHA_VERIFICATION_PATTERNS)
    
    # Add all suspicious terms from CommonPatterns
    suspicious_patterns.extend([fr'\b{re.escape(term)}\b' for term in CommonPatterns.SUSPICIOUS_TERMS])
    
    results = []
    for pattern in suspicious_patterns:
        try:
            matches = re.finditer(pattern, normalized_text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group().strip()
                if matched_text and matched_text not in results:
                    results.append(matched_text)
        except re.error:
            continue
    
    return results


def extract_clipboard_manipulation(html_content: str) -> List[str]:
    """Detect JavaScript clipboard manipulation."""
    results = []
    
    clipboard_patterns = CommonPatterns.CLIPBOARD_PATTERNS
    
    for pattern in clipboard_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            context = extract_match_with_context(match, html_content)
            if context not in results:
                results.append(context)
    
    return results


def extract_powershell_downloads(html_content: str) -> List[PowerShellDownload]:
    """Extract PowerShell download and execution commands."""
    results = []
    matched_positions = set()
    
    # Use download patterns from CommonPatterns
    url_patterns = CommonPatterns.POWERSHELL_DOWNLOAD_PATTERNS
    
    # Process URL patterns first
    for pattern in url_patterns:
        for match in re.finditer(pattern, html_content, re.IGNORECASE):
            if check_match_overlap(match, matched_positions):
                continue
                
            mark_match_positions(match, matched_positions)
            url = match.group(1) if match.groups() else None
            
            download_info = PowerShellDownload(
                FullMatch=match.group(),
                URL=url,
                Context=match.group()
            )
            results.append(download_info)
    
    # If no URL patterns matched, try standalone patterns
    if not results:
        # Use standalone patterns from CommonPatterns
        standalone_patterns = CommonPatterns.POWERSHELL_STANDALONE_DOWNLOAD_PATTERNS
        
        for pattern in standalone_patterns:
            for match in re.finditer(pattern, html_content, re.IGNORECASE):
                if check_match_overlap(match, matched_positions):
                    continue
                    
                mark_match_positions(match, matched_positions)
                
                download_info = PowerShellDownload(
                    FullMatch=match.group(),
                    URL=None,
                    Context=match.group()
                )
                results.append(download_info)
    
    # Use HTA path patterns from CommonPatterns
    hta_path_patterns = CommonPatterns.HTA_PATH_PATTERNS
    
    for pattern in hta_path_patterns:
        for match in re.finditer(pattern, html_content, re.IGNORECASE):
            if check_match_overlap(match, matched_positions):
                continue
                
            mark_match_positions(match, matched_positions)
            
            download_info = PowerShellDownload(
                FullMatch=match.group(),
                URL=match.group(1),
                Context=match.group(),
                HTAPath=match.group(1)
            )
            results.append(download_info)
    
    return results


def extract_captcha_elements(html_content: str) -> List[str]:
    """Extract fake CAPTCHA related elements from HTML."""
    results = []
    
    # Use CAPTCHA patterns from CommonPatterns
    captcha_patterns = CommonPatterns.CAPTCHA_PATTERNS
    
    for pattern in captcha_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                matched_text = match.group()
                if len(matched_text) > 200:
                    matched_text = extract_match_with_context(match, html_content)
                else:
                    matched_text = re.sub(r'\s+', ' ', matched_text)
                
                if matched_text not in results:
                    results.append(matched_text)
        except re.error:
            continue
    
    return results


def extract_encoded_powershell(text: str) -> List[EncodedPowerShellResult]:
    """Extract encoded PowerShell commands and decode them."""
    results = []
    
    encoded_patterns = [
        r'powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:oded)?)?(?:command)?\s+([A-Za-z0-9+/=]+)',
        r'powershell(?:\.exe)?\s+(?:-\w+\s+)*-enc(?:oded)?(?:command)?\s+([A-Za-z0-9+/=]+)',
        r'powershell(?:\.exe)?\s+(?:-\w+\s+)*-encodedcommand\s+([A-Za-z0-9+/=]+)',
        r'(?:cmd(?:\.exe)?|command(?:\.com)?)\s+/c\s+powershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:oded)?)?(?:command)?\s+([A-Za-z0-9+/=]+)',
        r'-EncodedCommand\s+([A-Za-z0-9+/=]+)',
        r'-enc\s+([A-Za-z0-9+/=]+)',
        r'-e\s+([A-Za-z0-9+/=]+)',
        r'echo\s+([A-Za-z0-9+/=]+)\s*\|\s*powershell\s+-e(?:nc(?:oded)?)?',
        r'function\s+\w+\([^\)]*\)\s*\{\s*[^}]*-e(?:nc(?:oded)?)?(?:command)?\s+([A-Za-z0-9+/=]+)'
    ]
    
    for pattern in encoded_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
        for match in matches:
            if len(match.groups()) > 0:
                encoded_cmd = match.group(1)
                try:
                    # PowerShell encoded commands are UTF-16LE base64
                    decoded_bytes = base64.b64decode(encoded_cmd)
                    # Try to decode as UTF-16LE (PowerShell's encoding)
                    decoded_cmd = decoded_bytes.decode('utf-16le', errors='ignore')
                    
                    if len(decoded_cmd) > 5:  # Avoid tiny/invalid decodes
                        results.append(EncodedPowerShellResult(
                            EncodedCommand=encoded_cmd,
                            DecodedCommand=decoded_cmd,
                            FullMatch=match.group()
                        ))
                except:
                    # If we can't decode it properly, try standard base64
                    try:
                        alt_decoded = base64.b64decode(encoded_cmd).decode('utf-8', errors='ignore')
                        if len(alt_decoded) > 5:
                            results.append(EncodedPowerShellResult(
                                EncodedCommand=encoded_cmd,
                                DecodedCommand=f"[ALTERNATIVE DECODE] {alt_decoded}",
                                FullMatch=match.group()
                            ))
                    except:
                        pass
    
    return results


def extract_obfuscated_javascript(text: str) -> List[Dict[str, Any]]:
    """Extract obfuscated JavaScript snippets from text."""
    obfuscation_patterns = CommonPatterns.JS_OBFUSCATION_PATTERNS
    
    # Patterns that might indicate PowerShell commands in JavaScript strings
    # These should NOT be flagged as obfuscated JavaScript on their own
    powershell_in_string_patterns = [
        r'const\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+command\s*=\s*["\'\`]powershell.*?["\`]',
        r'const\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'var\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'let\s+cmd\s*=\s*["\'\`]powershell.*?["\`]',
        r'["\'\`]powershell\s+-\w+\s+hidden["\'\`]',
        r'["\'\`]\$[a-zA-Z0-9_]+\s*=\s*\[[Cc]onvert\]::[Ff]rom[Bb]ase64[Ss]tring["\'\`]',
        r'document\.write\s*\(\s*["\'\`]<script[^>]*>[^<]*powershell[^<]*</script>["\'\`]\s*\)'
    ]
    
    results = []
    
    # Find script tags in the document
    script_tags = re.finditer(r'<script[^>]*>(.*?)</script>', text, re.DOTALL)
    
    for script_tag in script_tags:
        script_content = script_tag.group(1)
        
        if not script_content.strip():
            continue
        
        if ('jquery' in script_content.lower() or 
            'bootstrap' in script_content.lower() or
            'google-analytics' in script_content.lower()):
            continue
        
        obfuscation_score = 0
        obfuscation_indicators = []
        
        for pattern in obfuscation_patterns:
            pattern_matches = list(re.finditer(pattern, script_content, re.IGNORECASE))
            if pattern_matches:
                pattern_examples = [match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0) 
                                  for match in pattern_matches[:2]]  # Get up to 2 examples
                obfuscation_indicators.append({
                    'pattern': pattern,
                    'examples': pattern_examples,
                    'count': len(pattern_matches)
                })
                obfuscation_score += len(pattern_matches)
        
        # Only consider this JavaScript as potentially obfuscated if there are significant obfuscation indicators
        if obfuscation_score > 0:
            # Now check if it's just PowerShell in a JavaScript string
            is_powershell_in_string = False
            for pattern in powershell_in_string_patterns:
                if re.search(pattern, script_content, re.IGNORECASE):
                    # Only consider it a false positive if there's just 1-2 obfuscation indicators
                    # and they're weak indicators (like long base64 strings which can be legitimate)
                    if obfuscation_score <= 2 and all('base64' in ind['pattern'] for ind in obfuscation_indicators):
                        is_powershell_in_string = True
                        break
            
            # If it's not just PowerShell in a string
            if not is_powershell_in_string:
                # Check for hex-encoded variables which are strong indicators of obfuscation
                hex_var_patterns = [
                    r'_0x[a-f0-9]{4,}',
                    r'[a-zA-Z0-9_$]+\[[\'"`]0x[a-f0-9]+[\'"`]\]'
                ]
                
                has_hex_vars = False
                for pattern in hex_var_patterns:
                    if re.search(pattern, script_content):
                        has_hex_vars = True
                        break
                
                # If we have obfuscation score > 2 or we have hex variables, consider it obfuscated
                if obfuscation_score > 2 or has_hex_vars:
                    results.append({
                        'script': script_content[:150] + '...' if len(script_content) > 150 else script_content,
                        'indicators': obfuscation_indicators,
                        'score': obfuscation_score,
                        'position': script_tag.start()
                    })
    
    # Also look for obfuscated script content outside of script tags
    # (e.g., in event handlers or javascript: URLs)
    inline_js_patterns = [
        r'on(?:click|load|mouseover|error|keyup|change|focus)=[\'"`](.*?)[\'"`]',
        r'javascript:(.*?)[\'"`]'
    ]
    
    for pattern in inline_js_patterns:
        matches = re.finditer(pattern, text)
        for match in matches:
            js_content = match.group(1)
            
            # Skip very short content
            if len(js_content) < 20:
                continue
                
            obfuscation_score = 0
            obfuscation_indicators = []
            
            # Check for obfuscation patterns
            for obf_pattern in obfuscation_patterns:
                pattern_matches = list(re.finditer(obf_pattern, js_content, re.IGNORECASE))
                if pattern_matches:
                    pattern_examples = [match.group(0)[:50] + '...' if len(match.group(0)) > 50 else match.group(0) 
                                      for match in pattern_matches[:2]]
                    obfuscation_indicators.append({
                        'pattern': obf_pattern,
                        'examples': pattern_examples,
                        'count': len(pattern_matches)
                    })
                    obfuscation_score += len(pattern_matches)
            
            # Check for hex-encoded variables which are strong indicators of obfuscation
            hex_var_patterns = [
                r'_0x[a-f0-9]{4,}',
                r'[a-zA-Z0-9_$]+\[[\'"`]0x[a-f0-9]+[\'"`]\]'
            ]
            
            has_hex_vars = False
            for hex_pattern in hex_var_patterns:
                if re.search(hex_pattern, js_content):
                    has_hex_vars = True
                    break
            
            # If it has a significant obfuscation score or hex variables, consider it obfuscated
            if obfuscation_score > 1 or has_hex_vars:
                # Check if it's just PowerShell in a string
                is_powershell_in_string = False
                for ps_pattern in powershell_in_string_patterns:
                    if re.search(ps_pattern, js_content, re.IGNORECASE):
                        if obfuscation_score <= 2 and all('base64' in ind['pattern'] for ind in obfuscation_indicators):
                            is_powershell_in_string = True
                            break
                
                if not is_powershell_in_string:
                    results.append({
                        'script': js_content[:150] + '...' if len(js_content) > 150 else js_content,
                        'indicators': obfuscation_indicators,
                        'score': obfuscation_score,
                        'position': match.start()
                    })
    
    return results


def extract_suspicious_oauth_patterns(text: str) -> List[SuspiciousCommand]:
    """Extract suspicious OAuth-related patterns based on techniques, not specific IOCs.
    
    This focuses on Microsoft OAuth phishing techniques as described by Volexity:
    https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
    """
    # Use centralized OAuth phishing patterns from CommonPatterns
    oauth_technique_patterns = CommonPatterns.OAUTH_PATTERNS
    
    # Look for these suspicious OAuth patterns in the text
    results = []
    for pattern, description in oauth_technique_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            context = extract_match_with_context(match, text)
            results.append(SuspiciousCommand(
                Command=context,
                CommandType=CommandType.SUSPICIOUS.value,
                RiskLevel=CommandRiskLevel.HIGH.value,
                Source="OAuth Phishing Detection"
            ))
    
    return results


def extract_suspicious_commands(html_content: str) -> List[SuspiciousCommand]:
    """Extract suspicious commands from HTML content."""
    results = []
    
    # Add OAuth detection
    oauth_results = extract_suspicious_oauth_patterns(html_content)
    results.extend(oauth_results)
    
    # PowerShell commands
    powershell_cmds = extract_powershell_commands(html_content)
    for cmd in powershell_cmds:
        risk_level = CommandRiskLevel.HIGH.value if any(
            indicator in cmd.lower() for indicator in CommonPatterns.DANGEROUS_PS_INDICATORS
        ) else CommandRiskLevel.MEDIUM.value
        
        results.append(SuspiciousCommand(
            Command=cmd,
            CommandType=CommandType.POWERSHELL.value,
            Source="HTML/JavaScript",
            RiskLevel=risk_level
        ))
    
    # Encoded PowerShell
    encoded_ps = extract_encoded_powershell(html_content)
    for encoded in encoded_ps:
        results.append(SuspiciousCommand(
            Command=encoded.DecodedCommand,
            CommandType=CommandType.ENCODED_POWERSHELL.value,
            Source=encoded.FullMatch[:50] + "..." if len(encoded.FullMatch) > 50 else encoded.FullMatch,
            RiskLevel=encoded.RiskLevel
        ))
    
    # Command execution in JavaScript
    js_cmd_patterns = CommonPatterns.JS_COMMAND_EXECUTION_PATTERNS
    
    for pattern in js_cmd_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            context = extract_match_with_context(match, html_content, context_length=100)
            
            results.append(SuspiciousCommand(
                Command=context,
                CommandType=CommandType.JAVASCRIPT.value,
                Source=f"Context: {match.group()}",
                RiskLevel=CommandRiskLevel.HIGH.value if "powershell" in context.lower() 
                         else CommandRiskLevel.MEDIUM.value
            ))
    
    # VBScript commands
    vbs_patterns = CommonPatterns.VBS_COMMAND_PATTERNS
    
    for pattern in vbs_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            context = match.group()
            if len(context) > 100:
                context = context[:100] + "..."
            
            results.append(SuspiciousCommand(
                Command=context,
                CommandType=CommandType.VBSCRIPT.value,
                Source="HTML/VBScript",
                RiskLevel=CommandRiskLevel.HIGH.value
            ))
    
    # Clipboard manipulation commands
    clipboard_patterns = CommonPatterns.CLIPBOARD_COMMAND_PATTERNS
    
    for pattern in clipboard_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE)
        for match in matches:
            context = extract_match_with_context(match, html_content, context_length=50)
            
            results.append(SuspiciousCommand(
                Command=context,
                CommandType=CommandType.CLIPBOARD_MANIPULATION.value,
                Source="JavaScript Clipboard Access",
                RiskLevel=CommandRiskLevel.HIGH.value
            ))
    
    return results


def determine_command_type(command: str) -> str:
    """Determine the type of suspicious command."""
    command_lower = command.lower()
    
    if 'mshta' in command_lower:
        return CommandType.MSHTA.value
    elif 'powershell' in command_lower or 'iwr' in command_lower or 'iex' in command_lower:
        return CommandType.POWERSHELL.value
    elif 'cmd' in command_lower or 'command' in command_lower:
        return CommandType.COMMAND_PROMPT.value
    elif 'rundll32' in command_lower or 'regsvr32' in command_lower:
        return CommandType.DLL_LOADING.value
    elif 'curl' in command_lower or 'wget' in command_lower or 'bitsadmin' in command_lower:
        return CommandType.FILE_DOWNLOAD.value
    elif 'certutil' in command_lower:
        return CommandType.CERTIFICATE_UTILITY.value
    elif 'cscript' in command_lower or 'wscript' in command_lower:
        return CommandType.SCRIPT_ENGINE.value
    elif 'schtasks' in command_lower or 'reg' in command_lower:
        return CommandType.SYSTEM_CONFIG.value
    elif '-encodedcommand' in command_lower or '-encodedc' in command_lower or '-enc ' in command_lower:
        return CommandType.ENCODED_POWERSHELL.value
    elif 'facedetermines.bat' in command_lower:
        return CommandType.MALICIOUS_BATCH.value
    elif any(ext in command_lower for ext in ['.mp3', '.wav', '.ogg', '.aac', '.m4a', '.pdf']) and any(term in command_lower for term in ['robot', 'captcha', 'verif', 'uid', 'id']):
        return CommandType.FAKE_MEDIA.value
    elif 'temp' in command_lower and any(ext in command_lower for ext in ['.bat', '.ps1', '.vbs', '.js', '.hta']):
        return CommandType.TEMP_SCRIPT.value
    elif 'google' in command_lower and 'check' in command_lower:
        return CommandType.FAKE_GOOGLE.value
    elif '/min' in command_lower and 'powershell' in command_lower:
        return CommandType.HIDDEN_POWERSHELL.value
    elif 'out-file' in command_lower or 'outfile' in command_lower:
        return CommandType.FILE_WRITE.value
    elif 'bypass' in command_lower and 'executionpolicy' in command_lower:
        return CommandType.EXECUTION_POLICY_BYPASS.value
    elif re.search(r'https?://[^\s"\'<>\)\(]+\.[a-z0-9]+(?:\?[^\s]+)?(?:\s+#|\s*#)', command_lower):
        return CommandType.URL_WITH_COMMENT.value
    else:
        return CommandType.SUSPICIOUS.value


def extract_bot_detection(html_content: str) -> List[str]:
    """Extract bot detection and sandbox evasion techniques."""
    # Use new helper function with patterns from CommonPatterns
    patterns = CommonPatterns.BOT_DETECTION_PATTERNS
    
    matches = extract_patterns_with_context(html_content, patterns, context_length=100)
    
    # Extract just the context for the results
    results = [match["context"] for match in matches]
    
    return results


def extract_session_hijacking(html_content: str) -> List[str]:
    """Extract session hijacking and cookie theft techniques."""
    # Use new helper function with patterns from CommonPatterns
    patterns = CommonPatterns.SESSION_HIJACKING_PATTERNS
    
    matches = extract_patterns_with_context(html_content, patterns, context_length=75)
    
    # Extract just the context for the results
    results = [match["context"] for match in matches]
    
    # Check for token extraction from URLs (common in OAuth phishing)
    url_token_patterns = [
        r'new\s+URLSearchParams\((?:window\.)?location\.(?:search|hash)\)',
        r'location\.(?:search|hash)\.split',
        r'(?:get|extract)(?:AccessToken|IdToken|RefreshToken|Code)',
        r'url\.searchParams\.get\(["\'](?:code|token|access_token|id_token)["\']',
        r'RegExp\(["\'](?:code|token|access_token|id_token)=["\']'
    ]
    
    url_matches = extract_patterns_with_context(html_content, url_token_patterns, context_length=100)
    results.extend([f"URL Token Extraction: {match['context']}" for match in url_matches])
    
    return results


def extract_proxy_evasion(html_content: str) -> List[str]:
    """Detect techniques to evade web proxies or security tools.
    
    Args:
        html_content: HTML content to analyze
        
    Returns:
        List[str]: Detected proxy and security tool evasion techniques
    """
    results = []
    
    # Use patterns from CommonPatterns
    proxy_patterns = CommonPatterns.PROXY_EVASION_PATTERNS
    
    for pattern in proxy_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                context = extract_match_with_context(match, html_content)
                if context not in results:
                    results.append(context)
        except re.error:
            continue
    
    # Check for conditional redirects based on browser fingerprinting
    conditional_patterns = [
        r'if\s*\([^)]*(?:navigator|window|document|screen)[^)]*\)\s*{\s*(?:location|fetch)',
        r'else\s*{\s*window\.location\.(?:href|replace)',
        r'if\s*\(.*?userAgent.*?\)\s*{[^}]*(?:window\.location|fetch|document\.write)',
        r'switch\s*\([^)]*navigator[^)]*\)\s*{',
        r'return\s+navigator\s*\.\s*userAgent\s*\.\s*indexOf'
    ]
    
    for pattern in conditional_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                context = extract_match_with_context(match, html_content, context_length=100)
                results.append(f"Conditional redirection based on browser fingerprinting: {context}")
        except re.error:
            continue
    
    # Check for JavaScript errors that could crash analysis tools
    error_patterns = [
        r'throw\s+new\s+Error',
        r'console\.(?:error|exception)',
        r'debugger;',
        r'\[.*?\]\[.*?\]\[.*?\]\[.*?\]',  # Excessive array indexing (common in obfuscation)
        r'\(function\s*\(\s*\)\s*{\s*try\s*{[^}]*}\s*catch'
    ]
    
    for pattern in error_patterns:
        try:
            matches = re.finditer(pattern, html_content, re.IGNORECASE)
            for match in matches:
                context = extract_match_with_context(match, html_content)
                results.append(f"Potential analysis tool error trigger: {context}")
        except re.error:
            continue
    
    return results


def extract_patterns_with_context(
    content: str, 
    patterns: List[Union[str, Tuple[str, str]]], 
    flags: int = re.IGNORECASE,
    context_length: int = 50,
    deduplicate: bool = True
) -> List[Dict[str, Any]]:
    """Generic pattern extraction helper to reduce code duplication.
    
    Args:
        content: Text content to search
        patterns: List of patterns or (pattern, label) tuples
        flags: Regex flags to use
        context_length: Context length to extract around matches
        deduplicate: Whether to remove duplicate matches
        
    Returns:
        List of dictionaries with match information
    """
    results = []
    matched_positions = set() if deduplicate else None
    
    for pattern_item in patterns:
        # Handle both pattern strings and (pattern, label) tuples
        if isinstance(pattern_item, tuple):
            pattern, label = pattern_item
        else:
            pattern, label = pattern_item, None
            
        try:
            matches = re.finditer(pattern, content, flags)
            for match in matches:
                # Skip overlapping matches if deduplication is enabled
                if deduplicate and check_match_overlap(match, matched_positions):
                    continue
                    
                if deduplicate:
                    mark_match_positions(match, matched_positions)
                
                context = extract_match_with_context(match, content, context_length)
                result = {
                    "match": match.group(),
                    "context": context,
                    "start": match.start(),
                    "end": match.end(),
                    "groups": match.groups()
                }
                
                if label:
                    result["label"] = label
                    
                results.append(result)
        except re.error:
            continue
            
    return results 


def extract_js_redirects(content: str) -> List[str]:
    """Extract suspicious JavaScript redirects.
    
    Detects obfuscated JavaScript redirects, parking pages with encoded parameters,
    and suspicious script loaders often used for malicious activity.
    
    Args:
        content: The HTML content to analyze
        
    Returns:
        List of detected JavaScript redirect patterns
    """
    results = []
    matched_positions = set()
    
    # Check for suspicious script tags loading external files
    script_tag_patterns = [
        r'<script\s+src\s*=\s*["\'](/[a-zA-Z0-9]+\.[a-zA-Z0-9]+)["\'](?:\s+(?!src)[a-zA-Z0-9\-_]+(?:\s*=\s*["\'][^"\']*["\'])?)*\s*></script>',
        r'<script\s+src\s*=\s*["\'](https?://[^"\']*)["\'](?:\s+(?!src)[a-zA-Z0-9\-_]+(?:\s*=\s*["\'][^"\']*["\'])?)*\s*></script>'
    ]
    
    for pattern in script_tag_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            if check_match_overlap(match, matched_positions):
                continue
            
            mark_match_positions(match, matched_positions)
            script_src = match.group(1)
            
            # Look for suspicious script names or random-looking filenames
            if re.search(r'/[a-zA-Z0-9]{8,}\.[a-zA-Z0-9]{1,4}$', script_src) or \
               re.search(r'[A-Z][a-z][A-Z][a-z][A-Z][a-z]', script_src) or \
               re.search(r'[0-9][A-Z][0-9][a-z][0-9]', script_src):
                results.append(f"Suspicious external script: {match.group(0)}")
    
    # Check for encoded data in window variables
    encoded_data_patterns = [
        r'window\.park\s*=\s*["\']((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']',
        r'window\.[a-zA-Z0-9_]+\s*=\s*["\']((?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4}))["\']'
    ]
    
    for pattern in encoded_data_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            if check_match_overlap(match, matched_positions):
                continue
            
            mark_match_positions(match, matched_positions)
            results.append(f"Encoded data in window variable: {match.group(0)}")
    
    # Check for generic redirect patterns from CommonPatterns
    for pattern in CommonPatterns.SUSPICIOUS_JS_REDIRECT_PATTERNS:
        try:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if check_match_overlap(match, matched_positions):
                    continue
                
                mark_match_positions(match, matched_positions)
                context = extract_match_with_context(match, content)
                results.append(f"Suspicious JavaScript redirect pattern: {context}")
        except re.error:
            continue
    
    # Check for timeout/interval redirects
    timeout_patterns = [
        r'setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*(?:window\.)?location(?:\.href)?\s*=',
        r'setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*(?:window\.)?location\.replace\s*\(',
        r'setInterval\s*\(\s*function\s*\(\s*\)\s*{\s*(?:window\.)?location'
    ]
    
    for pattern in timeout_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            if check_match_overlap(match, matched_positions):
                continue
            
            mark_match_positions(match, matched_positions)
            context = extract_match_with_context(match, content, context_length=100)
            results.append(f"Delayed JavaScript redirect: {context}")
    
    # Check for dynamic script creation
    dynamic_script_patterns = [
        r'document\.createElement\s*\(\s*[\'"]script[\'"]\s*\)[^;]*\.src\s*=',
        r'var\s+[a-zA-Z0-9_$]+\s*=\s*document\.createElement\s*\(\s*[\'"]script[\'"]\s*\)',
        r'const\s+[a-zA-Z0-9_$]+\s*=\s*document\.createElement\s*\(\s*[\'"]script[\'"]\s*\)',
        r'let\s+[a-zA-Z0-9_$]+\s*=\s*document\.createElement\s*\(\s*[\'"]script[\'"]\s*\)'
    ]
    
    for pattern in dynamic_script_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
            if check_match_overlap(match, matched_positions):
                continue
            
            mark_match_positions(match, matched_positions)
            context = extract_match_with_context(match, content, context_length=100)
            results.append(f"Dynamic script creation: {context}")
    
    # Check for obfuscated function call chaining (typical in malicious loaders)
    obfuscated_chain_patterns = [
        r'\[\s*[\'"`][^\s\'"`]+[\'"`]\s*\]\s*\[\s*[\'"`][^\s\'"`]+[\'"`]\s*\]\s*\(',
        r'\[[\'"`][^\s\'"`]+[\'"`]\]\[[\'"`][^\s\'"`]+[\'"`]\]\([[\'"`][^\s\'"`]+[\'"`]\]',
        r'(?:\[[\'"`][^\s\'"`]+[\'"`]\]){3,}'
    ]
    
    for pattern in obfuscated_chain_patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            if check_match_overlap(match, matched_positions):
                continue
            
            mark_match_positions(match, matched_positions)
            context = extract_match_with_context(match, content)
            results.append(f"Obfuscated function call chain: {context}")
    
    return results 


def extract_parking_page_loaders(content: str) -> List[str]:
    """Extract parking page loader patterns.
    
    Detects parking page loaders with window.park Base64-encoded data and other
    related patterns often used in parking/redirect pages.
    
    Args:
        content: The HTML content to analyze
        
    Returns:
        List of detected parking page loader patterns
    """
    results = []
    
    # Use the PARKING_PAGE_PATTERNS from CommonPatterns
    for pattern in CommonPatterns.PARKING_PAGE_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            context = extract_match_with_context(match, content, context_length=100)
            
            # If window.park pattern, try to decode the Base64 to enrich the detection
            if "window.park" in match.group(0):
                try:
                    # Extract the Base64 string
                    base64_data = match.group(1)
                    decoded_data = base64.b64decode(base64_data).decode('utf-8')
                    # Add the decoded data to provide context
                    results.append(f"Parking page loader - window.park Base64: {match.group(0)}\nDecoded: {decoded_data}")
                except:
                    # If decoding fails, just add the original match
                    results.append(f"Parking page loader - window.park: {match.group(0)}")
            else:
                # For other patterns, just add with appropriate label
                if "data-adblockkey" in match.group(0):
                    results.append(f"Parking page loader - adblock detection: {context}")
                elif "opacity: 0" in match.group(0):
                    results.append(f"Parking page loader - hidden content: {context}")
                elif ".js" in match.group(0):
                    results.append(f"Parking page loader - external script: {context}")
                else:
                    results.append(f"Parking page loader: {context}")
    
    # Additional checks for other parking page indicators
    
    # Check for fake icons
    icon_pattern = r'<link\s+rel\s*=\s*["\'](?:icon|shortcut icon)["\'][^>]*href\s*=\s*["\']data:image/[^"\']+["\']'
    for match in re.finditer(icon_pattern, content, re.IGNORECASE):
        results.append(f"Parking page loader - fake icon: {match.group(0)}")
    
    # Check for suspicious Google preconnect (commonly used in parking pages)
    preconnect_pattern = r'<link\s+rel\s*=\s*["\']preconnect["\'][^>]*href\s*=\s*["\']https://www\.google\.com["\'][^>]*crossorigin'
    for match in re.finditer(preconnect_pattern, content, re.IGNORECASE):
        results.append(f"Parking page loader - Google preconnect: {match.group(0)}")
    
    return results