import json
import os
import collections
import re
import sys
from urllib.parse import urlparse
from datetime import datetime

if len(sys.argv) > 1:
    report_date = sys.argv[1]
else:
    report_date = datetime.now().strftime("%Y-%m-%d")

report_file = f"nightly_reports/clickgrab_report_{report_date}.json"

analysis_dir = "analysis"
if not os.path.exists(analysis_dir):
    os.makedirs(analysis_dir)

output_file = f"{analysis_dir}/report_{report_date}.md"

print(f"Analyzing report file: {report_file}")

with open(output_file, "w") as output:
    output.write(f"# ClickGrab Threat Analysis Report - {report_date}\n\n")
    
    try:
        with open(report_file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        output.write(f"Error: Report file not found: {report_file}\n")
        print(f"Error: Report file not found: {report_file}")
        sys.exit(1)

    all_urls = []
    site_url_sets = []
    ps_download_contexts = []
    clipboard_manipulation = []
    powershell_commands = []
    suspicious_keywords = []
    malicious_sites_with_data = []
    html_content = []
    full_js_snippets = []
    captcha_html_examples = []

    for site_index, site in enumerate(data.get("Sites", [])):
        urls = site.get("Urls", [])
        
        site_urls = set()
        if urls is None:
            continue
        elif isinstance(urls, str):
            all_urls.append(urls)
            site_urls.add(urls)
        elif isinstance(urls, list):
            all_urls.extend(urls)
            site_urls.update(urls)
        
        if site_urls:
            site_url_sets.append(site_urls)
        
        has_malicious_data = False
        
        if "PowerShellDownloads" in site:
            ps_downloads = site.get("PowerShellDownloads", [])
            if ps_downloads:
                has_malicious_data = True
                if isinstance(ps_downloads, list):
                    for download in ps_downloads:
                        if isinstance(download, dict) and "Context" in download:
                            ps_download_contexts.append(download["Context"])
                elif isinstance(ps_downloads, dict) and "Context" in ps_downloads:
                    ps_download_contexts.append(ps_downloads["Context"])
        
        if "ClipboardManipulation" in site:
            clips = site.get("ClipboardManipulation", [])
            if clips and isinstance(clips, list):
                has_malicious_data = True
                clipboard_manipulation.extend(clips)
                
                for clip in clips:
                    function_matches = re.findall(r'(function\s+\w+\s*\([^)]*\)\s*\{(?:[^{}]|(?:\{(?:[^{}]|(?:\{[^{}]*\}))*\}))*\})', clip, re.DOTALL)
                    if function_matches:
                        for func in function_matches:
                            if len(func) > 30 and ("copy" in func or "clipboard" in func or "textarea" in func):
                                full_js_snippets.append(func.strip())
        
        if "HTML" in site:
            html = site.get("HTML", "")
            if html and len(html) > 0:
                html_content.append(html)
        
        if "PowerShellCommands" in site:
            ps_cmds = site.get("PowerShellCommands")
            if ps_cmds:
                has_malicious_data = True
                if isinstance(ps_cmds, list):
                    powershell_commands.extend(ps_cmds)
                else:
                    powershell_commands.append(ps_cmds)
        
        if "SuspiciousKeywords" in site:
            keywords = site.get("SuspiciousKeywords")
            if keywords and isinstance(keywords, list):
                suspicious_keywords.extend(keywords)
        
        if has_malicious_data:
            malicious_sites_with_data.append(site)

    domains = []
    for url in all_urls:
        try:
            domain = urlparse(url).netloc
            domains.append(domain)
        except:
            pass

    domain_counts = collections.Counter(domains)

    output.write("## Most Common External Domains\n\n")
    for domain, count in domain_counts.most_common(10):
        output.write(f"- **{domain}**: {count} occurrences\n")
    output.write("\n## Common Pattern Analysis\n\n")
    patterns = {
        "reCAPTCHA imagery": collections.Counter([url for url in all_urls if "recaptcha" in url.lower() or "captcha" in url.lower()]),
        "Font resources": collections.Counter([url for url in all_urls if "font" in url.lower() or ".woff" in url.lower()]),
        "CDN hosted scripts": collections.Counter([url for url in all_urls if "cdn" in url.lower() or "jsdelivr" in url.lower()]),
        "Google resources": collections.Counter([url for url in all_urls if "google" in url.lower()]),
    }

    for pattern_name, url_counter in patterns.items():
        if url_counter:
            total_urls = sum(url_counter.values())
            unique_urls = len(url_counter)
            output.write(f"\n### {pattern_name} ({total_urls} occurrences, {unique_urls} distinct URLs)\n\n")
            for url, count in url_counter.most_common(5):  # Show top 5 by frequency
                output.write(f"- {url} ({count} times)\n")
            if len(url_counter) > 5:
                output.write(f"- ...and {len(url_counter) - 5} more distinct URLs\n")

    output.write("\n## JavaScript Clipboard Analysis\n\n")

    if clipboard_manipulation:
        output.write(f"Found clipboard manipulation code snippets in {len(clipboard_manipulation)} places\n\n")
        
        unique_js_functions = list(set(full_js_snippets))
        
        if unique_js_functions:
            output.write("### Complete Clipboard Functions\n\n")
            output.write("Here are examples of the complete clipboard manipulation functions found:\n\n")
            
            for i, func in enumerate(unique_js_functions[:3]):
                output.write(f"**Function Example {i+1}:**\n")
                output.write("```javascript\n" + func + "\n```\n\n")
        
        clipboard_patterns = {
            "document.execCommand copy": r'document\.execCommand\s*\(\s*[\'"]copy[\'"]',
            "textarea manipulation": r'document\.createElement\s*\(\s*[\'"]textarea[\'"]|textarea\.select\(\)|select\(\)|document\.body\.append\s*\(\s*tempTextArea',
        }
        
        for pattern_name, regex in clipboard_patterns.items():
            matches = 0
            matching_snippets = []
            
            for code_snippet in clipboard_manipulation:
                if re.search(regex, code_snippet, re.IGNORECASE | re.DOTALL):
                    matches += 1
                    relevant_part = re.search(r'([^\n;]{0,50}' + regex + r'[^\n;]{0,100})', code_snippet, re.IGNORECASE | re.DOTALL)
                    if relevant_part and len(relevant_part.group(0)) > 20:
                        matching_snippets.append(relevant_part.group(0).strip())
            
            if matches > 0:
                percentage = (matches / len(clipboard_manipulation)) * 100
                output.write(f"\n### {pattern_name}\n\n")
                output.write(f"Found in {matches} snippets ({percentage:.1f}% of clipboard code)\n\n")
                
                if matching_snippets:
                    output.write("**Examples:**\n\n")
                    for i, snippet in enumerate(list(set(matching_snippets))[:3]):
                        output.write(f"```javascript\n{snippet}\n```\n\n")

    if html_content:
        for html in html_content:
            if "captcha" in html.lower() or "robot" in html.lower():
                captcha_section = re.search(r'(<div[^>]*class\s*=\s*[\'"][^\'"]*captcha[^\'"]*[\'"][^>]*>.*?</div>|<div[^>]*id\s*=\s*[\'"][^\'"]*captcha[^\'"]*[\'"][^>]*>.*?</div>)', html, re.IGNORECASE | re.DOTALL)
                if captcha_section:
                    section = captcha_section.group(0)
                    if len(section) > 50 and len(section) < 1000:
                        captcha_html_examples.append(section)
        
        if captcha_html_examples:
            output.write("\n## Fake CAPTCHA HTML Examples\n\n")
            output.write("Here's how the fake CAPTCHA verification appears in HTML:\n\n")
            
            for i, html_example in enumerate(captcha_html_examples[:2]):
                output.write(f"**Example {i+1}:**\n")
                output.write("```html\n" + html_example + "\n```\n\n")

    output.write("\n## Command Context Analysis\n\n")

    if ps_download_contexts:
        output.write(f"Found {len(ps_download_contexts)} PowerShell download context snippets\n\n")
        
        stage_clipboard_refs = [
            context for context in ps_download_contexts 
            if "stageClipboard" in context
        ]
        
        if stage_clipboard_refs:
            output.write(f"### stageClipboard Function\n\n")
            output.write(f"Found {len(stage_clipboard_refs)} references to stageClipboard function\n\n")
            
            complete_stage_func = None
            for context in stage_clipboard_refs:
                func_match = re.search(r'(function\s+stageClipboard\s*\([^)]*\)\s*\{[^}]*\})', context, re.DOTALL)
                if func_match:
                    complete_stage_func = func_match.group(1)
                    break
            
            if complete_stage_func:
                output.write("**Complete stageClipboard Function:**\n```javascript\n")
                output.write(complete_stage_func + "\n```\n\n")
            
            output.write("**Example stageClipboard contexts:**\n\n")
            for i, context in enumerate(stage_clipboard_refs[:3]):
                cleaned = re.sub(r'\s+', ' ', context)
                if len(cleaned) > 200:
                    cleaned = cleaned[:200] + "..."
                
                output.write(f"**Example {i+1}**:\n```javascript\n{cleaned}\n```\n\n")
        
        command_run_pattern = r'const\s+commandToRun\s*=\s*[\'"](.*?)[\'"]|var\s+commandToRun\s*=\s*[\'"](.*?)[\'"]|commandToRun\s*=\s*[\'"](.*?)[\'"]|commandToRun\s*=\s*`(.*?)`'
        
        command_run_contexts = []
        for context in ps_download_contexts:
            matches = re.findall(command_run_pattern, context, re.IGNORECASE | re.DOTALL)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        cmd = ''.join([part for part in match if part])
                        if cmd:
                            surrounding = re.search(r'(.{0,100}' + re.escape(cmd) + r'.{0,100})', context, re.DOTALL)
                            if surrounding:
                                context_snippet = surrounding.group(1)
                            else:
                                context_snippet = context[:200] if len(context) > 200 else context
                            
                            command_run_contexts.append((cmd, context_snippet))
        
        if command_run_contexts:
            output.write(f"### Malicious Commands\n\n")
            output.write(f"Found {len(command_run_contexts)} commandToRun declarations\n\n")
            output.write("Malicious commands being prepared for clipboard:\n\n")
            for i, (cmd, context) in enumerate(command_run_contexts[:5]):
                output.write(f"**Example {i+1}**:\n\n")
                output.write(f"Command:\n```powershell\n{cmd}\n```\n\n")
                output.write(f"Context:\n```javascript\n{context}\n```\n\n")
        
        hta_path_pattern = r'(const|var)\s+htaPath\s*=\s*[\'"](.*?)[\'"]'
        
        hta_path_contexts = []
        for context in ps_download_contexts:
            matches = re.findall(hta_path_pattern, context, re.IGNORECASE | re.DOTALL)
            if matches:
                for match in matches:
                    if match and len(match) >= 2:
                        decl = match[0] + " htaPath = \"" + match[1] + "\""
                        surrounding = re.search(r'(.{0,100}' + re.escape(decl) + r'.{0,100})', context, re.DOTALL)
                        if surrounding:
                            context_snippet = surrounding.group(1)
                        else:
                            context_snippet = context[:200] if len(context) > 200 else context
                        
                        hta_path_contexts.append((match[1], context_snippet))
        
        if hta_path_contexts:
            output.write(f"### PowerShell Parameters\n\n")
            output.write(f"Found {len(hta_path_contexts)} htaPath declarations\n\n")
            output.write("Malicious PowerShell parameters:\n\n")
            for i, (path, context) in enumerate(hta_path_contexts[:5]):
                output.write(f"**Example {i+1}**:\n\n")
                output.write(f"Parameters:\n```powershell\n{path}\n```\n\n")
                output.write(f"Context:\n```javascript\n{context}\n```\n\n")

    output.write("\n## Clipboard Attack Pattern Analysis\n\n")

    if stage_clipboard_refs and command_run_contexts and suspicious_keywords:
        output.write("Based on the data analyzed, here's the complete clipboard attack pattern:\n\n")
        
        output.write("### 1. Initial Victim Engagement\n\n")
        output.write("Victim is shown a fake CAPTCHA verification UI with Google reCAPTCHA branding\n\n")
        output.write("Common elements found:\n")
        output.write("- Google reCAPTCHA logo image\n")
        output.write("- Font resources from CDNs\n")
        output.write("- \"I am not a robot\" checkbox\n")
        
        if captcha_html_examples:
            output.write("\n**Example Fake CAPTCHA HTML:**\n```html\n")
            output.write(captcha_html_examples[0][:500] + "...\n")
            output.write("```\n\n")
        
        output.write("\n### 2. Malicious Code Preparation\n\n")
        output.write("When user clicks the verification checkbox:\n\n")
        output.write("- A 'commandToRun' variable is set with a malicious PowerShell command\n")
        output.write("- The command is typically obfuscated and often downloads second-stage payloads\n")
        output.write("- Common download destinations include:\n\n")
        
        download_urls = set()
        for cmd, _ in command_run_contexts:
            if "powershell" in cmd.lower():
                urls = re.findall(r'https?://[^\s\'"`]+\.ps1', cmd)
                download_urls.update(urls)
        
        for url in list(download_urls)[:5]:
            output.write(f"  * `{url}`\n")
        
        if command_run_contexts:
            output.write("\n**Example Command Preparation Code:**\n```javascript\n")
            best_example = next((context for _, context in command_run_contexts if "htaPath" in context and len(context) > 50), "")
            if best_example:
                output.write(best_example)
            else:
                output.write(command_run_contexts[0][1])
            output.write("\n```\n\n")
        
        output.write("\n### 3. Clipboard Hijacking\n\n")
        output.write("The malicious command is copied to the user's clipboard:\n\n")
        output.write("- A temporary textarea element is created\n")
        output.write("- The command is combined with verification text like \"[CHECKMARK] I am not a robot\"\n")
        output.write("- document.execCommand(\"copy\") is used to copy to clipboard\n")
        output.write("- The temporary element is removed from the DOM\n")
        
        if full_js_snippets:
            output.write("\n**Example Clipboard Hijacking Code:**\n```javascript\n")
            clipboard_example = next((snippet for snippet in full_js_snippets 
                                    if "clipboard" in snippet.lower() or "execCommand" in snippet), full_js_snippets[0])
            output.write(clipboard_example)
            output.write("\n```\n\n")
        
        output.write("\n### 4. Social Engineering Component\n\n")
        output.write("User sees a success message:\n\n")
        output.write("- The verification UI shows success with a checkmark symbol\n")
        output.write("- User is told they've passed verification\n")
        output.write("- The clipboard now contains the malicious command + verification text\n")
        
        output.write("\n### 5. Attack Objective\n\n")
        output.write("Final stage of the attack:\n\n")
        output.write("- When user pastes the clipboard contents elsewhere (like in terminal)\n")
        output.write("- They see what looks like verification text\n")
        output.write("- But the PowerShell command at the start gets executed\n")
        output.write("- This downloads and runs additional malware from attacker-controlled servers\n")
        
        output.write("\n### Reconstructed Attack Example\n\n")
        
        example_cmd = next((cmd for cmd, _ in command_run_contexts if "powershell" in cmd.lower()), "powershell -w hidden ...")
        
        verification_text = next((kw for kw in suspicious_keywords if "robot" in kw.lower()), "I am not a robot")
        
        output.write("What's copied to clipboard:\n```\n")
        output.write(f"{example_cmd} # [CHECKMARK] '{verification_text} - reCAPTCHA Verification Hash: XY12Z345'\n")
        output.write("```\n\n")
        output.write("What user sees when pasting: A verification success message\n\n")
        output.write("What actually happens: PowerShell executes the hidden malicious command\n\n")
        
        output.write("\n## Conclusion\n\n")
        output.write("This is a sophisticated social engineering attack that tricks users into:\n\n")
        output.write("1. Thinking they're completing a legitimate CAPTCHA\n")
        output.write("2. Unknowingly copying malicious code to their clipboard\n")
        output.write("3. Executing malware when they paste what they think is just verification text\n")
        
        output.write("\n## Statistics\n\n")
        output.write(f"- **Total sites analyzed**: {len(data.get('Sites', []))}\n")
        output.write(f"- **Sites with malicious content**: {len(malicious_sites_with_data)}\n")
        output.write(f"- **Total unique domains**: {len(domain_counts)}\n")
        output.write(f"- **Total URLs extracted**: {len(all_urls)}\n")
    else:
        output.write("Insufficient data to reconstruct the complete clipboard attack pattern\n")

latest_file = f"{analysis_dir}/latest.md"
try:
    if os.path.exists(latest_file):
        os.remove(latest_file)
    
    try:
        os.symlink(os.path.basename(output_file), latest_file)
    except (OSError, AttributeError):
        import shutil
        shutil.copy2(output_file, latest_file)
        
    print(f"Created latest report link at {latest_file}")
except Exception as e:
    print(f"Warning: Could not create latest report link: {e}")

print(f"Analysis complete! Results saved to {output_file}")