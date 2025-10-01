import base64
import logging
import re
from typing import List, Optional, Set
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from models import JavaScriptRedirectChain
import extractors

logger = logging.getLogger("clickgrab.redirects")

JS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
}

_MAX_SCRIPTS_TO_FETCH = 8
_MAX_SNIPPET_LEN = 240

_LOCATION_ASSIGNMENT = re.compile(
    r"(?P<label>(?:window|document)\s*\.\s*)?location(?:\.href|\.replace)?\s*=\s*(?P<expr>[^;]+)",
    re.IGNORECASE,
)
_SRC_ASSIGNMENT = re.compile(
    r"\.src\s*=\s*(?P<expr>[^;]+)",
    re.IGNORECASE,
)
_BASE64_PATTERN = re.compile(r"(?P<b64>[A-Za-z0-9+/]{16,}={0,2})")
_HTTP_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def _safe_decode(value: str) -> Optional[str]:
    cleaned = value.strip().replace("\\n", "")
    pad = len(cleaned) % 4
    if pad:
        cleaned += "=" * (4 - pad)
    try:
        decoded = base64.b64decode(cleaned)
        text = decoded.decode("utf-8", errors="ignore")
        return text
    except Exception:
        return None


def _extract_url_from_expression(expr: str) -> Optional[str]:
    direct = _HTTP_PATTERN.search(expr)
    if direct:
        return direct.group(0)

    for match in _BASE64_PATTERN.finditer(expr):
        decoded = _safe_decode(match.group("b64"))
        if decoded and "http" in decoded:
            url_match = _HTTP_PATTERN.search(decoded)
            if url_match:
                return url_match.group(0)

    return None


def _collect_from_script(script_url: str, script_text: str) -> List[JavaScriptRedirectChain]:
    findings: List[JavaScriptRedirectChain] = []
    seen_urls: Set[str] = set()

    for pattern, redirect_type in (
        (_SRC_ASSIGNMENT, "script_src"),
        (_LOCATION_ASSIGNMENT, "location_assignment"),
    ):
        for match in pattern.finditer(script_text):
            expr = match.group("expr")
            candidate = _extract_url_from_expression(expr)
            if not candidate:
                continue
            evidence = script_text[max(0, match.start() - 80): match.end() + 80]
            cleaned_evidence = evidence.strip()
            if len(cleaned_evidence) > _MAX_SNIPPET_LEN:
                cleaned_evidence = cleaned_evidence[:_MAX_SNIPPET_LEN] + "…"
            if candidate in seen_urls:
                continue
            seen_urls.add(candidate)
            findings.append(
                JavaScriptRedirectChain(
                    ScriptURL=script_url,
                    RedirectType=redirect_type,
                    DestinationURL=candidate,
                    Evidence=cleaned_evidence,
                )
            )

    if not findings:
        base64_hits = extractors.extract_base64_strings(script_text)
        for hit in base64_hits:
            decoded = hit.Decoded
            if "http" not in decoded:
                continue
            candidate_match = _HTTP_PATTERN.search(decoded)
            if not candidate_match:
                continue
            candidate = candidate_match.group(0)
            if candidate in seen_urls:
                continue
            evidence = decoded[:_MAX_SNIPPET_LEN]
            seen_urls.add(candidate)
            findings.append(
                JavaScriptRedirectChain(
                    ScriptURL=script_url,
                    RedirectType="base64_payload",
                    DestinationURL=candidate,
                    Evidence=evidence,
                )
            )

    return findings


def collect_js_redirects(base_url: str, html_content: str, max_scripts: int = _MAX_SCRIPTS_TO_FETCH) -> List[JavaScriptRedirectChain]:
    soup = BeautifulSoup(html_content, "html.parser")
    script_urls: List[str] = []

    for script_tag in soup.find_all("script"):
        src = script_tag.get("src")
        if not src:
            continue
        normalized = src.strip()
        if not normalized.lower().endswith(".js"):
            continue
        script_url = urljoin(base_url, normalized)
        if script_url not in script_urls:
            script_urls.append(script_url)
        if len(script_urls) >= max_scripts:
            break

    if not script_urls:
        return []

    findings: List[JavaScriptRedirectChain] = []
    seen_scripts: Set[str] = set()

    logger.debug("Scanning %d external script(s) referenced from %s", len(script_urls), base_url)

    with requests.Session() as session:
        session.headers.update(JS_HEADERS)
        session.verify = False
        for script_url in script_urls:
            if script_url in seen_scripts:
                continue
            seen_scripts.add(script_url)
            try:
                resp = session.get(script_url, timeout=10, allow_redirects=True)
                resp.raise_for_status()
                script_text = resp.text
                logger.debug("Fetched script %s (size=%d)", script_url, len(script_text))
            except requests.RequestException as exc:
                logger.debug("Failed fetching script %s: %s", script_url, exc)
                continue

            script_findings = _collect_from_script(script_url, script_text)
            if script_findings:
                logger.info("Detected %d redirect indicators in %s", len(script_findings), script_url)
                findings.extend(script_findings)

    return findings
