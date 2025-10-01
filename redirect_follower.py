import base64
import logging
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Set
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

import extractors
from models import RedirectFollow

logger = logging.getLogger("clickgrab.redirects")

JS_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
}

_MAX_EXTERNAL_SCRIPTS = 8
_MAX_INLINE_SCRIPTS = 12
_MAX_FOLLOWED_URLS = 10
_FOLLOW_TIMEOUT = 6
_MAX_SNIPPET_LEN = 240
_MAX_FETCH_SNIPPET = 2000

_LOCATION_ASSIGNMENT = re.compile(
    r"(?P<label>(?:window|document|self|top)\s*\.\s*)?location(?:\.href|\.replace)?\s*=\s*(?P<expr>[^;]+)",
    re.IGNORECASE,
)
_SRC_ASSIGNMENT = re.compile(
    r"\.src\s*=\s*(?P<expr>[^;]+)",
    re.IGNORECASE,
)
_BASE64_PATTERN = re.compile(r"(?P<b64>[A-Za-z0-9+/]{16,}={0,2})")
_HTTP_PATTERN = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_META_REFRESH = re.compile(r"url\s*=\s*(?P<url>[^;]+)", re.IGNORECASE)


@dataclass(frozen=True)
class _Candidate:
    original_url: str
    source: str
    method: str
    script_url: Optional[str]
    evidence: str


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
        if decoded and "http" in decoded.lower():
            url_match = _HTTP_PATTERN.search(decoded)
            if url_match:
                return url_match.group(0)

    return None


def _truncate_evidence(snippet: str) -> str:
    trimmed = snippet.strip()
    if len(trimmed) > _MAX_SNIPPET_LEN:
        return trimmed[:_MAX_SNIPPET_LEN] + "…"
    return trimmed


def _collect_from_script(script_url: Optional[str], script_text: str, source_label: str) -> List[_Candidate]:
    findings: List[_Candidate] = []
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
            evidence = _truncate_evidence(script_text[max(0, match.start() - 80): match.end() + 80])
            if candidate in seen_urls:
                continue
            seen_urls.add(candidate)
            findings.append(
                _Candidate(
                    original_url=candidate,
                    source=source_label,
                    method=redirect_type,
                    script_url=script_url,
                    evidence=evidence,
                )
            )

    if not findings:
        base64_hits = extractors.extract_base64_strings(script_text)
        for hit in base64_hits:
            decoded = hit.Decoded
            if "http" not in decoded.lower():
                continue
            url_match = _HTTP_PATTERN.search(decoded)
            if not url_match:
                continue
            candidate = url_match.group(0)
            if candidate in seen_urls:
                continue
            seen_urls.add(candidate)
            findings.append(
                _Candidate(
                    original_url=candidate,
                    source=source_label,
                    method="base64_payload",
                    script_url=script_url,
                    evidence=_truncate_evidence(decoded),
                )
            )

    return findings


def _collect_meta_refresh(base_url: str, soup: BeautifulSoup) -> List[_Candidate]:
    findings: List[_Candidate] = []
    for idx, meta in enumerate(soup.find_all("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})):
        content = meta.get("content")
        if not content:
            continue
        match = _META_REFRESH.search(content)
        if not match:
            continue
        candidate = match.group("url").strip().strip('"\'')
        if not candidate:
            continue
        if not candidate.lower().startswith("http"):
            candidate = urljoin(base_url, candidate)
        findings.append(
            _Candidate(
                original_url=candidate,
                source="meta_refresh",
                method="meta_refresh",
                script_url=f"{base_url}#meta-{idx}",
                evidence=_truncate_evidence(content),
            )
        )
    return findings


def _follow_destination(session: requests.Session, url: str) -> RedirectFollow:
    history_urls: List[str] = []
    final_url: Optional[str] = None
    status = "ok"
    snippet = None
    try:
        response = session.get(url, timeout=_FOLLOW_TIMEOUT, allow_redirects=True)
        history_urls = [resp.url for resp in response.history]
        final_url = response.url
        snippet = response.text[:_MAX_FETCH_SNIPPET]
    except requests.RequestException as exc:
        status = f"error: {exc}"[:200]
    return final_url, history_urls, status, snippet


def _dedupe_candidates(candidates: Iterable[_Candidate], limit: int) -> List[_Candidate]:
    unique: List[_Candidate] = []
    seen: Set[str] = set()
    for candidate in candidates:
        key = f"{candidate.source}:{candidate.method}:{candidate.original_url}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
        if len(unique) >= limit:
            break
    return unique


def collect_redirects(base_url: str, html_content: str) -> List[RedirectFollow]:
    soup = BeautifulSoup(html_content, "html.parser")

    candidates: List[_Candidate] = []

    # Inline scripts
    inline_scripts = soup.find_all("script", src=False)
    for idx, script_tag in enumerate(inline_scripts[:_MAX_INLINE_SCRIPTS]):
        script_text = script_tag.string or script_tag.get_text() or ""
        if not script_text.strip():
            continue
        script_id = f"{base_url}#inline-{idx}"
        candidates.extend(_collect_from_script(script_id, script_text, "inline_js"))

    # External scripts
    external_urls: List[str] = []
    for script_tag in soup.find_all("script", src=True):
        raw_src = script_tag.get("src")
        if not raw_src:
            continue
        script_url = urljoin(base_url, raw_src.strip())
        if script_url not in external_urls:
            external_urls.append(script_url)
        if len(external_urls) >= _MAX_EXTERNAL_SCRIPTS:
            break

    session = requests.Session()
    session.headers.update(JS_HEADERS)
    session.verify = False

    for script_url in external_urls:
        try:
            resp = session.get(script_url, timeout=_FOLLOW_TIMEOUT, allow_redirects=True)
            resp.raise_for_status()
            script_text = resp.text
            logger.debug("Fetched script %s (size=%d)", script_url, len(script_text))
            candidates.extend(_collect_from_script(script_url, script_text, "external_js"))
        except requests.RequestException as exc:
            logger.debug("Failed fetching script %s: %s", script_url, exc)
            continue

    # Meta refresh tags
    candidates.extend(_collect_meta_refresh(base_url, soup))

    if not candidates:
        return []

    findings: List[RedirectFollow] = []
    deduped_candidates = _dedupe_candidates(candidates, _MAX_FOLLOWED_URLS)

    for candidate in deduped_candidates:
        final_url, history, status, snippet = _follow_destination(session, candidate.original_url)
        findings.append(
            RedirectFollow(
                Source=candidate.source,
                Method=candidate.method,
                OriginalURL=candidate.original_url,
                FinalURL=final_url,
                RedirectChain=history,
                ScriptURL=candidate.script_url,
                Evidence=candidate.evidence,
                Status=status,
                FetchedSnippet=snippet,
            )
        )

    return findings
