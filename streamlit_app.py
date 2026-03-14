"""
ClickGrab Analyzer — Modern Streamlit Dashboard
=================================================
A security analysis dashboard for detecting ClickFix / FakeCAPTCHA campaigns.
Redesigned with a category-based findings explorer, metric cards, and
modern Streamlit components (st.navigation, st.pills, st.container, st.dialog).

UI modules live in the ``ui/`` package:
  - ui/categories.py  — Finding category definitions
  - ui/helpers.py     — Shared helper functions
  - ui/findings.py    — Findings explorer component
  - ui/exports.py     — Download / export buttons
"""

import streamlit as st
import pandas as pd
import json
import re
import urllib3
import warnings
import yaml
from datetime import datetime
from pathlib import Path

from clickgrab import analyze_url, download_urlhaus_data, sanitize_url
from models import AnalysisVerdict

from ui.categories import FINDING_CATEGORIES
from ui.helpers import _val, _count, _category_counts
from ui.findings import render_findings_explorer
from ui.exports import render_downloads
from ui.threat_exports import render_threat_exports_page

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")



# ---------------------------------------------------------------------------
# Page: Dashboard
# ---------------------------------------------------------------------------

def dashboard_page():
    st.header("Dashboard", anchor=False)

    results = st.session_state.get("scan_results")
    if not results:
        st.info(
            "No scan results yet. Go to **Live Scan** to analyze URLs.",
            icon=":material/info:",
        )
        techniques_dir = Path("techniques")
        if techniques_dir.exists():
            yamls = list(techniques_dir.glob("*.yml"))
            cols = st.columns(3)
            with cols[0]:
                with st.container(border=True):
                    st.metric("Techniques in Library", len(yamls))
            with cols[1]:
                with st.container(border=True):
                    st.metric("Detection Categories", len(FINDING_CATEGORIES))
            with cols[2]:
                with st.container(border=True):
                    total_fields = sum(len(c["fields"]) for c in FINDING_CATEGORIES.values())
                    st.metric("Indicator Types", total_fields)
        return

    # --- Metrics row ---
    total = len(results)
    suspicious = sum(1 for r in results if _val(r, "Verdict") == AnalysisVerdict.SUSPICIOUS.value)
    scores = [_val(r, "ThreatScore", 0) for r in results]
    avg_score = round(sum(scores) / total) if total else 0
    max_score = max(scores) if scores else 0
    total_indicators = sum(_val(r, "TotalIndicators", 0) for r in results)

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        with st.container(border=True):
            st.metric("URLs Scanned", total)
    with m2:
        with st.container(border=True):
            pct = f"{round(suspicious/total*100)}%" if total else "0%"
            st.metric("Suspicious", suspicious, delta=pct)
    with m3:
        with st.container(border=True):
            st.metric("Avg Score", avg_score)
    with m4:
        with st.container(border=True):
            st.metric("Max Score", max_score)
    with m5:
        with st.container(border=True):
            st.metric("Total Indicators", total_indicators)

    st.divider()

    # --- Category breakdown ---
    st.subheader("Findings by Category", anchor=False)
    cat_cols = st.columns(len(FINDING_CATEGORIES))
    for idx, (cat_name, cat_info) in enumerate(FINDING_CATEGORIES.items()):
        cat_total = sum(
            sum(_count(r, f) for f, _ in cat_info["fields"])
            for r in results
        )
        with cat_cols[idx]:
            with st.container(border=True):
                st.metric(
                    label=f"{cat_info['icon']} {cat_name}",
                    value=cat_total,
                )

    st.divider()

    # --- Results table ---
    st.subheader("Scan Results", anchor=False)
    rows = []
    for r in results:
        url = _val(r, "URL", "")
        verdict = _val(r, "Verdict", "Unknown")
        score = _val(r, "ThreatScore", 0)
        indicators = _val(r, "TotalIndicators", 0)
        cats = _category_counts(r)
        rows.append({
            "URL": url,
            "Verdict": verdict,
            "Score": score,
            "Indicators": indicators,
            **cats,
        })

    df = pd.DataFrame(rows)
    max_score_val = max(100, int(df["Score"].max())) if not df.empty else 100
    st.dataframe(
        df.style.background_gradient(
            subset=["Score"], cmap="YlOrRd", vmin=0, vmax=max_score_val
        ).background_gradient(
            subset=["Indicators"], cmap="Blues", vmin=0
        ),
        use_container_width=True,
        hide_index=True,
        column_config={
            "URL": st.column_config.TextColumn("URL", width="large"),
            "Verdict": st.column_config.TextColumn("Verdict", width="small"),
            "Score": st.column_config.ProgressColumn(
                "Threat Score", min_value=0, max_value=max_score_val, format="%d"
            ),
        },
    )


# ---------------------------------------------------------------------------
# Page: Live Scan
# ---------------------------------------------------------------------------

def live_scan_page():
    st.header("Live Scan", anchor=False)

    scan_mode = st.pills(
        "Scan Mode",
        ["Single URL", "Batch URLs", "URLhaus Feed"],
        default="Single URL",
        key="scan_mode_pills",
    )

    if scan_mode == "Single URL":
        _scan_single()
    elif scan_mode == "Batch URLs":
        _scan_batch()
    else:
        _scan_urlhaus()


def _scan_single():
    with st.form("single_url_form"):
        url = st.text_input(
            "URL to analyze",
            placeholder="https://suspicious-site.example.com",
        )
        submitted = st.form_submit_button(
            "Analyze", type="primary", use_container_width=True
        )

    if submitted and url:
        with st.status("Analyzing...", expanded=True) as status:
            st.write(f"Fetching content from `{url}`...")
            result = analyze_url(url)
            status.update(label="Analysis complete", state="complete")

        if result:
            st.session_state["scan_results"] = [result]
            st.toast("Analysis complete!", icon=":material/check_circle:")
            _render_result(result)


def _scan_batch():
    with st.form("batch_url_form"):
        urls_text = st.text_area(
            "URLs (one per line)",
            height=150,
            placeholder="https://site1.com\nhttps://site2.com",
        )
        limit = st.number_input("Max URLs", min_value=1, max_value=200, value=20)
        submitted = st.form_submit_button(
            "Analyze All", type="primary", use_container_width=True
        )

    if submitted and urls_text.strip():
        raw_urls = [
            u.strip() for u in urls_text.strip().splitlines() if u.strip()
        ][:limit]
        results = []

        with st.status(f"Analyzing {len(raw_urls)} URLs...", expanded=True) as status:
            progress = st.progress(0)
            for i, url in enumerate(raw_urls):
                st.write(f"`{url}`")
                r = analyze_url(sanitize_url(url))
                if r:
                    results.append(r)
                progress.progress((i + 1) / len(raw_urls))
            status.update(
                label=f"Done -- {len(results)} analyzed", state="complete"
            )

        if results:
            st.session_state["scan_results"] = results
            st.toast(
                f"Batch complete: {len(results)} URLs",
                icon=":material/check_circle:",
            )
            _render_batch_summary(results)


def _scan_urlhaus():
    with st.form("urlhaus_form"):
        c1, c2 = st.columns([3, 1])
        with c1:
            tags = st.text_input(
                "Tags (comma-separated)", value="FakeCaptcha,ClickFix,click"
            )
        with c2:
            limit = st.number_input("Limit", min_value=1, max_value=100, value=10)
        submitted = st.form_submit_button(
            "Fetch & Analyze", type="primary", use_container_width=True
        )

    if submitted:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]

        with st.status("Fetching from URLhaus...", expanded=True) as status:
            st.write("Querying URLhaus API...")
            urls = download_urlhaus_data(limit=limit, tags=tag_list)

            if not urls:
                status.update(label="No URLs found", state="error")
                st.warning("No matching URLs found on URLhaus.")
                return

            st.write(f"Found **{len(urls)}** URLs. Analyzing...")
            results = []
            progress = st.progress(0)
            for i, url in enumerate(urls):
                st.write(f"`{url}`")
                r = analyze_url(url)
                if r:
                    results.append(r)
                progress.progress((i + 1) / len(urls))
            status.update(
                label=f"Done -- {len(results)} analyzed", state="complete"
            )

        if results:
            st.session_state["scan_results"] = results
            st.toast(
                f"URLhaus scan complete: {len(results)} URLs",
                icon=":material/check_circle:",
            )
            _render_batch_summary(results)


# ---------------------------------------------------------------------------
# Result rendering
# ---------------------------------------------------------------------------

def _render_result(result):
    """Render a single analysis result with metrics + category explorer."""
    score = _val(result, "ThreatScore", 0)
    verdict = _val(result, "Verdict", "Unknown")
    total_ind = _val(result, "TotalIndicators", 0)

    if verdict == AnalysisVerdict.SUSPICIOUS.value:
        st.error(
            f"**SUSPICIOUS** -- Threat Score: **{score}** -- "
            f"{total_ind} indicators found",
            icon=":material/warning:",
        )
    elif total_ind > 0:
        st.warning(
            f"**Low Risk** -- Threat Score: **{score}** -- "
            f"{total_ind} indicators found",
            icon=":material/info:",
        )
    else:
        st.success(
            "**Likely Safe** -- No significant indicators found",
            icon=":material/check_circle:",
        )

    if total_ind == 0:
        return

    # Category metrics
    cats = _category_counts(result)
    cols = st.columns(len(cats))
    for idx, (cat_name, count) in enumerate(cats.items()):
        cat_info = FINDING_CATEGORIES[cat_name]
        with cols[idx]:
            with st.container(border=True):
                st.metric(f"{cat_info['icon']} {cat_name}", count)

    st.divider()
    render_findings_explorer([result])

    # Raw HTML
    with st.expander("Raw HTML Content"):
        raw = _val(result, "RawHTML", "")
        if raw and raw != "ERROR: Failed to retrieve content":
            st.code(
                raw[:5000] + ("..." if len(raw) > 5000 else ""),
                language="html",
            )
        else:
            st.info("No HTML content available.")

    render_downloads([result])


def _render_batch_summary(results):
    """Summary table for batch results + findings explorer."""
    st.subheader("Results Summary", anchor=False)

    rows = []
    for r in results:
        rows.append({
            "URL": _val(r, "URL", ""),
            "Verdict": _val(r, "Verdict", "Unknown"),
            "Score": _val(r, "ThreatScore", 0),
            "Indicators": _val(r, "TotalIndicators", 0),
        })
    df = pd.DataFrame(rows)
    max_score_val = max(100, int(df["Score"].max())) if not df.empty else 100

    st.dataframe(
        df.style.background_gradient(
            subset=["Score"], cmap="YlOrRd", vmin=0, vmax=max_score_val
        ),
        use_container_width=True,
        hide_index=True,
        column_config={
            "URL": st.column_config.TextColumn("URL", width="large"),
            "Score": st.column_config.ProgressColumn(
                "Score", min_value=0, max_value=max_score_val, format="%d"
            ),
        },
    )

    st.divider()
    render_findings_explorer(results)
    render_downloads(results)




# ---------------------------------------------------------------------------
# Page: Findings (standalone explorer for session results)
# ---------------------------------------------------------------------------

def findings_page():
    st.header("Findings Explorer", anchor=False)

    results = st.session_state.get("scan_results")
    if not results:
        st.info(
            "No scan results yet. Run a **Live Scan** first.",
            icon=":material/info:",
        )
        return

    if len(results) > 1:
        urls = ["All URLs"] + [
            _val(r, "URL", f"Site {i}") for i, r in enumerate(results)
        ]
        selected_url = st.selectbox("Filter by URL", urls)
        if selected_url != "All URLs":
            results = [r for r in results if _val(r, "URL") == selected_url]

    render_findings_explorer(results)


# ---------------------------------------------------------------------------
# Page: Technique Library
# ---------------------------------------------------------------------------

def techniques_page():
    st.header("Technique Library", anchor=False)

    techniques_dir = Path("techniques")
    if not techniques_dir.exists():
        st.warning("No techniques directory found.")
        return

    yamls = sorted(techniques_dir.glob("*.yml"))
    if not yamls:
        st.warning("No technique files found.")
        return

    # Load all techniques
    all_techniques = []
    for ypath in yamls:
        try:
            with open(ypath, "r") as f:
                content = f.read()
            docs = list(yaml.safe_load_all(content))
            for doc in docs:
                if doc and isinstance(doc, dict) and "name" in doc:
                    doc["_file"] = ypath.name
                    all_techniques.append(doc)
        except Exception:
            continue

    # Search and filter
    c1, c2 = st.columns([3, 1])
    with c1:
        search = st.text_input(
            "Search techniques",
            placeholder="e.g. powershell, mshta, osascript...",
        )
    with c2:
        platforms = sorted(
            {t.get("platform", "unknown") for t in all_techniques}
        )
        platform_filter = st.selectbox("Platform", ["all"] + platforms)

    filtered = all_techniques
    if search:
        search_lower = search.lower()
        filtered = [
            t
            for t in filtered
            if search_lower in t.get("name", "").lower()
            or search_lower in t.get("info", "").lower()
            or search_lower in t.get("_file", "").lower()
        ]
    if platform_filter != "all":
        filtered = [
            t for t in filtered if t.get("platform") == platform_filter
        ]

    st.caption(f"Showing {len(filtered)} of {len(all_techniques)} techniques")

    for tech in filtered:
        name = tech.get("name", "Unknown")
        platform = tech.get("platform", "unknown")
        info = tech.get("info", "").strip()
        lures = tech.get("lures", [])
        added = tech.get("added_at", "")

        if platform == "windows":
            platform_icon = ":material/computer:"
        elif platform in ("macos", "darwin"):
            platform_icon = ":material/laptop_mac:"
        else:
            platform_icon = ":material/devices:"

        with st.container(border=True):
            h1, h2 = st.columns([4, 1])
            with h1:
                st.markdown(f"### {platform_icon} {name}")
            with h2:
                st.caption(f"{platform} | {added}")

            if info:
                st.markdown(
                    info[:300] + ("..." if len(info) > 300 else "")
                )

            if lures:
                with st.expander(
                    f"{len(lures)} lure{'s' if len(lures) != 1 else ''} documented"
                ):
                    for lure in lures:
                        nick = lure.get("nickname", "Untitled")
                        st.markdown(f"**{nick}**")

                        preamble = lure.get("preamble", "")
                        if preamble:
                            st.info(
                                preamble.strip(),
                                icon=":material/format_quote:",
                            )

                        steps = lure.get("steps", [])
                        if steps:
                            for j, step in enumerate(steps, 1):
                                st.markdown(f"{j}. {step}")

                        refs = lure.get("references", [])
                        if refs:
                            st.markdown("**References:**")
                            for ref in refs:
                                st.markdown(f"- {ref}")

                        mitigations = lure.get("mitigations", [])
                        if mitigations:
                            st.markdown("**Mitigations:**")
                            for m in mitigations:
                                st.markdown(f"- {m}")

                        st.divider()


# ---------------------------------------------------------------------------
# Page: Contribute Technique
# ---------------------------------------------------------------------------

def contribute_page():
    st.header("Contribute a Technique", anchor=False)
    st.markdown(
        "Submit a new ClickFix technique to the library. "
        "Fill out the form below and download the YAML file."
    )

    with st.form("contribute_form"):
        st.subheader("Basic Info", anchor=False)
        c1, c2, c3 = st.columns(3)
        with c1:
            name = st.text_input(
                "Technique Name", placeholder="e.g. powershell.exe"
            )
        with c2:
            platform = st.selectbox(
                "Platform", ["windows", "macos", "linux", "cross-platform"]
            )
        with c3:
            presentation = st.selectbox("Presentation", ["cli", "browser", "gui"])

        info = st.text_area(
            "Description",
            placeholder="Describe how this technique works...",
        )

        st.subheader("Lure Details", anchor=False)
        nickname = st.text_input(
            "Lure Nickname",
            placeholder="e.g. Fix Windows Security Update",
        )
        preamble = st.text_area(
            "Preamble (social engineering text)", height=80
        )
        steps_text = st.text_area(
            "Steps (one per line)",
            height=100,
            placeholder="Press Win+R\nType powershell\nPress Ctrl+V\nPress Enter",
        )
        capabilities = st.multiselect(
            "Capabilities", ["UAC", "MOTW", "File Explorer", "CLI", "GUI"]
        )
        references = st.text_area(
            "References (one URL per line)", height=80
        )
        mitigations = st.text_area(
            "Mitigations (one per line)", height=80
        )

        st.subheader("Contributor", anchor=False)
        c1, c2 = st.columns(2)
        with c1:
            contributor_name = st.text_input("Your Name")
        with c2:
            contributor_handle = st.text_input("Twitter/X Handle")

        submitted = st.form_submit_button(
            "Generate YAML", type="primary", use_container_width=True
        )

    if submitted and name:
        steps = [s.strip() for s in steps_text.strip().splitlines() if s.strip()]
        refs = [r.strip() for r in references.strip().splitlines() if r.strip()]
        mits = [m.strip() for m in mitigations.strip().splitlines() if m.strip()]

        technique = {
            "name": name,
            "added_at": datetime.now().strftime("%Y-%m-%d"),
            "platform": platform,
            "presentation": presentation,
            "info": info,
            "lures": [
                {
                    "nickname": nickname,
                    "added_at": datetime.now().strftime("%Y-%m-%d"),
                    "contributor": {
                        "name": contributor_name,
                        **(
                            {"handle": contributor_handle}
                            if contributor_handle
                            else {}
                        ),
                    },
                    "preamble": preamble,
                    "steps": steps,
                    "capabilities": capabilities,
                    "references": refs,
                    "mitigations": mits,
                }
            ],
        }

        yaml_content = yaml.dump(
            technique,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )

        st.code(yaml_content, language="yaml")

        safe_name = re.sub(r"[^\w\-.]", "_", name.lower())
        st.download_button(
            "Download YAML",
            data=yaml_content,
            file_name=f"{safe_name}.yml",
            mime="text/yaml",
            use_container_width=True,
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    st.set_page_config(
        page_title="ClickGrab",
        page_icon=":material/security:",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.sidebar.markdown("### ClickGrab")
    st.sidebar.caption("ClickFix / FakeCAPTCHA Analyzer")
    st.sidebar.divider()

    pages = {
        "Analysis": [
            st.Page(
                dashboard_page,
                title="Dashboard",
                icon=":material/dashboard:",
            ),
            st.Page(
                live_scan_page,
                title="Live Scan",
                icon=":material/search:",
            ),
            st.Page(
                findings_page,
                title="Findings",
                icon=":material/bug_report:",
            ),
            st.Page(
                render_threat_exports_page,
                title="Threat Intel Exports",
                icon=":material/file_download:",
            ),
        ],
        "Library": [
            st.Page(
                techniques_page,
                title="Techniques",
                icon=":material/library_books:",
            ),
            st.Page(
                contribute_page,
                title="Contribute",
                icon=":material/add_circle:",
            ),
        ],
    }

    pg = st.navigation(pages)
    pg.run()


if __name__ == "__main__":
    main()
