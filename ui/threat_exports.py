"""Threat Intel Exports — focused export views for clipboard commands,
download cradles, and HTML lure variants across all analyzed URLs."""

import streamlit as st
import pandas as pd
import json
import io
from datetime import datetime

from ui.helpers import _val


# ---------------------------------------------------------------------------
# Field mappings for each export category
# ---------------------------------------------------------------------------

CLIPBOARD_FIELDS = [
    ("ClipboardCommands", "Clipboard Command"),
    ("ClipboardManipulation", "Clipboard Manipulation JS"),
]

DOWNLOAD_CRADLE_FIELDS = [
    ("PowerShellDownloads", "PowerShell Download"),
    ("PowerShellCommands", "PowerShell Command"),
    ("EncodedPowerShell", "Encoded PowerShell"),
    ("MacOSTerminalCommands", "macOS Terminal Command"),
    ("DNSClickFix", "DNS ClickFix (nslookup)"),
    ("WindowsTerminalClickFix", "Windows Terminal"),
    ("WebDAVClickFix", "WebDAV net use"),
    ("FingerExeAbuse", "finger.exe Abuse"),
    ("WinHttpVBScript", "WinHttp VBScript"),
]

LURE_VARIANT_FIELDS = [
    ("ClickFixInstructions", "ClickFix Instructions"),
    ("FakeCloudflare", "Fake Cloudflare"),
    ("FakeVideoConferencing", "Fake Video Conferencing"),
    ("FakeWindowsUpdate", "Fake Windows Update"),
    ("FakeGlitchLures", "Fake Glitch / Broken Page"),
    ("FakeSoftwareDownloads", "Fake Software Download"),
    ("ConsentFixIndicators", "ConsentFix OAuth Theft"),
    ("LLMArtifactAbuse", "LLM / AI Artifact Abuse"),
    ("SharedAIChatLinks", "Shared AI Chat Links"),
    ("FakeBrowserUpdate", "Fake Browser Update"),
    ("CaptchaElements", "CAPTCHA Elements"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_items(results, fields):
    """Pull every matching item from results into flat rows.

    Returns list of dicts with keys: source_url, category, value, detail.
    """
    rows = []
    for r in results:
        url = _val(r, "URL", "")
        score = _val(r, "ThreatScore", 0)
        for field_key, label in fields:
            items = _val(r, field_key, [])
            if not items:
                continue
            for item in items:
                value, detail = _item_to_strings(item)
                rows.append({
                    "source_url": url,
                    "threat_score": score,
                    "category": label,
                    "value": value,
                    "detail": detail,
                })
    return rows


def _item_to_strings(item):
    """Convert a single finding item into (short_value, full_detail) strings."""
    if isinstance(item, str):
        return item, item

    if isinstance(item, dict):
        # PowerShellDownload shape
        if "FullMatch" in item:
            url = item.get("URL", "")
            risk = item.get("RiskLevel", "")
            short = item["FullMatch"][:200]
            detail = json.dumps(item, indent=2, default=str)
            if url:
                short = f"[{risk}] {url} — {short}"
            return short, detail
        if "Command" in item:
            risk = item.get("RiskLevel", "")
            return f"[{risk}] {item['Command'][:200]}", json.dumps(item, indent=2, default=str)
        if "EncodedCommand" in item:
            decoded = item.get("DecodedCommand", "")[:200]
            return f"Encoded → {decoded}", json.dumps(item, indent=2, default=str)
        return json.dumps(item, default=str)[:200], json.dumps(item, indent=2, default=str)

    # Pydantic model objects
    if hasattr(item, "FullMatch"):
        url = getattr(item, "URL", "") or ""
        risk = getattr(item, "RiskLevel", "")
        short = item.FullMatch[:200]
        if url:
            short = f"[{risk}] {url} — {short}"
        detail = json.dumps(item.model_dump(), indent=2, default=str) if hasattr(item, "model_dump") else str(item)
        return short, detail
    if hasattr(item, "Command"):
        risk = getattr(item, "RiskLevel", "")
        detail = json.dumps(item.model_dump(), indent=2, default=str) if hasattr(item, "model_dump") else str(item)
        return f"[{risk}] {item.Command[:200]}", detail
    if hasattr(item, "EncodedCommand"):
        decoded = getattr(item, "DecodedCommand", "")[:200]
        detail = json.dumps(item.model_dump(), indent=2, default=str) if hasattr(item, "model_dump") else str(item)
        return f"Encoded → {decoded}", detail

    return str(item)[:200], str(item)


def _rows_to_dataframe(rows):
    """Build a DataFrame from extracted rows."""
    if not rows:
        return pd.DataFrame(columns=["Source URL", "Category", "Value", "Threat Score"])
    return pd.DataFrame([
        {
            "Source URL": r["source_url"],
            "Category": r["category"],
            "Value": r["value"][:300],
            "Threat Score": r["threat_score"],
        }
        for r in rows
    ])


def _render_export_buttons(rows, prefix):
    """JSON + CSV download buttons for a set of rows."""
    c1, c2 = st.columns(2)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    with c1:
        json_str = json.dumps(rows, indent=2, default=str)
        st.download_button(
            "Export JSON",
            data=json_str,
            file_name=f"clickgrab_{prefix}_{ts}.json",
            mime="application/json",
            use_container_width=True,
        )
    with c2:
        csv_buf = io.StringIO()
        _rows_to_dataframe(rows).to_csv(csv_buf, index=False)
        st.download_button(
            "Export CSV",
            data=csv_buf.getvalue(),
            file_name=f"clickgrab_{prefix}_{ts}.csv",
            mime="text/csv",
            use_container_width=True,
        )


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_clipboard_section(results):
    """Clipboard commands export + analysis."""
    rows = _extract_items(results, CLIPBOARD_FIELDS)

    if not rows:
        st.info("No clipboard commands found in the current results.", icon=":material/info:")
        return

    # Stats row
    commands = [r for r in rows if r["category"] == "Clipboard Command"]
    manipulation = [r for r in rows if r["category"] == "Clipboard Manipulation JS"]
    unique_sources = len({r["source_url"] for r in rows})

    m1, m2, m3 = st.columns(3)
    with m1:
        with st.container(border=True):
            st.metric("Clipboard Commands", len(commands))
    with m2:
        with st.container(border=True):
            st.metric("Manipulation Scripts", len(manipulation))
    with m3:
        with st.container(border=True):
            st.metric("Source URLs", unique_sources)

    # Data table
    df = _rows_to_dataframe(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Detail expanders
    with st.expander(f"Detailed view ({len(rows)} items)"):
        for i, row in enumerate(rows[:50]):
            st.markdown(f"**{row['category']}** from `{row['source_url']}`")
            st.code(row["detail"][:2000], language="text")
            if i < len(rows) - 1:
                st.divider()
        if len(rows) > 50:
            st.caption(f"Showing 50 of {len(rows)} — export for full data.")

    _render_export_buttons(rows, "clipboard_commands")


def _render_cradles_section(results):
    """Download cradles export + analysis."""
    rows = _extract_items(results, DOWNLOAD_CRADLE_FIELDS)

    if not rows:
        st.info("No download cradles found in the current results.", icon=":material/info:")
        return

    # Stats row
    categories = {}
    for r in rows:
        categories[r["category"]] = categories.get(r["category"], 0) + 1
    unique_sources = len({r["source_url"] for r in rows})

    cols = st.columns(min(len(categories) + 1, 5))
    with cols[0]:
        with st.container(border=True):
            st.metric("Total Cradles", len(rows))
    for i, (cat, count) in enumerate(sorted(categories.items(), key=lambda x: -x[1])):
        if i + 1 >= len(cols):
            break
        with cols[i + 1]:
            with st.container(border=True):
                st.metric(cat, count)

    # Breakdown chart
    if len(categories) > 1:
        chart_df = pd.DataFrame(
            [{"Category": k, "Count": v} for k, v in categories.items()]
        ).sort_values("Count", ascending=True)
        st.bar_chart(chart_df, x="Category", y="Count", horizontal=True)

    # Extracted URLs from download cradles
    extracted_urls = []
    for r in results:
        downloads = _val(r, "PowerShellDownloads", [])
        for dl in downloads:
            dl_url = _val(dl, "URL", None) or (getattr(dl, "URL", None) if hasattr(dl, "URL") else None)
            if dl_url:
                extracted_urls.append({
                    "source": _val(r, "URL", ""),
                    "download_url": dl_url,
                    "risk": _val(dl, "RiskLevel", "") or (getattr(dl, "RiskLevel", "") if hasattr(dl, "RiskLevel") else ""),
                })

    if extracted_urls:
        st.markdown("**Extracted Download URLs**")
        url_df = pd.DataFrame(extracted_urls)
        st.dataframe(url_df, use_container_width=True, hide_index=True)

    # Full data table
    st.markdown("**All Download Cradles**")
    df = _rows_to_dataframe(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Detail expanders
    with st.expander(f"Detailed view ({len(rows)} items)"):
        for i, row in enumerate(rows[:50]):
            st.markdown(f"**{row['category']}** from `{row['source_url']}`")
            st.code(row["detail"][:2000], language="text")
            if i < len(rows) - 1:
                st.divider()
        if len(rows) > 50:
            st.caption(f"Showing 50 of {len(rows)} — export for full data.")

    _render_export_buttons(rows, "download_cradles")


def _render_lures_section(results):
    """HTML lure variants export + analysis."""
    rows = _extract_items(results, LURE_VARIANT_FIELDS)

    if not rows:
        st.info("No lure variants found in the current results.", icon=":material/info:")
        return

    # Stats row
    categories = {}
    for r in rows:
        categories[r["category"]] = categories.get(r["category"], 0) + 1
    unique_sources = len({r["source_url"] for r in rows})

    cols = st.columns(min(len(categories) + 1, 5))
    with cols[0]:
        with st.container(border=True):
            st.metric("Total Lure Indicators", len(rows))
    for i, (cat, count) in enumerate(sorted(categories.items(), key=lambda x: -x[1])):
        if i + 1 >= len(cols):
            break
        with cols[i + 1]:
            with st.container(border=True):
                st.metric(cat, count)

    # Breakdown chart
    if len(categories) > 1:
        chart_df = pd.DataFrame(
            [{"Lure Type": k, "Count": v} for k, v in categories.items()]
        ).sort_values("Count", ascending=True)
        st.bar_chart(chart_df, x="Lure Type", y="Count", horizontal=True)

    # Per-type breakdown
    st.markdown("**Lure Variants by Type**")
    for field_key, label in LURE_VARIANT_FIELDS:
        type_rows = [r for r in rows if r["category"] == label]
        if not type_rows:
            continue
        with st.container(border=True):
            type_sources = len({r["source_url"] for r in type_rows})
            st.markdown(
                f"**{label}** — {len(type_rows)} finding{'s' if len(type_rows) != 1 else ''} "
                f"across {type_sources} URL{'s' if type_sources != 1 else ''}"
            )
            for tr in type_rows[:10]:
                with st.expander(f"`{tr['source_url']}` — {tr['value'][:100]}"):
                    st.code(tr["detail"][:2000], language="text")
            if len(type_rows) > 10:
                st.caption(f"Showing 10 of {len(type_rows)} — export for full data.")

    # Full data table
    st.markdown("**All Lure Indicators**")
    df = _rows_to_dataframe(rows)
    st.dataframe(df, use_container_width=True, hide_index=True)

    _render_export_buttons(rows, "lure_variants")


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

def render_threat_exports_page():
    """Threat Intel Exports page — focused exports for clipboard, cradles, lures."""
    st.header("Threat Intel Exports", anchor=False)
    st.caption(
        "Export and analyze clipboard commands, download cradles, "
        "and HTML lure variants across all analyzed URLs."
    )

    results = st.session_state.get("scan_results")
    precomputed = st.session_state.get("precomputed_intel")

    # On first visit with nothing loaded, auto-load the most recent nightly run
    # so the page isn't empty. This pulls ALL three categories for that run.
    if not results and not precomputed and not st.session_state.get("_intel_autoload_tried"):
        st.session_state["_intel_autoload_tried"] = True
        if _autoload_latest_run():
            precomputed = st.session_state.get("precomputed_intel")

    # If still nothing, offer an explicit picker.
    if not results and not precomputed:
        st.info(
            "No scan results in the current session. "
            "Run a **Live Scan** first, or load a nightly report below.",
            icon=":material/info:",
        )
        _offer_nightly_load()
        results = st.session_state.get("scan_results")
        precomputed = st.session_state.get("precomputed_intel")
        if not results and not precomputed:
            return
    else:
        # Data is loaded — still let the user switch to a different run.
        with st.expander("Load a different nightly run", expanded=False):
            _offer_nightly_load()
            results = st.session_state.get("scan_results")
            precomputed = st.session_state.get("precomputed_intel")

    # Section selector
    section = st.pills(
        "Export Type",
        [
            ":material/content_paste: Clipboard Commands",
            ":material/download: Download Cradles",
            ":material/web: Lure Variants",
        ],
        default=":material/content_paste: Clipboard Commands",
        key="threat_export_pills",
    )

    st.divider()

    # If we have precomputed intel (from latest_threat_intel.json), render
    # directly from that — much faster than re-extracting from full results.
    if precomputed and not results:
        _render_from_precomputed(precomputed, section)
        return

    if section and "Clipboard" in section:
        _render_clipboard_section(results)
    elif section and "Cradle" in section:
        _render_cradles_section(results)
    elif section and "Lure" in section:
        _render_lures_section(results)


def _render_from_precomputed(data, section):
    """Render from a precomputed latest_threat_intel.json bundle."""
    date_label = data.get("date", "unknown")
    total_urls = data.get("total_urls_analyzed", 0)
    st.caption(f"Nightly intel from **{date_label}** ({total_urls} URLs analyzed)")

    if section and "Clipboard" in section:
        rows = data.get("clipboard_commands", [])
        if not rows:
            st.info("No clipboard commands in this nightly run.", icon=":material/info:")
            return
        _render_precomputed_table(rows, "clipboard_commands")

    elif section and "Cradle" in section:
        rows = data.get("download_cradles", [])
        if not rows:
            st.info("No download cradles in this nightly run.", icon=":material/info:")
            return
        _render_precomputed_table(rows, "download_cradles")

    elif section and "Lure" in section:
        rows = data.get("lure_variants", [])
        if not rows:
            st.info("No lure variants in this nightly run.", icon=":material/info:")
            return
        _render_precomputed_table(rows, "lure_variants")


def _render_precomputed_table(rows, prefix):
    """Render stats + table + exports from a flat list of precomputed rows."""
    # Category breakdown
    categories = {}
    for r in rows:
        cat = r.get("category", "Unknown")
        categories[cat] = categories.get(cat, 0) + 1
    unique_sources = len({r.get("source_url", "") for r in rows})

    cols = st.columns(min(len(categories) + 2, 5))
    with cols[0]:
        with st.container(border=True):
            st.metric("Total", len(rows))
    with cols[1]:
        with st.container(border=True):
            st.metric("Source URLs", unique_sources)
    for i, (cat, count) in enumerate(sorted(categories.items(), key=lambda x: -x[1])):
        if i + 2 >= len(cols):
            break
        with cols[i + 2]:
            with st.container(border=True):
                st.metric(cat, count)

    if len(categories) > 1:
        chart_df = pd.DataFrame(
            [{"Category": k, "Count": v} for k, v in categories.items()]
        ).sort_values("Count", ascending=True)
        st.bar_chart(chart_df, x="Category", y="Count", horizontal=True)

    # Data table
    df = pd.DataFrame([
        {
            "Source URL": r.get("source_url", ""),
            "Category": r.get("category", ""),
            "Value": str(r.get("value", ""))[:300],
            "Threat Score": r.get("threat_score", 0),
        }
        for r in rows
    ])
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Detail view
    with st.expander(f"Detailed view ({len(rows)} items)"):
        for i, row in enumerate(rows[:50]):
            st.markdown(f"**{row.get('category', '')}** from `{row.get('source_url', '')}`")
            val = row.get("value", "")
            if isinstance(val, dict):
                st.code(json.dumps(val, indent=2, default=str)[:2000], language="json")
            else:
                st.code(str(val)[:2000], language="text")
            if i < min(len(rows), 50) - 1:
                st.divider()
        if len(rows) > 50:
            st.caption(f"Showing 50 of {len(rows)} — export for full data.")

    _render_export_buttons(rows, prefix)


import re as _re

# Per-category intel filenames look like: clipboard_commands_20260601_020619.json
_INTEL_FILE_RE = _re.compile(
    r"^(clipboard_commands|download_cradles|lure_variants)_(\d{8}_\d{6})\.json$"
)


def _format_run_ts(ts):
    """20260601_020619 -> '2026-06-01 02:06:19' (falls back to the raw string)."""
    try:
        return datetime.strptime(ts, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts


def _discover_intel_runs(intel_dir):
    """Group per-category intel files by run timestamp.

    Returns an ordered dict-like list of (ts, {category_key: Path}) newest first.
    """
    runs = {}
    if not intel_dir.exists():
        return []
    for p in intel_dir.glob("*.json"):
        m = _INTEL_FILE_RE.match(p.name)
        if not m:
            continue
        category, ts = m.group(1), m.group(2)
        runs.setdefault(ts, {})[category] = p
    return [(ts, runs[ts]) for ts in sorted(runs, reverse=True)]


def _build_bundle_from_run(ts, files):
    """Load all available category files for one run into a combined intel bundle."""
    import json as _json

    bundle = {
        "timestamp": _format_run_ts(ts),
        "date": _format_run_ts(ts),
        "clipboard_commands": [],
        "download_cradles": [],
        "lure_variants": [],
    }
    sources = set()
    intel_dir = None
    for category, path in files.items():
        intel_dir = path.parent
        try:
            rows = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            rows = []
        if not isinstance(rows, list):
            rows = []
        bundle[category] = rows
        for r in rows:
            if isinstance(r, dict) and r.get("source_url"):
                sources.add(r["source_url"])

    # Prefer the true analyzed-URL count from the run's summary CSV if present.
    total = len(sources)
    summary = (intel_dir / f"threat_intel_summary_{ts}.csv") if intel_dir else None
    if summary and summary.exists():
        try:
            import csv as _csv

            with summary.open(encoding="utf-8") as fh:
                total = max(total, sum(1 for _ in _csv.DictReader(fh)))
        except Exception:
            pass
    bundle["total_urls_analyzed"] = total
    return bundle


def _autoload_latest_run():
    """Auto-load the most recent nightly run (all 3 categories). Returns True on success."""
    from pathlib import Path
    import json as _json

    # Combined file at repo root wins if it exists (local dev convenience).
    latest_intel = Path("latest_threat_intel.json")
    if latest_intel.exists():
        try:
            st.session_state["precomputed_intel"] = _json.loads(
                latest_intel.read_text(encoding="utf-8")
            )
            return True
        except Exception:
            pass

    runs = _discover_intel_runs(Path("nightly_reports") / "threat_intel")
    if not runs:
        return False
    ts, files = runs[0]
    st.session_state["precomputed_intel"] = _build_bundle_from_run(ts, files)
    return True


def _offer_nightly_load():
    """Let users load a full nightly run (all categories) or a consolidated report."""
    from pathlib import Path
    import json as _json

    nightly_dir = Path("nightly_reports")
    intel_dir = nightly_dir / "threat_intel"
    latest_intel = Path("latest_threat_intel.json")
    latest_report = Path("latest_consolidated_report.json")

    # Each option: (label, kind, payload)
    options = []

    if latest_intel.exists():
        options.append(("Latest threat intel (combined)", "intel_file", latest_intel))

    # Per-run bundles — every nightly run becomes ONE entry that loads all three
    # categories together (clipboard + cradles + lures), fixing the empty-tab bug.
    for ts, files in _discover_intel_runs(intel_dir)[:15]:
        have = ", ".join(
            short
            for key, short in (
                ("clipboard_commands", "clipboard"),
                ("download_cradles", "cradles"),
                ("lure_variants", "lures"),
            )
            if key in files
        )
        options.append(
            (f"Nightly run {_format_run_ts(ts)}  ({have})", "intel_bundle", (ts, files))
        )

    # Full consolidated reports re-extract everything (slower, but complete objects).
    if latest_report.exists():
        options.append(("Latest consolidated report (full)", "report", latest_report))
    if nightly_dir.exists():
        for p in sorted(nightly_dir.glob("clickgrab_report_*.json"), reverse=True)[:10]:
            options.append((p.name, "report", p))

    if not options:
        st.warning("No nightly data found in `nightly_reports/`.")
        return

    labels = [o[0] for o in options]
    choice = st.selectbox("Load from nightly data", ["(none)"] + labels)
    if not choice or choice == "(none)":
        return

    _, kind, payload = options[labels.index(choice)]
    try:
        if kind == "intel_file":
            data = _json.loads(payload.read_text(encoding="utf-8"))
            st.session_state["precomputed_intel"] = data
            # Clear any live/report results so the precomputed bundle is what renders.
            st.session_state.pop("scan_results", None)
            st.success(
                f"Loaded combined intel ({data.get('date', 'unknown')}, "
                f"{data.get('total_urls_analyzed', '?')} URLs).",
                icon=":material/check_circle:",
            )
            st.rerun()
        elif kind == "intel_bundle":
            ts, files = payload
            bundle = _build_bundle_from_run(ts, files)
            st.session_state["precomputed_intel"] = bundle
            # Clear any live/report results so the precomputed bundle is what renders.
            st.session_state.pop("scan_results", None)
            st.success(
                f"Loaded nightly run {_format_run_ts(ts)} — "
                f"{len(bundle['clipboard_commands'])} clipboard, "
                f"{len(bundle['download_cradles'])} cradles, "
                f"{len(bundle['lure_variants'])} lures.",
                icon=":material/check_circle:",
            )
            st.rerun()
        else:  # report
            data = _json.loads(payload.read_text(encoding="utf-8"))
            sites = data.get("sites", []) if isinstance(data, dict) else []
            if sites:
                st.session_state["scan_results"] = sites
                st.session_state.pop("precomputed_intel", None)
                st.success(
                    f"Loaded {len(sites)} results from `{payload.name}`.",
                    icon=":material/check_circle:",
                )
                st.rerun()
            else:
                st.warning(f"`{payload.name}` has no `sites` to load.")
    except Exception as e:
        st.error(f"Failed to load: {e}")
