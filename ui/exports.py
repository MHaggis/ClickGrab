"""Download / export functionality."""

import streamlit as st
import pandas as pd
import json
import io
from datetime import datetime

from ui.categories import FINDING_CATEGORIES
from ui.helpers import _val, _count


def render_downloads(results):
    """Render export buttons for JSON, CSV, and HTML reports."""
    st.divider()
    st.subheader("Export", anchor=False)
    c1, c2, c3 = st.columns(3)

    with c1:
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "total_sites": len(results),
            "results": [
                r.model_dump(exclude_none=True)
                if hasattr(r, "model_dump")
                else r
                for r in results
            ],
        }
        json_str = json.dumps(report_data, indent=2, default=str)
        st.download_button(
            "Download JSON",
            data=json_str,
            file_name=f"clickgrab_{datetime.now():%Y%m%d_%H%M%S}.json",
            mime="application/json",
            use_container_width=True,
        )

    with c2:
        rows = []
        for r in results:
            row = {
                "URL": _val(r, "URL", ""),
                "Verdict": _val(r, "Verdict", ""),
                "ThreatScore": _val(r, "ThreatScore", 0),
                "TotalIndicators": _val(r, "TotalIndicators", 0),
            }
            for cat_name, cat_info in FINDING_CATEGORIES.items():
                row[cat_name] = sum(
                    _count(r, f) for f, _ in cat_info["fields"]
                )
            rows.append(row)
        csv_buf = io.StringIO()
        pd.DataFrame(rows).to_csv(csv_buf, index=False)
        st.download_button(
            "Download CSV",
            data=csv_buf.getvalue(),
            file_name=f"clickgrab_{datetime.now():%Y%m%d_%H%M%S}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with c3:
        try:
            from clickgrab import generate_html_report
            from models import ClickGrabConfig

            config = ClickGrabConfig(output_dir="/tmp/clickgrab_reports")
            html_path = generate_html_report(results, config)
            with open(html_path, "r") as f:
                html_data = f.read()
            st.download_button(
                "Download HTML Report",
                data=html_data,
                file_name=f"clickgrab_{datetime.now():%Y%m%d_%H%M%S}.html",
                mime="text/html",
                use_container_width=True,
            )
        except Exception:
            st.button(
                "Download HTML Report",
                disabled=True,
                use_container_width=True,
            )
