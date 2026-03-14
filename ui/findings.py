"""Findings explorer component — replaces the old 32-tab interface."""

import streamlit as st
import json

from ui.categories import FINDING_CATEGORIES
from ui.helpers import _val, _count, _flatten_finding, _flatten_finding_full


def render_findings_explorer(results):
    """Category-based findings explorer with pills and expandable cards."""
    st.subheader("Findings Explorer", anchor=False)

    cat_names = list(FINDING_CATEGORIES.keys())
    cat_labels = []
    for name in cat_names:
        info = FINDING_CATEGORIES[name]
        total = sum(
            sum(_count(r, f) for f, _ in info["fields"]) for r in results
        )
        cat_labels.append(f"{info['icon']} {name} ({total})")

    selected_label = st.pills(
        "Category",
        cat_labels,
        default=cat_labels[0],
        key="findings_cat_pills",
    )

    if not selected_label:
        return

    selected_idx = cat_labels.index(selected_label)
    selected_cat = cat_names[selected_idx]
    cat_info = FINDING_CATEGORIES[selected_cat]

    has_any = False
    for field_key, field_label in cat_info["fields"]:
        all_items = []
        for r in results:
            items = _val(r, field_key, [])
            if items:
                url = _val(r, "URL", "")
                for item in items:
                    all_items.append((url, item))

        if not all_items:
            continue

        has_any = True
        with st.container(border=True):
            st.markdown(
                f"**{field_label}** -- "
                f"{len(all_items)} finding{'s' if len(all_items) != 1 else ''}"
            )

            for i, (url, item) in enumerate(all_items[:25]):
                display = _flatten_finding(item)
                source_label = f" `{url}`" if len(results) > 1 else ""
                truncated = (
                    display[:120] + "..." if len(display) > 120 else display
                )

                with st.expander(
                    f"{truncated}{source_label}", expanded=False
                ):
                    if isinstance(item, dict) and "script" in item:
                        st.code(item["script"], language="javascript")
                        if "indicators" in item:
                            st.json(item["indicators"])
                    elif isinstance(item, str):
                        st.code(item, language="text")
                    else:
                        full = _flatten_finding_full(item)
                        st.code(full, language="text")

            if len(all_items) > 25:
                st.caption(
                    f"Showing 25 of {len(all_items)} -- "
                    "export JSON for full data."
                )

    if not has_any:
        st.info(f"No findings in the **{selected_cat}** category.")
