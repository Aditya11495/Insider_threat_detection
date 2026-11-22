import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# ============================================================
# 1. PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="Insider Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# 2. THEME
# ============================================================
if "dashboard_theme" not in st.session_state:
    st.session_state.dashboard_theme = "Dark"

with st.sidebar:
    st.markdown(
        """
        <div class="brand">
            <div class="brand-icon">🛡️</div>
            <div>
                <div class="brand-name">THREAT INTEL</div>
                <div class="brand-subtitle">INSIDER THREAT MONITORING</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()
    st.session_state.dashboard_theme = st.radio(
        "APPEARANCE",
        ["Dark", "Light"],
        index=0 if st.session_state.dashboard_theme == "Dark" else 1,
        horizontal=True,
        key="theme_selector",
    )

DARK = st.session_state.dashboard_theme == "Dark"

if DARK:
    C = {
        "bg": "#0B1220",
        "panel": "#151F32",
        "panel_alt": "#1B2940",
        "sidebar": "#0A1020",
        "text": "#E8EEF8",
        "muted": "#9AAAC0",
        "border": "#2A3A54",
        "accent": "#8B7CFF",
        "blue": "#4EA1FF",
        "red": "#FF647C",
        "green": "#36C995",
        "orange": "#F6B65B",
        "grid": "#2A3A54",
    }
    PLOT_TEMPLATE = "plotly_dark"
else:
    C = {
        "bg": "#F3F6FC",
        "panel": "#FFFFFF",
        "panel_alt": "#F8FAFE",
        "sidebar": "#17243A",
        "text": "#17243A",
        "muted": "#64748B",
        "border": "#E1E8F0",
        "accent": "#6558D3",
        "blue": "#2878D0",
        "red": "#D9435D",
        "green": "#15966C",
        "orange": "#C77A19",
        "grid": "#E5EAF2",
    }
    PLOT_TEMPLATE = "plotly_white"

st.markdown(
    f"""
    <style>
    :root {{
        --bg: {C['bg']};
        --panel: {C['panel']};
        --panel-alt: {C['panel_alt']};
        --sidebar: {C['sidebar']};
        --text: {C['text']};
        --muted: {C['muted']};
        --border: {C['border']};
        --accent: {C['accent']};
    }}
