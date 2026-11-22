import os
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# =====================================================
# 1. PAGE CONFIGURATION
# =====================================================
st.set_page_config(
    page_title="Insider Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =====================================================
# 2. THEME SWITCH
# =====================================================
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True

st.sidebar.markdown("<div class='brand'>🛡️ <b>THREAT INTEL</b></div>", unsafe_allow_html=True)
st.sidebar.caption("INSIDER THREAT MONITORING")
st.sidebar.toggle("Dark mode", key="dark_mode")

DARK = st.session_state.dark_mode
if DARK:
    T = {
        "app": "#0B1220", "sidebar": "#111A2B", "panel": "#1B2940",
        "panel2": "#202F49", "text": "#E8EEF8", "muted": "#A6B4C8",
        "border": "#2C3B55", "accent": "#8B7CFF", "blue": "#54A6FF",
        "red": "#FF667A", "green": "#48C99A", "orange": "#F6A65B",
        "plot": "#1B2940", "grid": "#34445F", "metric": "#202F49",
    }
else:
    T = {
        "app": "#F3F6FC", "sidebar": "#FFFFFF", "panel": "#FFFFFF",
        "panel2": "#F8FAFE", "text": "#17243A", "muted": "#66758B",
        "border": "#DFE6F0", "accent": "#6557E8", "blue": "#2878D0",
        "red": "#D94B62", "green": "#169B72", "orange": "#D88732",
        "plot": "#FFFFFF", "grid": "#E5EAF2", "metric": "#FFFFFF",
    }

st.markdown(f"""
<style>
.stApp {{ background: {T['app']}; color: {T['text']}; }}
[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1500px; }}
[data-testid="stSidebar"] {{ background: {T['sidebar']}; border-right: 1px solid {T['border']}; }}
[data-testid="stSidebar"] * {{ color: {T['text']} !important; }}
.brand {{ font-size: 1.35rem; letter-spacing: .5px; color: {T['accent']}; padding: .35rem 0 .1rem; }}
[data-testid="stMetric"] {{ background: {T['metric']}; border: 1px solid {T['border']}; padding: 16px 18px; border-radius: 13px; box-shadow: 0 5px 18px rgba(0,0,0,.07); }}
[data-testid="stMetricLabel"] {{ color: {T['muted']} !important; font-weight: 600; }}
[data-testid="stMetricValue"] {{ color: {T['text']} !important; font-weight: 800; }}
h1, h2, h3 {{ color: {T['text']} !important; letter-spacing: -.35px; }}
p, label, .stMarkdown {{ color: {T['text']}; }}
[data-testid="stCaptionContainer"] {{ color: {T['muted']} !important; }}
[data-testid="stDataFrame"], [data-testid="stPlotlyChart"] {{ background: {T['panel']}; border: 1px solid {T['border']}; border-radius: 13px; padding: 7px; }}
.stButton > button, .stDownloadButton > button {{ background: {T['accent']}; color: white; border: 0; border-radius: 9px; font-weight: 650; }}
.stButton > button:hover, .stDownloadButton > button:hover {{ background: {T['blue']}; color: white; border: 0; }}
[data-testid="stSelectbox"] > div > div, [data-testid="stTextInput"] input {{ background: {T['panel']}; color: {T['text']}; border-color: {T['border']}; }}
hr {{ border-color: {T['border']}; }}
.footer {{ color: {T['muted']}; text-align: center; padding: 22px 5px 5px; font-size: 12px; }}
</style>
""", unsafe_allow_html=True)

# =====================================================
# 3. LOAD PROJECT DATA
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "insider_threat_app")

@st.cache_data
def load_data():
    results_path = os.path.join(DATA_DIR, "anomaly_results.csv")
    employees_path = os.path.join(DATA_DIR, "employee_summary.csv")
    if not os.path.exists(results_path):
        raise FileNotFoundError(f"Could not find: {results_path}")
    if not os.path.exists(employees_path):
        raise FileNotFoundError(f"Could not find: {employees_path}")
    results = pd.read_csv(results_path)
    employees = pd.read_csv(employees_path)
    if "activity_date" in results.columns:
        results["activity_date"] = pd.to_datetime(results["activity_date"], errors="coerce")
    return results, employees

try:
    results, employees = load_data()
except Exception as e:
    st.error(f"Unable to load project data: {e}")
    st.info("Check that both CSV files are inside the insider_threat_app folder next to app.py.")
    st.stop()

# =====================================================
# 4. VALIDATE DATA