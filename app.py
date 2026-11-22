from pathlib import Path

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="Insider Threat Intelligence",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


if "dashboard_theme" not in st.session_state:
    st.session_state.dashboard_theme = "Dark"


with st.sidebar:
    st.markdown(
        """
        <div style="padding: 0.25rem 0 0.5rem;">
            <div style="font-size: 1.1rem; font-weight: 700;">Threat intel</div>
            <div style="font-size: 0.75rem; opacity: 0.7;">Insider threat monitoring</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()
    st.session_state.dashboard_theme = st.segmented_control(
        "Appearance",
        ["Dark", "Light"],
        default=st.session_state.dashboard_theme,
        key="theme_selector",
    )


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "insider_threat_app"


@st.cache_data
def load_anomalies() -> pd.DataFrame:
    frame = pd.read_csv(DATA_DIR / "anomaly_results.csv")
    frame["activity_date"] = pd.to_datetime(frame["activity_date"], errors="coerce")
    return frame


@st.cache_data
def load_employee_summary() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "employee_summary.csv")


anomalies = load_anomalies()
employee_summary = load_employee_summary()


st.title("Insider threat intelligence")
st.caption("Behavior anomaly monitoring and employee risk overview")

with st.sidebar:
    st.header("Filters")
    risk_threshold = st.slider(
        "Minimum anomaly rate",
        min_value=0,
        max_value=100,
        value=0,
        step=5,
        key="risk_threshold",
    )
    selected_label = st.segmented_control(
        "Detection",
        ["All", "Anomaly", "Normal"],
        default="All",
        key="detection_label",
    )

filtered_summary = employee_summary[
    employee_summary["anomaly_rate"] >= risk_threshold
].copy()

filtered_anomalies = anomalies
if selected_label != "All":
    filtered_anomalies = filtered_anomalies[
        filtered_anomalies["anomaly_label"] == selected_label
    ]

visible_users = set(filtered_summary["user"])
if risk_threshold > 0:
    filtered_anomalies = filtered_anomalies[
        filtered_anomalies["user"].isin(visible_users)
    ]

total_users = int(filtered_summary["user"].nunique())
anomaly_count = int(
    (filtered_anomalies["anomaly_label"] == "Anomaly").sum()
)
high_risk_users = int(
    (filtered_summary["anomaly_rate"] >= 50).sum()
)
average_risk = float(filtered_summary["anomaly_rate"].mean())
if pd.isna(average_risk):
    average_risk = 0.0

with st.container(horizontal=True):
    st.metric(
        "Users monitored",
        f"{total_users:,}",
        border=True,
        height="stretch",
    )
    st.metric(
        "Anomaly detections",
        f"{anomaly_count:,}",
        border=True,
        height="stretch",
    )
    st.metric(
        "High-risk users",
        f"{high_risk_users:,}",
        border=True,
        height="stretch",
    )
    st.metric(
        "Average anomaly rate",
        f"{average_risk:.1f}%",
        border=True,
        height="stretch",
    )

left_chart, right_chart = st.columns(2)

with left_chart:
    with st.container(border=True):
        st.subheader("Detections over time")
        anomaly_trend = (
            filtered_anomalies[
                filtered_anomalies["anomaly_label"] == "Anomaly"
            ]
            .dropna(subset=["activity_date"])
            .groupby("activity_date")
            .size()
            .reset_index(name="Anomalies")
            .sort_values("activity_date")
        )
        if anomaly_trend.empty:
            st.info("No anomalies match the current filters.")
        else:
            st.line_chart(
                anomaly_trend,
                x="activity_date",
                y="Anomalies",
                alt="Anomaly detections over time",
            )

with right_chart:
    with st.container(border=True):
        st.subheader("Highest-risk users")
        top_users = (
            filtered_summary.sort_values(
                ["anomaly_rate", "minimum_anomaly_score"],
                ascending=[False, True],
            )
            .head(10)
            .set_index("user")
        )
        if top_users.empty:
            st.info("No users match the current risk threshold.")
        else:
            st.bar_chart(
                top_users,
                y="anomaly_rate",
                alt="Top employees by anomaly rate",
            )

with st.container(border=True):
    st.subheader("Employee risk summary")
    st.dataframe(
        filtered_summary.sort_values(
            ["anomaly_rate", "minimum_anomaly_score"],
            ascending=[False, True],
        ),
        hide_index=True,
        alt="Employee anomaly summary",
        height=420,
    )
