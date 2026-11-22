
import streamlit as st
import pandas as pd
import plotly.express as px
import os

# =====================================================
# 1. PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="Insider Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"


# =====================================================
# 2. CUSTOM CSS DESIGN
# =====================================================

st.markdown("""
<style>

/* Main background */
.stApp {
    background-color: #F4F7FB;
}

/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

/* Main headings */
h1 {
    color: #14213D;
    font-weight: 800;
    letter-spacing: -1px;
}

h2, h3 {
    color: #1D3557;
    font-weight: 700;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #14213D;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3,
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] label,
[data-testid="stSidebar"] span {
    color: white;
}

/* Sidebar radio buttons */
[data-testid="stSidebar"] [role="radiogroup"] label {
    background-color: #203653;
    padding: 10px;
    border-radius: 8px;
    margin-bottom: 6px;
}

/* Metric cards */
[data-testid="stMetric"] {
    background-color: white;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #E1E8F0;
    box-shadow: 0 3px 12px rgba(0,0,0,0.04);
}

[data-testid="stMetricLabel"] {
    color: #64748B;
    font-weight: 600;
}

[data-testid="stMetricValue"] {
    color: #1565C0;
    font-weight: 800;
}

/* Charts and dataframes */
[data-testid="stPlotlyChart"],
[data-testid="stDataFrame"] {
    background-color: white;
    border-radius: 12px;
    padding: 8px;
}

/* Buttons */
.stButton button {
    background-color: #1565C0;
    color: white;
    border-radius: 8px;
    border: none;
}

/* Divider */
hr {
    border-color: #DCE4EF;
}

/* Footer */
.footer {
    text-align: center;
    color: #64748B;
    font-size: 13px;
    padding: 20px;
}

</style>
""", unsafe_allow_html=True)


# =====================================================
# 3. LOAD PROJECT DATA
# =====================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "insider_threat_app")


@st.cache_data
def load_data():

    results_path = os.path.join(
        DATA_DIR, "anomaly_results.csv"
    )

    employees_path = os.path.join(
        DATA_DIR, "employee_summary.csv"
    )

    if not os.path.exists(results_path):
        raise FileNotFoundError(results_path)

    if not os.path.exists(employees_path):
        raise FileNotFoundError(employees_path)

    results = pd.read_csv(results_path)
    employees = pd.read_csv(employees_path)

    if "activity_date" in results.columns:
        results["activity_date"] = pd.to_datetime(
            results["activity_date"],
            errors="coerce"
        )

    return results, employees


try:
    results, employees = load_data()

except Exception as e:
    st.error(f"Unable to load project data: {e}")
    st.stop()


# =====================================================
# 4. DATA VALIDATION AND PREPARATION
# =====================================================

required_columns = ["user", "anomaly_prediction"]

missing_columns = [
    col for col in required_columns
    if col not in results.columns
]

if missing_columns:
    st.error(
        f"Required columns missing: {missing_columns}"
    )
    st.stop()

results["anomaly_prediction"] = pd.to_numeric(
    results["anomaly_prediction"],
    errors="coerce"
)

results = results.dropna(
    subset=["anomaly_prediction", "user"]
).copy()

results["anomaly_label"] = results[
    "anomaly_prediction"
].map({
    1: "Normal",
    -1: "Anomaly"
})

# Remove unexpected prediction values
results = results[
    results["anomaly_prediction"].isin([1, -1])
].copy()

total_records = len(results)

anomaly_count = int(
    (results["anomaly_prediction"] == -1).sum()
)

normal_count = int(
    (results["anomaly_prediction"] == 1).sum()
)

total_employees = results["user"].nunique()

flagged_employees = results.loc[
    results["anomaly_prediction"] == -1,
    "user"
].nunique()

anomaly_percentage = (
    anomaly_count / total_records * 100
    if total_records > 0 else 0
)


# =====================================================
# 5. SIDEBAR NAVIGATION
# =====================================================

st.sidebar.markdown("# 🛡️ THREAT INTEL")
st.sidebar.caption("INSIDER THREAT MONITORING")
st.sidebar.divider()

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Overview",
        "Anomaly Analysis",
        "Employee Monitoring",
        "Investigation Data"
    ]
)

st.sidebar.divider()

st.sidebar.markdown("### PROJECT INFORMATION")
st.sidebar.write("📊 Dataset: CERT r4.2")
st.sidebar.write("🤖 Model: Isolation Forest")
st.sidebar.write("🐍 Language: Python")
st.sidebar.write("📈 Framework: Streamlit")

st.sidebar.divider()

st.sidebar.caption(
    "Academic Project | 2026"
)


# =====================================================
# 6. MAIN HEADER
# =====================================================

st.markdown(
    "<h1>🛡️ Insider Threat Intelligence</h1>",
    unsafe_allow_html=True
)

st.markdown(
    "Employee Behaviour Analytics & Machine Learning "
    "Based Anomaly Detection"
)

st.caption(
    "CERT r4.2 Dataset  |  Isolation Forest  |  "
    "Cybersecurity Analytics"
)

st.divider()


# =====================================================
# 7. OVERVIEW PAGE
# =====================================================

if page == "Overview":

    st.header("📊 Security Overview")

    st.write(
        "A summary of employee activity and unusual "
        "behaviour detected by the machine learning model."
    )

    # KPI CARDS

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Total Records",
        f"{total_records:,}"
    )

    c2.metric(
        "Total Employees",
        f"{total_employees:,}"
    )

    c3.metric(
        "Anomalous Records",
        f"{anomaly_count:,}"
    )

    c4.metric(
        "Flagged Employees",
        f"{flagged_employees:,}"
    )

    st.write("")

    # ANOMALY RATE

    st.info(
        f"Anomaly rate: {anomaly_percentage:.2f}% "
        f"of all evaluated employee-day records."
    )

    st.divider()

    # PIE CHART

    st.subheader("Normal vs Anomalous Activity")

    chart_data = pd.DataFrame({
        "Activity": ["Normal", "Anomaly"],
        "Count": [normal_count, anomaly_count]
    })

    col1, col2 = st.columns([1.2, 1])

    with col1:

        fig = px.pie(
            chart_data,
            names="Activity",
            values="Count",
            hole=0.55,
            color="Activity",
            color_discrete_map={
                "Normal": "#2196F3",
                "Anomaly": "#EF5350"
            },
            title="Activity Distribution"
        )

        fig.update_layout(
            paper_bgcolor="white",
            plot_bgcolor="white",
            font_color="#14213D",
            legend_title_text="Activity"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with col2:

        st.markdown("### Detection Summary")

        st.metric(
            "Normal Activity",
            f"{normal_count:,}"
        )

        st.metric(
            "Anomalous Activity",
            f"{anomaly_count:,}"
        )

        st.metric(
            "Anomaly Percentage",
            f"{anomaly_percentage:.2f}%"
        )

        st.caption(
            "Anomalies represent unusual patterns, "
            "not confirmed malicious activity."
        )

    st.divider()

    # RECENT RECORDS

    st.subheader("Recent Prediction Records")

    st.dataframe(
        results.head(20),
        use_container_width=True,
        hide_index=True
    )


# =====================================================
# 8. ANOMALY ANALYSIS PAGE
# =====================================================

elif page == "Anomaly Analysis":

    st.header("🔍 Anomaly Analysis")

    st.info(
        "The Isolation Forest model identifies unusual "
        "activity patterns. An anomaly does not prove "
        "malicious behaviour."
    )

    # ANOMALY SCORE DISTRIBUTION

    if "anomaly_score" in results.columns:

        st.subheader("Anomaly Score Distribution")

        fig = px.histogram(
            results,
            x="anomaly_score",
            color="anomaly_label",
            nbins=50,
            opacity=0.8,
            color_discrete_map={
                "Normal": "#2196F3",
                "Anomaly": "#EF5350"
            },
            title="Distribution of Model Anomaly Scores"
        )

        fig.update_layout(
            paper_bgcolor="white",
            plot_bgcolor="white",
            font_color="#14213D",
            xaxis_title="Anomaly Score",
            yaxis_title="Number of Records"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        st.caption(
            "More negative Isolation Forest scores indicate "
            "more unusual observations. Scores are not probabilities."
        )

    st.divider()

    # DAILY ANOMALY TREND

    if "activity_date" in results.columns:

        st.subheader("Daily Anomaly Trend")

        daily = results.groupby(
            "activity_date"
        ).agg(
            Anomalies=(
                "anomaly_prediction",
                lambda x: (x == -1).sum()
            )
        ).reset_index()

        fig = px.line(
            daily,
            x="activity_date",
            y="Anomalies",
            markers=True,
            title="Daily Detected Anomalies",
            color_discrete_sequence=["#EF5350"]
        )

        fig.update_layout(
            paper_bgcolor="white",
            plot_bgcolor="white",
            font_color="#14213D",
            xaxis_title="Activity Date",
            yaxis_title="Anomaly Count"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        st.warning(
            "Activity date information is not available."
        )

    # MODEL SUMMARY

    st.divider()

    st.subheader("Model Summary")

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Records Evaluated",
            f"{total_records:,}"
        )

    with col2:
        st.metric(
            "Anomaly Detection Rate",
            f"{anomaly_percentage:.2f}%"
        )


# =====================================================
# 9. EMPLOYEE MONITORING PAGE
# =====================================================

elif page == "Employee Monitoring":

    st.header("👥 Employee Monitoring")

    st.write(
        "Review employee activity patterns and identify "
        "employees with a higher proportion of anomalous records."
    )

    # EMPLOYEE RANKING

    employee_table = results.groupby("user").agg(
        Total_Records=(
            "anomaly_prediction",
            "size"
        ),
        Anomalies=(
            "anomaly_prediction",
            lambda x: (x == -1).sum()
        )
    ).reset_index()

    employee_table["Anomaly_Rate"] = (
        employee_table["Anomalies"] /
        employee_table["Total_Records"] * 100
    ).round(2)

    employee_table = employee_table.sort_values(
        "Anomaly_Rate",
        ascending=False
    )

    st.subheader("Employee Anomaly Ranking")

    search_user = st.text_input(
        "🔎 Search Employee ID",
        placeholder="Enter employee ID..."
    )

    display_table = employee_table.copy()

    if search_user:
        display_table = display_table[
            display_table["user"].astype(str).str.contains(
                search_user,
                case=False,
                na=False
            )
        ]

    st.dataframe(
        display_table,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # EMPLOYEE SELECTION

    st.subheader("Individual Employee Investigation")

    selected_user = st.selectbox(
        "Select an employee",
        sorted(results["user"].astype(str).unique())
    )

    user_data = results[
        results["user"].astype(str) == selected_user
    ]

    user_anomalies = user_data[
        user_data["anomaly_prediction"] == -1
    ]

    a, b, c = st.columns(3)

    a.metric(
        "Total Records",
        f"{len(user_data):,}"
    )

    b.metric(
        "Anomalies",
        f"{len(user_anomalies):,}"
    )

    employee_rate = (
        len(user_anomalies) / len(user_data) * 100
        if len(user_data) > 0 else 0
    )

    c.metric(
        "Anomaly Rate",
        f"{employee_rate:.2f}%"
    )

    st.subheader(
        f"Activity Details: {selected_user}"
    )

    st.dataframe(
        user_data,
        use_container_width=True,
        hide_index=True
    )

    st.warning(
        "Employee rankings are based on model predictions "
        "and should not be treated as proof of misconduct."
    )


# =====================================================
# 10. INVESTIGATION DATA PAGE
# =====================================================

elif page == "Investigation Data":

    st.header("📁 Investigation Centre")

    st.write(
        "Review saved employee summaries and anomalous "
        "activity records for further investigation."
    )

    # EMPLOYEE SUMMARY

    st.subheader("Saved Employee Summary")

    st.dataframe(
        employees,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    # FLAGGED RECORDS

    st.subheader("Flagged Activity Records")

    flagged = results[
        results["anomaly_prediction"] == -1
    ].copy()

    st.metric(
        "Total Flagged Records",
        f"{len(flagged):,}"
    )

    # FILTER BY EMPLOYEE

    if len(flagged) > 0:

        employee_options = [
            "All Employees"
        ] + sorted(
            flagged["user"].astype(str).unique()
        )

        selected_employee = st.selectbox(
            "Filter by Employee",
            employee_options
        )

        if selected_employee != "All Employees":

            flagged = flagged[
                flagged["user"].astype(str)
                == selected_employee
            ]

        # DOWNLOAD DATA

        csv_data = flagged.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="⬇️ Download Investigation Records",
            data=csv_data,
            file_name="flagged_investigation_records.csv",
            mime="text/csv"
        )

        st.dataframe(
            flagged,
            use_container_width=True,
            hide_index=True
        )

    else:

        st.success(
            "No anomalous records found in the available results."
        )

    st.warning(
        "Flagged activity requires human review. "
        "Model predictions alone do not establish insider threats."
    )


# =====================================================
# 11. FOOTER
# =====================================================

st.divider()

st.markdown("""
<div class="footer">
    🛡️ Insider Threat Intelligence Dashboard<br>
    CERT r4.2 Dataset | Isolation Forest | Python & Streamlit<br>
    Academic Project | 2026<br>
    <b>Detected anomalies are candidates for investigation, not confirmed threats.</b>
</div>
""", unsafe_allow_html=True)