
import streamlit as st
import pandas as pd
import plotly.express as px
import os

# PAGE CONFIG
st.set_page_config(
    page_title="Insider Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Insider Threat Detection System")
st.markdown(
    "Anomaly detection dashboard using the CERT r4.2 dataset and Isolation Forest."
)

# LOAD DATA
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "insider_threat_app")

@st.cache_data
def load_data():
    results_path = os.path.join(DATA_DIR, "anomaly_results.csv")
    employees_path = os.path.join(DATA_DIR, "employee_summary.csv")

    if not os.path.exists(results_path):
        raise FileNotFoundError(results_path)

    if not os.path.exists(employees_path):
        raise FileNotFoundError(employees_path)

    results = pd.read_csv(results_path)
    employees = pd.read_csv(employees_path)

    if "activity_date" in results.columns:
        results["activity_date"] = pd.to_datetime(
            results["activity_date"], errors="coerce"
        )

    return results, employees

try:
    results, employees = load_data()
    st.success("Project data loaded successfully!")
except Exception as e:
    st.error(f"Could not load project data: {e}")
    st.stop()

# CHECK REQUIRED COLUMNS
if "anomaly_prediction" not in results.columns or "user" not in results.columns:
    st.error("Required columns are missing from anomaly_results.csv.")
    st.stop()

results["anomaly_label"] = results["anomaly_prediction"].map({
    1: "Normal",
    -1: "Anomaly"
})

total_records = len(results)
anomaly_count = (results["anomaly_prediction"] == -1).sum()
normal_count = (results["anomaly_prediction"] == 1).sum()
total_employees = results["user"].nunique()
flagged_employees = results.loc[
    results["anomaly_prediction"] == -1, "user"
].nunique()

# SIDEBAR
st.sidebar.title("Navigation")
page = st.sidebar.radio(
    "Select Dashboard",
    ["Overview", "Anomaly Analysis", "Employee Monitoring", "Investigation Data"]
)

# OVERVIEW
if page == "Overview":
    st.header("Project Overview")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records", f"{total_records:,}")
    c2.metric("Total Employees", f"{total_employees:,}")
    c3.metric("Anomalous Records", f"{anomaly_count:,}")
    c4.metric("Flagged Employees", f"{flagged_employees:,}")

    st.subheader("Normal vs Anomalous Activity")

    chart_data = pd.DataFrame({
        "Activity": ["Normal", "Anomaly"],
        "Count": [normal_count, anomaly_count]
    })

    fig = px.pie(
        chart_data,
        names="Activity",
        values="Count",
        title="Activity Distribution",
        hole=0.45
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Recent Prediction Records")
    st.dataframe(results.head(20), use_container_width=True)

# ANOMALY ANALYSIS
elif page == "Anomaly Analysis":
    st.header("Anomaly Analysis")
    st.info(
        "Anomaly predictions identify unusual activity. "
        "They do not prove malicious behaviour."
    )

    if "anomaly_score" in results.columns:
        fig = px.histogram(
            results,
            x="anomaly_score",
            color="anomaly_label",
            nbins=50,
            title="Distribution of Anomaly Scores"
        )
        st.plotly_chart(fig, use_container_width=True)

    if "activity_date" in results.columns:
        daily = results.groupby("activity_date").agg(
            Anomalies=("anomaly_prediction", lambda x: (x == -1).sum())
        ).reset_index()

        fig = px.line(
            daily,
            x="activity_date",
            y="Anomalies",
            title="Daily Anomaly Trend"
        )
        st.plotly_chart(fig, use_container_width=True)

# EMPLOYEE MONITORING
elif page == "Employee Monitoring":
    st.header("Employee Monitoring")

    employee_table = results.groupby("user").agg(
        Total_Records=("anomaly_prediction", "size"),
        Anomalies=("anomaly_prediction", lambda x: (x == -1).sum())
    ).reset_index()

    employee_table["Anomaly_Rate"] = (
        employee_table["Anomalies"] /
        employee_table["Total_Records"] * 100
    ).round(2)

    employee_table = employee_table.sort_values(
        "Anomaly_Rate", ascending=False
    )

    st.subheader("Employee Anomaly Ranking")
    st.dataframe(employee_table, use_container_width=True)

    selected_user = st.selectbox(
        "Select an employee",
        sorted(results["user"].dropna().unique())
    )

    user_data = results[results["user"] == selected_user]

    st.subheader(f"Activity Details: {selected_user}")
    st.write(f"Total records: {len(user_data)}")
    st.write(
        f"Anomalies: {(user_data['anomaly_prediction'] == -1).sum()}"
    )
    st.dataframe(user_data, use_container_width=True)

# INVESTIGATION DATA
elif page == "Investigation Data":
    st.header("Investigation Data")

    st.write(
        "Review model predictions and available investigation records. "
        "Flagged records require human investigation."
    )

    st.subheader("Saved Employee Summary")
    st.dataframe(employees, use_container_width=True)

    st.subheader("Flagged Activity Records")
    flagged = results[results["anomaly_prediction"] == -1]
    st.dataframe(flagged, use_container_width=True)

# FOOTER
st.divider()
st.caption(
    "Academic Project | CERT r4.2 | Isolation Forest | "
    "Anomalies are candidates for human investigation."
)
