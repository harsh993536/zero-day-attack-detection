import os
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Zero-Day AI | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

    /* Main background */
    .stApp {
        background-color: #f5f7fb;
    }

    /* Main content */
    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1500px;
    }

    /* Header */
    .main-header {
        background: linear-gradient(90deg, #0f172a, #1e3a8a);
        padding: 25px 30px;
        border-radius: 15px;
        margin-bottom: 25px;
        color: white;
        box-shadow: 0 5px 15px rgba(15, 23, 42, 0.15);
    }

    .main-header h1 {
        margin: 0;
        font-size: 32px;
        font-weight: 700;
    }

    .main-header p {
        margin-top: 8px;
        margin-bottom: 0;
        font-size: 15px;
        color: #dbeafe;
    }

    /* Metric cards */
    .metric-card {
        background: white;
        padding: 20px;
        border-radius: 14px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 3px 10px rgba(15, 23, 42, 0.06);
        text-align: center;
    }

    .metric-title {
        font-size: 14px;
        color: #64748b;
        font-weight: 600;
        margin-bottom: 8px;
    }

    .metric-value {
        font-size: 30px;
        font-weight: 700;
        color: #0f172a;
    }

    /* Section headings */
    .section-title {
        font-size: 21px;
        font-weight: 700;
        color: #0f172a;
        margin-top: 25px;
        margin-bottom: 12px;
    }

    /* Live status */
    .live-box {
        background: #ecfdf5;
        border: 1px solid #86efac;
        color: #166534;
        padding: 14px 18px;
        border-radius: 12px;
        font-weight: 600;
        margin-bottom: 20px;
    }

    .waiting-box {
        background: #fffbeb;
        border: 1px solid #fde68a;
        color: #92400e;
        padding: 14px 18px;
        border-radius: 12px;
        font-weight: 600;
        margin-bottom: 20px;
    }

    /* Alert cards */
    .critical-box {
    background: #fef2f2;
    border-left: 5px solid #dc2626;
    color: #991b1b;
    padding: 16px;
    border-radius: 10px;
    margin-bottom: 10px;
}

.medium-box {
    background: #fff7ed;
    border-left: 5px solid #f97316;
    color: #9a3412;
    padding: 16px;
    border-radius: 10px;
    margin-bottom: 10px;
}

.normal-box {
    background: #f0fdf4;
    border-left: 5px solid #16a34a;
    color: #166534;
    padding: 16px;
    border-radius: 10px;
    margin-bottom: 10px;
}
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #ffffff;
        border-right: 1px solid #e2e8f0;
    }

</style>
""", unsafe_allow_html=True)


# =========================================================
# AUTO REFRESH
# =========================================================

st_autorefresh(
    interval=5000,
    key="live_dashboard_refresh"
)


# =========================================================
# HEADER
# =========================================================

st.markdown(
    """
    <div class="main-header">
        <h1>🛡️ Zero-Day Attack Detection using Behavioral AI</h1>
        <p>Real-Time Security Operations Center (SOC) Dashboard | Behavioral Anomaly Detection</p>
    </div>
    """,
    unsafe_allow_html=True
)


# =========================================================
# DATA PATH
# =========================================================

LIVE_DATA_PATH = "data/processed/live_detection_results.csv"


# =========================================================
# LOAD DATA
# =========================================================

if os.path.exists(LIVE_DATA_PATH):

    df = pd.read_csv(LIVE_DATA_PATH)

    # Live traffic does not contain ground-truth labels
    if "Label" not in df.columns:
        df["Label"] = "LIVE"

else:

    df = pd.DataFrame()


# =========================================================
# LIVE DETECTION STATUS
# =========================================================

st.markdown("### 🟢 Live Detection Status")

if not df.empty and "Timestamp" in df.columns:

    latest_event = df["Timestamp"].iloc[-1]
    event_count = len(df)

    st.markdown(
        f"""
        <div class="live-box">
            🟢 LIVE DETECTION ACTIVE
            &nbsp;&nbsp;|&nbsp;&nbsp;
            Events Received: {event_count}
            &nbsp;&nbsp;|&nbsp;&nbsp;
            Last Event: {latest_event}
        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown(
        """
        <div class="waiting-box">
            🟡 LIVE DETECTION WAITING FOR DATA
        </div>
        """,
        unsafe_allow_html=True
    )


# =========================================================
# EMPTY DATA CHECK
# =========================================================

if df.empty:

    st.info(
        "No live detection data available yet. "
        "Start the Scapy capture using capture.py."
    )

    st.stop()


# =========================================================
# CLEAN DATA
# =========================================================

df = df.copy()

if "Risk Level" not in df.columns:
    df["Risk Level"] = "LOW"

if "Status" not in df.columns:
    df["Status"] = "NORMAL"


# =========================================================
# CALCULATE METRICS
# =========================================================

total_traffic = len(df)

normal_traffic = len(
    df[df["Status"] == "NORMAL"]
)

anomalies = len(
    df[df["Status"] == "ANOMALY"]
)

high_risk = len(
    df[
        (df["Risk Level"] == "HIGH") &
        (df["Status"] == "ANOMALY")
    ]
)


# =========================================================
# METRIC CARDS
# =========================================================

st.markdown(
    '<div class="section-title">📊 Security Overview</div>',
    unsafe_allow_html=True
)

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">TOTAL TRAFFIC</div>
            <div class="metric-value">{total_traffic}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col2:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">NORMAL TRAFFIC</div>
            <div class="metric-value">{normal_traffic}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col3:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">ANOMALIES</div>
            <div class="metric-value">{anomalies}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


with col4:

    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">HIGH RISK EVENTS</div>
            <div class="metric-value">{high_risk}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


# =========================================================
# DETECTION SUMMARY
# =========================================================

st.markdown(
    '<div class="section-title">📈 Detection Summary</div>',
    unsafe_allow_html=True
)

summary = pd.DataFrame({
    "Status": ["NORMAL", "ANOMALY"],
    "Count": [normal_traffic, anomalies]
})

st.bar_chart(
    summary.set_index("Status")
)


# =========================================================
# RISK DISTRIBUTION
# =========================================================

st.markdown(
    '<div class="section-title">⚠️ Risk Distribution</div>',
    unsafe_allow_html=True
)

risk_counts = (
    df["Risk Level"]
    .value_counts()
    .reindex(
        ["LOW", "MEDIUM", "HIGH"],
        fill_value=0
    )
)

risk_df = pd.DataFrame({
    "Risk Level": risk_counts.index,
    "Events": risk_counts.values
})

st.bar_chart(
    risk_df.set_index("Risk Level")
)


# =========================================================
# RISK FILTER
# =========================================================

st.markdown(
    '<div class="section-title">🔎 Filter Detection Results</div>',
    unsafe_allow_html=True
)

selected_risk = st.selectbox(
    "Select Risk Level",
    ["ALL", "LOW", "MEDIUM", "HIGH"]
)

if selected_risk == "ALL":

    filtered_df = df.copy()

else:

    filtered_df = df[
        df["Risk Level"] == selected_risk
    ].copy()


# =========================================================
# RECENT DETECTION RESULTS
# =========================================================

st.markdown(
    '<div class="section-title">🧠 Recent Detection Results</div>',
    unsafe_allow_html=True
)

display_columns = [
    "Timestamp",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Status",
    "Anomaly Score",
    "Risk Score",
    "Risk Level"
]

available_columns = [
    col for col in display_columns
    if col in filtered_df.columns
]

recent_df = filtered_df[
    available_columns
].tail(50)

st.dataframe(
    recent_df,
    use_container_width=True,
    hide_index=True
)


# =========================================================
# HIGH-RISK ALERTS
# =========================================================

st.markdown(
    '<div class="section-title">🚨 High-Risk Security Alerts</div>',
    unsafe_allow_html=True
)

high_risk_df = df[
    (df["Risk Level"] == "HIGH") &
    (df["Status"] == "ANOMALY")
].copy()


if high_risk_df.empty:

    st.markdown(
        """
        <div class="normal-box">
            🟢 No high-risk anomalies detected.
        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown(
        f"""
        <div class="critical-box">
            🔴 <b>{len(high_risk_df)}</b>
            high-risk anomalous event(s) detected.
        </div>
        """,
        unsafe_allow_html=True
    )

    alert_columns = [
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Destination Port",
        "Protocol",
        "Anomaly Score",
        "Risk Score",
        "Risk Level"
    ]

    available_alert_columns = [
        col for col in alert_columns
        if col in high_risk_df.columns
    ]

    st.dataframe(
        high_risk_df[
            available_alert_columns
        ].tail(20),
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# SOC SUMMARY
# =========================================================

st.markdown(
    '<div class="section-title">🛡️ SOC Security Summary</div>',
    unsafe_allow_html=True
)

critical_alerts = len(
    df[
        (df["Risk Level"] == "HIGH") &
        (df["Status"] == "ANOMALY")
    ]
)

medium_risk = len(
    df[
        (df["Risk Level"] == "MEDIUM") &
        (df["Status"] == "ANOMALY")
    ]
)

low_risk = len(
    df[
        (df["Risk Level"] == "LOW") &
        (df["Status"] == "ANOMALY")
    ]
)

soc1, soc2, soc3 = st.columns(3)


with soc1:

    st.markdown(
        f"""
        <div class="critical-box">
            🔴 <b>Critical Alerts</b><br>
            {critical_alerts} anomalous high-risk events
        </div>
        """,
        unsafe_allow_html=True
    )


with soc2:

    st.markdown(
        f"""
        <div class="medium-box">
            🟠 <b>Medium Risk</b><br>
            {medium_risk} anomalous medium-risk events
        </div>
        """,
        unsafe_allow_html=True
    )


with soc3:

    st.markdown(
        f"""
        <div class="normal-box">
            🟢 <b>Low Risk</b><br>
            {low_risk} anomalous low-risk events
        </div>
        """,
        unsafe_allow_html=True
    )


# =========================================================
# NETWORK INFORMATION
# =========================================================

st.markdown(
    '<div class="section-title">🌐 Network Information</div>',
    unsafe_allow_html=True
)

network_columns = [
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol"
]

available_network_columns = [
    col for col in network_columns
    if col in df.columns
]

st.dataframe(
    df[
        available_network_columns
    ].tail(30),
    use_container_width=True,
    hide_index=True
)


# =========================================================
# ANOMALY SCORE
# =========================================================

if "Anomaly Score" in df.columns:

    st.markdown(
        '<div class="section-title">📉 Anomaly Score Timeline</div>',
        unsafe_allow_html=True
    )

    score_df = df[
        ["Anomaly Score"]
    ].tail(100)

    st.line_chart(
        score_df
    )


# =========================================================
# FOOTER
# =========================================================

st.markdown("---")

st.markdown(
    """
    <div style="
        text-align:center;
        color:#64748b;
        font-size:13px;
        padding:10px;
    ">
        🛡️ Zero-Day Attack Detection using Behavioral AI
        <br>
        Isolation Forest + Scapy + Streamlit
        <br>
        Real-Time Behavioral Anomaly Monitoring
    </div>
    """,
    unsafe_allow_html=True
)