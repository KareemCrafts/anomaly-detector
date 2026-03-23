import pandas as pd
from sklearn.ensemble import IsolationForest
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import io
import re
from datetime import datetime

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Blue Team | Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #0a0e1a;
    color: #c9d1d9;
}

.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1117 60%, #0a1628 100%);
}

h1, h2, h3 {
    font-family: 'Share Tech Mono', monospace !important;
    color: #00ffe1 !important;
    letter-spacing: 2px;
}

.metric-box {
    background: rgba(0, 255, 225, 0.05);
    border: 1px solid rgba(0, 255, 225, 0.2);
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
}
.metric-box::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #00ffe1, transparent);
}
.metric-number {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.5rem;
    color: #00ffe1;
    line-height: 1;
}
.metric-label {
    font-size: 0.85rem;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 6px;
}
.metric-number.red { color: #ff4c4c; }
.metric-number.yellow { color: #ffd700; }

.alert-box {
    background: rgba(255, 76, 76, 0.08);
    border-left: 3px solid #ff4c4c;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 6px 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.82rem;
}
.normal-box {
    background: rgba(0, 255, 225, 0.04);
    border-left: 3px solid #00ffe1;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 6px 0;
    font-size: 0.82rem;
}

.section-header {
    font-family: 'Share Tech Mono', monospace;
    color: #00ffe1;
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 3px;
    border-bottom: 1px solid rgba(0,255,225,0.15);
    padding-bottom: 8px;
    margin: 24px 0 16px 0;
}

div[data-testid="stFileUploader"] {
    background: rgba(0,255,225,0.03);
    border: 1px dashed rgba(0,255,225,0.3);
    border-radius: 8px;
    padding: 10px;
}

div[data-testid="stMetric"] {
    background: rgba(0,255,225,0.04);
    border: 1px solid rgba(0,255,225,0.15);
    border-radius: 8px;
    padding: 12px;
}
div[data-testid="stMetricValue"] { color: #00ffe1 !important; }

.stDataFrame { border: 1px solid rgba(0,255,225,0.15) !important; border-radius: 8px; }

.tag {
    display: inline-block;
    background: rgba(255,76,76,0.15);
    border: 1px solid rgba(255,76,76,0.4);
    color: #ff4c4c;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 0.75rem;
    font-family: 'Share Tech Mono', monospace;
    margin-right: 4px;
}
</style>
""", unsafe_allow_html=True)


# ── Data helpers ──────────────────────────────────────────────────────────────

def generate_sample_logs():
    logs = []
    for i in range(200):
        logs.append({
            "time": f"2024-01-15 09:{i % 60:02d}:00",
            "ip": f"192.168.1.{(i % 10) + 1}",
            "event": "login_success",
            "attempts": 1,
            "user": f"user_{(i % 5) + 1}",
        })
    for i in range(20):
        logs.append({
            "time": f"2024-01-15 03:{i % 60:02d}:00",
            "ip": "45.33.32.156",
            "event": "login_failed",
            "attempts": 50 + i,
            "user": "root",
        })
    logs.append({
        "time": "2024-01-15 03:00:00",
        "ip": "192.168.1.99",
        "event": "login_success",
        "attempts": 1,
        "user": "admin",
    })
    return pd.DataFrame(logs)


def parse_uploaded_log(file_bytes: bytes) -> pd.DataFrame:
    """
    Supports:
    1. CSV with columns: time, ip, event, attempts
    2. Windows Event Log CSV (exported via PowerShell or Event Viewer)
    3. Linux auth.log / syslog plain text
    """
    text = file_bytes.decode("utf-8", errors="ignore")

    # ── 1. Try CSV ──────────────────────────────────────────────────────────
    try:
        df = pd.read_csv(io.StringIO(text))
        cols = [c.lower().strip() for c in df.columns]
        df.columns = cols

        # Already in our format
        if {"time", "ip", "event", "attempts"}.issubset(set(cols)):
            return df

        # Windows Event Log exported via PowerShell
        # Columns: time, event_id, message
        if "time" in cols and "event_id" in cols and "message" in cols:
            rows = []
            # Windows Security Event IDs
            # 4624 = successful logon, 4625 = failed logon, 4648 = explicit logon
            FAILED_IDS  = {4625, 4771, 4776}
            SUCCESS_IDS = {4624, 4648}

            ip_pattern  = re.compile(r"Source Network Address[:\s]+([0-9a-fA-F.:]+)")
            user_pattern = re.compile(r"Account Name[:\s]+([\w\\.-]+)")

            for _, row in df.iterrows():
                eid     = int(str(row.get("event_id", 0)).strip()) if str(row.get("event_id","")).strip().isdigit() else 0
                msg     = str(row.get("message", ""))
                ip_m    = ip_pattern.search(msg)
                user_m  = user_pattern.search(msg)
                ip      = ip_m.group(1) if ip_m else "unknown"
                user    = user_m.group(1) if user_m else "unknown"

                if eid in FAILED_IDS:
                    event = "login_failed"
                elif eid in SUCCESS_IDS:
                    event = "login_success"
                else:
                    continue   # skip unrelated events

                rows.append({
                    "time":     row.get("time", ""),
                    "ip":       ip,
                    "event":    event,
                    "attempts": 1,
                    "user":     user,
                })

            if rows:
                out = pd.DataFrame(rows)
                out["time"] = pd.to_datetime(out["time"], errors="coerce")
                out = out.dropna(subset=["time"])
                # Aggregate per minute + IP
                out["time_bucket"] = out["time"].dt.floor("min")
                agg = (out.groupby(["time_bucket", "ip", "event", "user"])
                           .size().reset_index(name="attempts"))
                agg = agg.rename(columns={"time_bucket": "time"})
                agg["time"] = agg["time"].astype(str)
                return agg

        # Windows Event Viewer CSV (different column names)
        # Columns vary but usually: Date and Time, Source, Event ID, ...
        date_col  = next((c for c in cols if "date" in c or "time" in c), None)
        eid_col   = next((c for c in cols if "event" in c and "id" in c), None)
        if date_col and eid_col:
            FAILED_IDS  = {"4625", "4771", "4776"}
            SUCCESS_IDS = {"4624", "4648"}
            rows = []
            for _, row in df.iterrows():
                eid = str(row.get(eid_col, "")).strip()
                if eid in FAILED_IDS:
                    event = "login_failed"
                elif eid in SUCCESS_IDS:
                    event = "login_success"
                else:
                    continue
                rows.append({
                    "time":     row.get(date_col, ""),
                    "ip":       "windows_host",
                    "event":    event,
                    "attempts": 1,
                    "user":     "unknown",
                })
            if rows:
                out = pd.DataFrame(rows)
                out["time"] = pd.to_datetime(out["time"], errors="coerce")
                out = out.dropna(subset=["time"])
                out["time_bucket"] = out["time"].dt.floor("min")
                agg = (out.groupby(["time_bucket", "ip", "event", "user"])
                           .size().reset_index(name="attempts"))
                agg = agg.rename(columns={"time_bucket": "time"})
                agg["time"] = agg["time"].astype(str)
                return agg

    except Exception:
        pass

    # ── 2. Linux auth.log plain text ────────────────────────────────────────
    pattern = re.compile(
        r"(\w{3}\s+\d+\s+\d+:\d+:\d+).*?"
        r"(Failed password|Accepted password|Invalid user)"
        r".*?from\s+([\d.]+)",
        re.IGNORECASE,
    )
    rows = []
    for line in text.splitlines():
        m = pattern.search(line)
        if m:
            ts, event_raw, ip = m.groups()
            event = "login_failed" if "Failed" in event_raw or "Invalid" in event_raw else "login_success"
            rows.append({"time": ts + " 2024", "ip": ip, "event": event, "attempts": 1, "user": "unknown"})
    if rows:
        df2 = pd.DataFrame(rows)
        df2["time"] = pd.to_datetime(df2["time"], format="%b %d %H:%M:%S %Y", errors="coerce")
        df2 = df2.dropna(subset=["time"])
        df2["time_bucket"] = df2["time"].dt.floor("min")
        agg = (df2.groupby(["time_bucket", "ip", "event", "user"])
                   .size().reset_index(name="attempts"))
        agg = agg.rename(columns={"time_bucket": "time"})
        agg["time"] = agg["time"].astype(str)
        return agg

    return pd.DataFrame()


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["time"] = pd.to_datetime(df["time"], errors="coerce")
    df = df.dropna(subset=["time"])
    df["hour"] = df["time"].dt.hour
    df["is_failed"] = (df["event"] == "login_failed").astype(int)
    df["is_offhours"] = ((df["hour"] < 6) | (df["hour"] > 22)).astype(int)
    return df


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    features = df[["hour", "attempts", "is_failed", "is_offhours"]]
    model = IsolationForest(contamination=0.1, random_state=42)
    df = df.copy()
    df["anomaly_score"] = model.fit_predict(features)
    df["is_anomaly"] = df["anomaly_score"] == -1
    return df


def explain(row) -> str:
    reasons = []
    if row["is_failed"]:
        reasons.append("login failures")
    if row["is_offhours"]:
        reasons.append("off-hours (3am-6am)")
    if row["attempts"] > 10:
        reasons.append(f"high attempts ({int(row['attempts'])})")
    return " | ".join(reasons) if reasons else "unusual pattern"


# ── UI ────────────────────────────────────────────────────────────────────────

st.markdown("# 🛡️ BLUE TEAM // ANOMALY DETECTOR")
st.markdown("<p style='color:#8b949e;font-size:0.9rem;letter-spacing:1px;margin-top:-12px;'>AI-powered log threat analysis</p>", unsafe_allow_html=True)
st.divider()

# Sidebar: data source
with st.sidebar:
    st.markdown("### 📂 DATA SOURCE")
    source = st.radio("", ["Use demo data", "Upload my own log file"], label_visibility="collapsed")
    uploaded = None
    if source == "Upload my own log file":
        st.markdown("**Supported formats:**")
        st.markdown("- Linux `auth.log` / syslog\n- CSV with columns: `time, ip, event, attempts`")
        uploaded = st.file_uploader("Drop log file here", type=["log", "txt", "csv"])
    st.divider()
    st.markdown("### ⚙️ SETTINGS")
    contamination = st.slider("Anomaly sensitivity", 0.01, 0.3, 0.1, 0.01,
                               help="Higher = more alerts. Lower = only obvious threats.")

# Load data
if source == "Upload my own log file" and uploaded is not None:
    raw = parse_uploaded_log(uploaded.read())
    if raw.empty:
        st.error("Could not parse this file. Make sure it's a Linux auth.log or a CSV with columns: time, ip, event, attempts")
        st.stop()
    df = raw
    st.success(f"Loaded {len(df)} log entries from **{uploaded.name}**")
else:
    df = generate_sample_logs()
    st.info("Using demo data. Upload your own log file from the sidebar to analyze real logs.")

# Process
df = extract_features(df)
df = detect_anomalies(df)
df["reason"] = df.apply(lambda r: explain(r) if r["is_anomaly"] else "", axis=1)

anomalies = df[df["is_anomaly"]]
normal = df[~df["is_anomaly"]]

# ── Metrics ───────────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""<div class="metric-box">
        <div class="metric-number">{len(df)}</div>
        <div class="metric-label">Total Events</div></div>""", unsafe_allow_html=True)
with c2:
    st.markdown(f"""<div class="metric-box">
        <div class="metric-number red">{len(anomalies)}</div>
        <div class="metric-label">Anomalies</div></div>""", unsafe_allow_html=True)
with c3:
    st.markdown(f"""<div class="metric-box">
        <div class="metric-number yellow">{anomalies['ip'].nunique()}</div>
        <div class="metric-label">Suspicious IPs</div></div>""", unsafe_allow_html=True)
with c4:
    risk = "HIGH" if len(anomalies) > 15 else "MEDIUM" if len(anomalies) > 5 else "LOW"
    color = "red" if risk == "HIGH" else "yellow" if risk == "MEDIUM" else ""
    st.markdown(f"""<div class="metric-box">
        <div class="metric-number {color}">{risk}</div>
        <div class="metric-label">Threat Level</div></div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Timeline chart ────────────────────────────────────────────────────────────
st.markdown('<p class="section-header">// Activity Timeline</p>', unsafe_allow_html=True)

fig = go.Figure()
fig.add_trace(go.Scatter(
    x=normal["time"], y=normal["attempts"],
    mode="markers",
    name="Normal",
    marker=dict(color="rgba(0,255,225,0.5)", size=7, symbol="circle"),
))
fig.add_trace(go.Scatter(
    x=anomalies["time"], y=anomalies["attempts"],
    mode="markers",
    name="Anomaly",
    marker=dict(color="#ff4c4c", size=12, symbol="x", line=dict(width=2, color="#ff4c4c")),
    text=anomalies["reason"],
    hovertemplate="<b>%{x}</b><br>IP: %{customdata}<br>Attempts: %{y}<br>Reason: %{text}<extra></extra>",
    customdata=anomalies["ip"],
))
fig.update_layout(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(10,14,26,0.8)",
    font=dict(family="Share Tech Mono", color="#8b949e"),
    legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(0,255,225,0.2)", borderwidth=1),
    xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zerolinecolor="rgba(0,255,225,0.1)"),
    yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zerolinecolor="rgba(0,255,225,0.1)", title="Login Attempts"),
    hovermode="closest",
    height=380,
    margin=dict(l=20, r=20, t=20, b=20),
)
st.plotly_chart(fig, use_container_width=True)

# ── Two columns: Top IPs + Hourly heatmap ─────────────────────────────────────
col_a, col_b = st.columns(2)

with col_a:
    st.markdown('<p class="section-header">// Top Suspicious IPs</p>', unsafe_allow_html=True)
    if not anomalies.empty:
        ip_counts = anomalies.groupby("ip")["attempts"].sum().sort_values(ascending=True).tail(8)
        fig2 = go.Figure(go.Bar(
            x=ip_counts.values, y=ip_counts.index,
            orientation="h",
            marker=dict(
                color=ip_counts.values,
                colorscale=[[0, "#1a2a3a"], [1, "#ff4c4c"]],
                showscale=False,
            ),
        ))
        fig2.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(10,14,26,0.8)",
            font=dict(family="Share Tech Mono", color="#8b949e"),
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)", title="Total Attempts"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            height=280, margin=dict(l=10, r=10, t=10, b=10),
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No anomalies detected.")

with col_b:
    st.markdown('<p class="section-header">// Activity by Hour</p>', unsafe_allow_html=True)
    hourly = df.groupby(["hour", "is_anomaly"]).size().reset_index(name="count")
    fig3 = px.bar(
        hourly, x="hour", y="count", color="is_anomaly",
        color_discrete_map={True: "#ff4c4c", False: "rgba(0,255,225,0.4)"},
        labels={"is_anomaly": "Anomaly", "hour": "Hour of Day", "count": "Events"},
        barmode="stack",
    )
    fig3.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(10,14,26,0.8)",
        font=dict(family="Share Tech Mono", color="#8b949e"),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", dtick=2),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
        height=280, margin=dict(l=10, r=10, t=10, b=10),
    )
    st.plotly_chart(fig3, use_container_width=True)

# ── Flagged events table ──────────────────────────────────────────────────────
st.markdown('<p class="section-header">// Flagged Events</p>', unsafe_allow_html=True)

if anomalies.empty:
    st.success("No anomalies detected in this log set.")
else:
    display_cols = [c for c in ["time", "ip", "user", "event", "attempts", "reason"] if c in anomalies.columns]
    styled = anomalies[display_cols].reset_index(drop=True)
    st.dataframe(
        styled,
        use_container_width=True,
        column_config={
            "time": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss"),
            "ip": st.column_config.TextColumn("Source IP"),
            "event": st.column_config.TextColumn("Event"),
            "attempts": st.column_config.NumberColumn("Attempts", format="%d"),
            "reason": st.column_config.TextColumn("Detection Reason"),
        },
        hide_index=True,
    )

# ── Download results ──────────────────────────────────────────────────────────
if not anomalies.empty:
    csv = anomalies[display_cols].to_csv(index=False)
    st.download_button(
        label="⬇ Export Flagged Events as CSV",
        data=csv,
        file_name="flagged_events.csv",
        mime="text/csv",
    )

st.divider()
st.markdown("<p style='text-align:center;color:#3d444d;font-size:0.75rem;font-family:Share Tech Mono'>BLUE TEAM ANOMALY DETECTOR // ISOLATION FOREST MODEL // FOR EDUCATIONAL USE</p>", unsafe_allow_html=True)
