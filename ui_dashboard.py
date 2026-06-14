"""
ui_dashboard.py — NIDS Streamlit Dashboard
============================================
UI Team deliverable. Connects to the Backend Team's FastAPI server.

Week 1:  Dashboard layout + live 50-flow table
Week 2:  SHAP detail view (Plotly bar), bandwidth/PPS line graph,
         attack-distribution donut chart
Week 3:  IP geolocation map (st.map), Red Alert banner, performance polish

Run:
    streamlit run ui_dashboard.py

Requirements (add to a separate ui_requirements.txt):
    streamlit>=1.35.0
    plotly>=5.22.0
    requests>=2.32.0
    pandas>=2.2.0
    numpy>=1.26.0

The FastAPI backend must be running (default: http://localhost:8000).
Configure via the sidebar or the UI_API_BASE environment variable.
"""

import os
import time
import math
import random
import datetime
from collections import deque

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# ─────────────────────────────────────────────────────────────────────────────
# Page config  (must be the very first Streamlit call)
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NIDS · Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Custom CSS — dark terminal aesthetic, red-alert animation
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ──────────────────────────────────────────────────────────────── */
[data-testid="stAppViewContainer"] { background: #050a0e; }
[data-testid="stSidebar"]          { background: #0b1520; border-right: 1px solid #1a2d42; }
[data-testid="stHeader"]           { background: transparent; }
.block-container                   { padding-top: 1.2rem; }

/* ── Metric tiles ───────────────────────────────────────────────────────── */
[data-testid="metric-container"] {
    background: #0b1520;
    border: 1px solid #1a2d42;
    border-radius: 6px;
    padding: 14px 18px;
}
[data-testid="stMetricValue"]  { color: #cde8f5; font-family: 'Courier New', monospace; }
[data-testid="stMetricLabel"]  { color: #3a5a72; font-size: 0.75rem; text-transform: uppercase; letter-spacing: .1em; }
[data-testid="stMetricDelta"]  { font-size: 0.8rem; }

/* ── Dataframe ──────────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] { border: 1px solid #1a2d42; border-radius: 6px; }

/* ── Red Alert banner ───────────────────────────────────────────────────── */
@keyframes flashRed {
    0%,100% { background: rgba(255,30,50,0.18); border-color: #ff1e32; }
    50%     { background: rgba(255,30,50,0.45); border-color: #ff8090; }
}
.red-alert {
    animation: flashRed 0.9s ease-in-out infinite;
    border: 2px solid #ff1e32;
    border-radius: 8px;
    padding: 14px 22px;
    color: #ff8090;
    font-family: 'Courier New', monospace;
    font-size: 1.15rem;
    font-weight: bold;
    letter-spacing: .06em;
    text-align: center;
    margin-bottom: 1rem;
}

/* ── Section dividers ────────────────────────────────────────────────────── */
hr { border-color: #1a2d42; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Constants & helpers
# ─────────────────────────────────────────────────────────────────────────────
# API base URL — override at launch with:  UI_API_BASE=http://your-host:8000 streamlit run ui_dashboard.py
DEFAULT_API = os.getenv("UI_API_BASE", "http://localhost:8000")

# Severity thresholds (mirrors backend alerting logic)
HIGH_SEVERITY_LABELS   = {"DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
                           "DoS slowloris", "Heartbleed", "Web Attack – Brute Force"}
MEDIUM_SEVERITY_LABELS = {"PortScan", "FTP-Patator", "SSH-Patator",
                           "Web Attack – XSS", "Web Attack – SQL Injection",
                           "Infiltration", "Bot"}

ALL_77_FEATURES = [
    "Flow Duration","Total Fwd Packets","Total Backward Packets",
    "Total Length of Fwd Packets","Total Length of Bwd Packets",
    "Fwd Packet Length Max","Fwd Packet Length Min",
    "Fwd Packet Length Mean","Fwd Packet Length Std",
    "Bwd Packet Length Max","Bwd Packet Length Min",
    "Bwd Packet Length Mean","Bwd Packet Length Std",
    "Flow Bytes/s","Flow Packets/s",
    "Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
    "Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
    "Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
    "Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags",
    "Fwd Header Length","Bwd Header Length",
    "Fwd Packets/s","Bwd Packets/s",
    "Min Packet Length","Max Packet Length",
    "Packet Length Mean","Packet Length Std","Packet Length Variance",
    "FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count",
    "ACK Flag Count","URG Flag Count","CWE Flag Count","ECE Flag Count",
    "Down/Up Ratio","Average Packet Size",
    "Avg Fwd Segment Size","Avg Bwd Segment Size","Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate",
    "Subflow Fwd Packets","Subflow Fwd Bytes",
    "Subflow Bwd Packets","Subflow Bwd Bytes",
    "Init_Win_bytes_forward","Init_Win_bytes_backward",
    "act_data_pkt_fwd","min_seg_size_forward",
    "Active Mean","Active Std","Active Max","Active Min",
    "Idle Mean","Idle Std","Idle Max","Idle Min",
]

# Key features shown in the manual predict form
KEY_FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "SYN Flag Count", "ACK Flag Count", "PSH Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
]


def _get_severity(label: str) -> str:
    if label in HIGH_SEVERITY_LABELS:
        return "HIGH"
    if label in MEDIUM_SEVERITY_LABELS:
        return "MEDIUM"
    if label == "BENIGN":
        return "—"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Session state initialisation
# ─────────────────────────────────────────────────────────────────────────────
def _init_state():
    defaults = {
        "flow_log":        deque(maxlen=50),   # last 50 flows for live table
        "bw_history":      deque(maxlen=120),  # (timestamp, bytes/s, pkts/s)
        "attack_counts":   {},                 # label → count
        "total_flows":     0,
        "total_attacks":   0,
        "latencies":       deque(maxlen=200),
        "selected_flow":   None,               # row clicked for SHAP detail
        "red_alert_label": None,               # label that triggered RED ALERT
        "geo_points":      [],                 # [{lat, lon, label}]
        "api_base":        DEFAULT_API,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ─────────────────────────────────────────────────────────────────────────────
# API client
# ─────────────────────────────────────────────────────────────────────────────

def api(path: str, method: str = "GET", payload: dict = None, timeout: int = 60):
    url = st.session_state.api_base.rstrip("/") + path
    try:
        if method == "POST":
            r = requests.post(url, json=payload or {}, timeout=timeout)
        else:
            r = requests.get(url, timeout=timeout)
        r.raise_for_status()
        return r.json(), None
    except requests.exceptions.ConnectionError:
        return None, "Cannot reach API — is the backend running?"
    except requests.exceptions.Timeout:
        return None, "Request timed out (Backend took too long to load models)"
    except Exception as exc:
        return None, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# GeoIP  (free ip-api.com — no key needed, rate-limited to 45 req/min)
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=3600, show_spinner=False)
def geolocate_ip(ip: str) -> tuple[float | None, float | None]:
    """Return (lat, lon) for an IP using ip-api.com, or (None, None) on failure."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,status",
                         timeout=3)
        data = r.json()
        if data.get("status") == "success":
            return float(data["lat"]), float(data["lon"])
    except Exception:
        pass
    return None, None


def _fake_src_ip() -> str:
    """Generate a random public-looking IP for demo when no real capture exists."""
    # Avoid RFC-1918 ranges
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 172, 192):
            continue
        return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ NIDS Sentinel")
    st.caption("Network Intrusion Detection System")
    st.divider()

    st.session_state.api_base = st.text_input(
        "API Base URL",
        value=st.session_state.api_base,
        help="Change here or set UI_API_BASE env var before launching: "
             "UI_API_BASE=http://host:8000 streamlit run ui_dashboard.py",
    )

    health_data, health_err = api("/health")
    if health_data:
        st.success("● API Online", icon="✅")
    else:
        st.error(f"● API Offline  \n{health_err}", icon="🔴")

    st.divider()
    st.markdown("**Pipeline Info**")
    st.caption("Stage 1 · XGBoost classifier")
    st.caption("Stage 2 · Isolation Forest fallback")
    st.caption("Explainability · SHAP")
    st.caption("Features · 77 CIC-IDS-2017 cols")
    st.divider()

    auto_refresh = st.toggle("Auto-refresh alerts (5 s)", value=False)
    alert_threshold = st.slider(
        "Red Alert threshold (confidence %)", 50, 100, 85
    )
    st.divider()
    st.caption(f"v3.0 · {datetime.datetime.now().strftime('%H:%M:%S')}")

# ─────────────────────────────────────────────────────────────────────────────
# Page header + Red Alert banner
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ NIDS · Sentinel Dashboard")
st.caption("CIC-IDS-2017 · XGBoost + Isolation Forest · Real-time intrusion detection")

if st.session_state.red_alert_label:
    st.markdown(
        f'<div class="red-alert">🚨 RED ALERT — {st.session_state.red_alert_label} DETECTED 🚨</div>',
        unsafe_allow_html=True,
    )

st.divider()

# ─────────────────────────────────────────────────────────────────────────────
# Tabs
# ─────────────────────────────────────────────────────────────────────────────
tab_overview, tab_predict, tab_alerts, tab_map, tab_labels = st.tabs([
    "📊 Overview", "⚡ Predict", "🚨 Alerts", "🗺️ IP Map", "🏷️ Labels"
])

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 · OVERVIEW
# ═════════════════════════════════════════════════════════════════════════════
with tab_overview:

    # ── Metric row ───────────────────────────────────────────────────────────
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Flows",     st.session_state.total_flows,
              delta=None)
    m2.metric("Attacks Detected", st.session_state.total_attacks,
              delta=f"{st.session_state.total_attacks} flagged" if st.session_state.total_attacks else None,
              delta_color="inverse")
    benign = st.session_state.total_flows - st.session_state.total_attacks
    m3.metric("Benign Flows",    benign)
    avg_lat = (
        round(sum(st.session_state.latencies) / len(st.session_state.latencies), 1)
        if st.session_state.latencies else 0
    )
    m4.metric("Avg Latency (ms)", avg_lat)

    st.markdown("---")

    # ── Charts row ───────────────────────────────────────────────────────────
    col_line, col_donut = st.columns([3, 2])

    with col_line:
        st.markdown("#### 📈 Real-time Bandwidth & Packets/s")
        if st.session_state.bw_history:
            bw_df = pd.DataFrame(
                list(st.session_state.bw_history),
                columns=["timestamp", "bytes_s", "pkts_s"]
            )
            bw_df["time"] = pd.to_datetime(bw_df["timestamp"], unit="s")
            fig_line = go.Figure()
            fig_line.add_trace(go.Scatter(
                x=bw_df["time"], y=bw_df["bytes_s"],
                name="Bytes/s", line=dict(color="#00d4ff", width=2),
                fill="tozeroy", fillcolor="rgba(0,212,255,0.08)"
            ))
            fig_line.add_trace(go.Scatter(
                x=bw_df["time"], y=bw_df["pkts_s"],
                name="Packets/s", line=dict(color="#00ff88", width=2),
                yaxis="y2"
            ))
            fig_line.update_layout(
                paper_bgcolor="#050a0e", plot_bgcolor="#0b1520",
                font=dict(color="#8fbcd4", family="Courier New"),
                margin=dict(l=0, r=0, t=10, b=0),
                legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="#1a2d42"),
                xaxis=dict(gridcolor="#1a2d42", showgrid=True),
                yaxis=dict(title=dict(text="Bytes/s", font=dict(color="#00d4ff")), gridcolor="#1a2d42"),
                yaxis2=dict(title=dict(text="Packets/s", font=dict(color="#00ff88")), overlaying="y", side="right", gridcolor="#1a2d42"),
            )
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("Run predictions to populate the bandwidth graph.", icon="ℹ️")

    with col_donut:
        st.markdown("#### 🍩 Attack Distribution")
        counts = st.session_state.attack_counts
        if counts:
            labels_list = list(counts.keys())
            values_list = list(counts.values())
            colors = (
                ["#00ff88"] * (1 if "BENIGN" in labels_list else 0) +
                ["#ff3d5a", "#ff8c00", "#ffdd00", "#00d4ff",
                 "#a855f7", "#ec4899", "#f97316", "#14b8a6"]
            )
            fig_donut = go.Figure(go.Pie(
                labels=labels_list, values=values_list,
                hole=0.55,
                marker=dict(colors=colors[:len(labels_list)],
                            line=dict(color="#050a0e", width=2)),
                textfont=dict(color="#cde8f5", family="Courier New"),
                hovertemplate="<b>%{label}</b><br>%{value} flows (%{percent})<extra></extra>",
            ))
            fig_donut.update_layout(
                paper_bgcolor="#050a0e",
                font=dict(color="#8fbcd4", family="Courier New"),
                margin=dict(l=0, r=0, t=10, b=0),
                legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=11)),
                height=280,
                annotations=[dict(
                    text=f"<b>{sum(values_list)}</b><br>flows",
                    x=0.5, y=0.5, font=dict(color="#cde8f5", size=14),
                    showarrow=False
                )]
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("Run predictions to populate the donut chart.", icon="ℹ️")

    # ── Live flow table (last 50) ─────────────────────────────────────────────
    st.markdown("---")
    st.markdown("#### 📋 Live Flow Log  _(last 50 flows)_")

    if st.session_state.flow_log:
        flow_df = pd.DataFrame(list(st.session_state.flow_log))
        # Colour-code the label column
        def _colour_label(val):
            if val == "BENIGN":
                return "color: #00ff88"
            if val == "Unknown/Novel Attack":
                return "color: #a855f7"
            return "color: #ff3d5a"

        styled = (
            flow_df.style
            .map(_colour_label, subset=["label"])
            .format({"confidence": "{:.1%}", "latency_ms": "{:.1f} ms"})
        )
        selected = st.dataframe(
            styled,
            use_container_width=True,
            height=380,
            on_select="rerun",
            selection_mode="single-row",
        )
        # Capture row selection for SHAP detail view
        rows = selected.selection.get("rows", []) if hasattr(selected, "selection") else []
        if rows:
            st.session_state.selected_flow = flow_df.iloc[rows[0]].to_dict()
    else:
        st.info("No flows logged yet. Run a prediction to populate the table.", icon="ℹ️")

    # ── SHAP Detail View (triggered by row click) ─────────────────────────────
    if st.session_state.selected_flow:
        flow = st.session_state.selected_flow
        st.markdown("---")
        st.markdown(f"#### 🔍 SHAP Detail View — `{flow.get('label', '?')}`")
        shap_vals = flow.get("shap_values", {})

        if shap_vals:
            shap_df = (
                pd.DataFrame(list(shap_vals.items()), columns=["Feature", "SHAP Value"])
                .sort_values("SHAP Value", key=abs, ascending=True)
            )
            fig_shap = go.Figure(go.Bar(
                x=shap_df["SHAP Value"],
                y=shap_df["Feature"],
                orientation="h",
                marker=dict(
                    color=shap_df["SHAP Value"].apply(
                        lambda v: "#ff3d5a" if v >= 0 else "#00ff88"
                    ),
                    line=dict(width=0),
                ),
                hovertemplate="<b>%{y}</b><br>SHAP: %{x:.4f}<extra></extra>",
            ))
            fig_shap.update_layout(
                paper_bgcolor="#050a0e", plot_bgcolor="#0b1520",
                font=dict(color="#8fbcd4", family="Courier New"),
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(title="SHAP Value (impact on prediction)",
                           gridcolor="#1a2d42", zeroline=True,
                           zerolinecolor="#3a5a72"),
                yaxis=dict(gridcolor="#1a2d42"),
                height=300,
                title=dict(
                    text=f"Top features pushing toward «{flow.get('label')}»",
                    font=dict(color="#cde8f5", size=13)
                ),
            )
            st.plotly_chart(fig_shap, use_container_width=True)
        else:
            st.info("No SHAP values for this flow (Unknown/Novel Attack or SHAP unavailable).")

        if st.button("✕ Clear selection"):
            st.session_state.selected_flow = None
            st.rerun()


# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 · PREDICT
# ═════════════════════════════════════════════════════════════════════════════
with tab_predict:
    st.markdown("#### ⚡ Submit a Flow for Prediction")
    st.caption("Fill key features below (remaining 62 default to 0), or load a real sample from the API.")

    load_col, _ = st.columns([1, 4])
    with load_col:
        if st.button("⬇ Load Sample from /sample"):
            sample_data, sample_err = api("/sample")
            if sample_data:
                # This grabs the data and forces the page to refresh with the new numbers
                st.session_state["_sample_payload"] = sample_data.get("payload", {})
                st.success("Sample loaded!")
                st.rerun()  
            else:
                st.error(sample_err)

    sample_payload = st.session_state.get("_sample_payload", {})

    # Build feature inputs in a 3-column grid
    feature_values = {}
    cols_per_row = 3
    rows = [KEY_FEATURES[i:i+cols_per_row] for i in range(0, len(KEY_FEATURES), cols_per_row)]
    for row_features in rows:
        cols = st.columns(cols_per_row)
        for col, feat in zip(cols, row_features):
            val_from_sample = float(st.session_state.get("_sample_payload", {}).get(feat, 0.0))
            
            feature_values[feat] = col.number_input(
                feat, 
                value=val_from_sample, 
                step=1.0,
                format="%g", 
                key=f"input_{feat}" 
            )

    # Fill remaining 77 features with 0 (or sample value)
    full_features = {f: float(sample_payload.get(f, 0.0)) for f in ALL_77_FEATURES}
    full_features.update(feature_values)

    st.markdown("")
    predict_btn = st.button("▶ Run Prediction", type="primary", use_container_width=False)

    if predict_btn:
        with st.spinner("Running inference…"):
            result, err = api("/predict", method="POST", payload=full_features)

        if err:
            st.error(f"Prediction failed: {err}")
        else:
            label      = result["label"]
            confidence = result["confidence"]
            is_attack  = result["is_attack"]
            latency    = result.get("latency_ms", 0)
            shap_vals  = result.get("shap_values", {})
            pipeline   = result.get("pipeline_used", "—")

            # ── Red Alert ─────────────────────────────────────────────────
            if is_attack and confidence * 100 >= alert_threshold:
                st.session_state.red_alert_label = label
                st.markdown(
                    f'<div class="red-alert">🚨 RED ALERT — {label} (conf: {confidence:.1%}) 🚨</div>',
                    unsafe_allow_html=True,
                )
            elif not is_attack:
                st.session_state.red_alert_label = None

            # ── Result card ───────────────────────────────────────────────
            colour = "#ff3d5a" if is_attack else "#00ff88"
            icon   = "🔴" if is_attack else "🟢"
            st.markdown(f"""
            <div style="background:#0b1520;border:1px solid {colour};border-radius:8px;
                        padding:18px 24px;margin:12px 0;">
                <span style="font-size:1.8rem;font-family:'Courier New';
                             color:{colour};font-weight:bold;">{icon} {label}</span>
                <span style="font-size:0.9rem;color:#8fbcd4;margin-left:18px;">
                    confidence: <b style="color:#cde8f5">{confidence:.1%}</b> &nbsp;|&nbsp;
                    pipeline: <b style="color:#00d4ff">{pipeline}</b> &nbsp;|&nbsp;
                    latency: <b style="color:#cde8f5">{latency} ms</b>
                </span>
            </div>
            """, unsafe_allow_html=True)

            # ── SHAP chart ────────────────────────────────────────────────
            if shap_vals:
                st.markdown("**Top SHAP Feature Contributions**")
                shap_df = (
                    pd.DataFrame(list(shap_vals.items()), columns=["Feature", "SHAP Value"])
                    .sort_values("SHAP Value", key=abs, ascending=True)
                )
                fig_s = go.Figure(go.Bar(
                    x=shap_df["SHAP Value"], y=shap_df["Feature"],
                    orientation="h",
                    marker=dict(
                        color=shap_df["SHAP Value"].apply(
                            lambda v: "#ff3d5a" if v >= 0 else "#00ff88"
                        )
                    ),
                    hovertemplate="<b>%{y}</b><br>SHAP: %{x:.4f}<extra></extra>",
                ))
                fig_s.update_layout(
                    paper_bgcolor="#050a0e", plot_bgcolor="#0b1520",
                    font=dict(color="#8fbcd4", family="Courier New"),
                    margin=dict(l=0, r=0, t=10, b=0), height=260,
                    xaxis=dict(gridcolor="#1a2d42", zeroline=True, zerolinecolor="#3a5a72"),
                    yaxis=dict(gridcolor="#1a2d42"),
                )
                st.plotly_chart(fig_s, use_container_width=True)
            else:
                st.info("No SHAP values returned (Unknown/Novel Attack or SHAP init failed).")

            # ── Update session state ──────────────────────────────────────
            src_ip = _fake_src_ip()
            flow_row = {
                "timestamp":    datetime.datetime.now().strftime("%H:%M:%S"),
                "src_ip":       src_ip,
                "label":        label,
                "confidence":   confidence,
                "is_attack":    is_attack,
                "severity":     _get_severity(label),
                "pipeline":     pipeline,
                "latency_ms":   latency,
                "shap_values":  shap_vals,
            }
            st.session_state.flow_log.appendleft(flow_row)
            st.session_state.total_flows   += 1
            st.session_state.latencies.append(latency)
            st.session_state.attack_counts[label] = (
                st.session_state.attack_counts.get(label, 0) + 1
            )
            if is_attack:
                st.session_state.total_attacks += 1

            # Bandwidth history (use Flow Bytes/s + Flow Packets/s from input)
            st.session_state.bw_history.append((
                time.time(),
                full_features.get("Flow Bytes/s", 0.0),
                full_features.get("Flow Packets/s", 0.0),
            ))

            # Geolocation
            lat, lon = geolocate_ip(src_ip)
            if lat and lon:
                st.session_state.geo_points.append({
                    "lat": lat, "lon": lon,
                    "label": label, "src_ip": src_ip
                })

            # Raw JSON expander
            with st.expander("Raw JSON response"):
                st.json(result)


# ═════════════════════════════════════════════════════════════════════════════
# TAB 3 · ALERTS
# ═════════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.markdown("#### 🚨 SIEM Alert Log  _(GET /alerts)_")

    a_col1, a_col2 = st.columns([1, 5])
    with a_col1:
        n_alerts = st.number_input("Last N alerts", min_value=1, max_value=500,
                                   value=20, step=5)
    with a_col2:
        st.markdown("")   # spacing
        fetch_btn = st.button("↻ Load Alerts", type="primary")

    if fetch_btn or auto_refresh:
        alerts_data, alerts_err = api(f"/alerts?n={int(n_alerts)}")
        if alerts_err:
            st.error(f"Could not load alerts: {alerts_err}")
        else:
            alerts_list = alerts_data.get("alerts", [])
            if alerts_list:
                alerts_df = pd.DataFrame(alerts_list)
                # Format timestamp
                if "timestamp" in alerts_df.columns:
                    alerts_df["timestamp"] = pd.to_datetime(
                        alerts_df["timestamp"], unit="s"
                    ).dt.strftime("%Y-%m-%d %H:%M:%S")
                # Reorder columns nicely
                desired_cols = ["timestamp", "label", "severity",
                                "confidence", "is_attack", "alert_id"]
                show_cols = [c for c in desired_cols if c in alerts_df.columns]
                st.dataframe(alerts_df[show_cols], use_container_width=True, height=420)
                st.caption(f"{len(alerts_list)} alert(s) loaded from SIEM log.")
            else:
                st.info("No alerts in the log yet — run some predictions first.", icon="ℹ️")

    if auto_refresh:
        time.sleep(5)
        st.rerun()


# ═════════════════════════════════════════════════════════════════════════════
# TAB 4 · IP MAP
# ═════════════════════════════════════════════════════════════════════════════
with tab_map:
    st.markdown("#### 🗺️ Source IP Geolocation Map")
    st.caption(
        "Each point represents a flow's source IP geocoded via ip-api.com. "
        "Red = attack, green = benign. Run predictions in the Predict tab to populate."
    )

    geo = st.session_state.geo_points
    if geo:
        geo_df = pd.DataFrame(geo)

        # st.map expects a DataFrame with 'lat'/'lon' columns
        # We also build a Plotly scatter_mapbox for colour-coding
        fig_map = px.scatter_mapbox(
            geo_df,
            lat="lat", lon="lon",
            color="label",
            hover_name="src_ip",
            hover_data={"label": True, "lat": False, "lon": False},
            color_discrete_map={
                "BENIGN": "#00ff88",
                "Unknown/Novel Attack": "#a855f7",
                **{lbl: "#ff3d5a" for lbl in HIGH_SEVERITY_LABELS},
                **{lbl: "#ff8c00" for lbl in MEDIUM_SEVERITY_LABELS},
            },
            zoom=1,
            height=500,
        )
        fig_map.update_layout(
            mapbox_style="carto-darkmatter",
            paper_bgcolor="#050a0e",
            font=dict(color="#8fbcd4", family="Courier New"),
            margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(bgcolor="rgba(11,21,32,0.8)", bordercolor="#1a2d42"),
        )
        st.plotly_chart(fig_map, use_container_width=True)

        # Fallback plain st.map
        with st.expander("Plain st.map view"):
            st.map(geo_df[["lat", "lon"]])

        st.caption(f"{len(geo_df)} geocoded IPs plotted.")
    else:
        st.info(
            "No geolocation data yet. Run predictions and the source IPs will appear here.",
            icon="🗺️"
        )
        # Show an empty world map as a placeholder
        fig_empty = go.Figure(go.Scattermapbox())
        fig_empty.update_layout(
            mapbox=dict(style="carto-darkmatter", zoom=0.8,
                        center=dict(lat=20, lon=0)),
            paper_bgcolor="#050a0e",
            margin=dict(l=0, r=0, t=0, b=0),
            height=400,
        )
        st.plotly_chart(fig_empty, use_container_width=True)


# ═════════════════════════════════════════════════════════════════════════════
# TAB 5 · LABELS
# ═════════════════════════════════════════════════════════════════════════════
with tab_labels:
    st.markdown("#### 🏷️ Model Label Registry  _(GET /labels)_")
    st.caption("Class names derived from the trained LabelEncoder — never hardcoded.")

    if st.button("↻ Fetch Labels", type="primary"):
        labels_data, labels_err = api("/labels")
        if labels_err:
            st.error(labels_err)
        else:
            all_labels = labels_data.get("labels", [])
            st.session_state["_fetched_labels"] = all_labels

    fetched = st.session_state.get("_fetched_labels")
    if fetched:
        st.success(f"{len(fetched)} classes loaded from LabelEncoder")

        # Split into benign / known-attack / novel
        benign_l  = [l for l in fetched if l == "BENIGN"]
        novel_l   = [l for l in fetched if "Novel" in l]
        attack_l  = [l for l in fetched if l not in benign_l and l not in novel_l]

        col_b, col_a, col_n = st.columns(3)
        with col_b:
            st.markdown("**✅ Benign**")
            for l in benign_l:
                st.markdown(f"`{l}`")
        with col_a:
            st.markdown("**🔴 Attack Classes**")
            for l in sorted(attack_l):
                sev = _get_severity(l)
                badge = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(sev, "⚪")
                st.markdown(f"{badge} `{l}`")
        with col_n:
            st.markdown("**🟣 Anomaly**")
            for l in novel_l:
                st.markdown(f"`{l}`")
    else:
        st.info("Click 'Fetch Labels' to load the model's class registry.", icon="ℹ️")
