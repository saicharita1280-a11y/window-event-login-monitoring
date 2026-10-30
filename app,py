"""Local Windows Event Log monitoring dashboard."""
from __future__ import annotations

from datetime import date
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from detection_rules import REQUIRED_COLUMNS, SEVERITY_ORDER, analyze_events, validate_events

APP_DIR = Path(__file__).resolve().parent
LOCAL_CSV = APP_DIR / "windows_events.csv"
SAMPLE_CSV = APP_DIR / "sample_events.csv"

st.set_page_config(page_title="Windows Event Monitor", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp { background: #0b1220; color: #e6edf7; }
[data-testid="stSidebar"] { background: #101a2b; }
[data-testid="stMetric"] { background: linear-gradient(145deg,#142238,#101a2b); border: 1px solid #263a57; padding: 16px; border-radius: 12px; }
[data-testid="stMetricValue"] { color: #eaf3ff; }
.block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Windows Event Monitor")
st.caption("Local event review and transparent detection rules · Detection signals are leads for investigation, not confirmed incidents.")

with st.sidebar:
    st.header("Data source")
    default_source = "Collected CSV" if LOCAL_CSV.exists() else "Synthetic demo"
    source_mode = st.radio("Choose events", ["Collected CSV", "Upload CSV", "Synthetic demo"],
                           index=["Collected CSV", "Upload CSV", "Synthetic demo"].index(default_source))
    uploaded = None
    if source_mode == "Upload CSV":
        uploaded = st.file_uploader("Upload event CSV", type=["csv"])
    st.divider()
    st.subheader("Detection tuning")
    threshold = st.number_input("Failed logons from one source", min_value=2, max_value=100, value=5)
    window_minutes = st.number_input("Time window (minutes)", min_value=1, max_value=1440, value=10)
    st.caption("Burst detection is skipped when source fields are missing. This dashboard does not change system settings or block activity.")


def load_frame() -> tuple[pd.DataFrame | None, str, str | None]:
    try:
        if source_mode == "Collected CSV":
            if not LOCAL_CSV.exists():
                return None, "", f"No collected file found at {LOCAL_CSV.name}. Run the PowerShell collector or choose Synthetic demo."
            return pd.read_csv(LOCAL_CSV), "Local collected CSV (contents are not independently verified)", None
        if source_mode == "Upload CSV":
            if uploaded is None:
                return None, "", None
            return pd.read_csv(uploaded), "User-uploaded CSV (origin not independently verified)", None
        return pd.read_csv(SAMPLE_CSV), "SYNTHETIC DEMONSTRATION DATA — not real Windows events", None
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError, OSError) as exc:
        return None, "", f"Could not read the selected CSV: {exc}"


raw, provenance, load_error = load_frame()
if load_error:
    st.error(load_error)
    st.stop()
if raw is None:
    st.info("Choose a CSV file in the sidebar, or select Synthetic demo to explore the dashboard.")
    st.stop()
try:
    normalized, warnings = validate_events(raw)
except ValueError as exc:
    st.error(f"CSV validation failed: {exc}")
    st.info("Required columns: " + ", ".join(sorted(REQUIRED_COLUMNS)))
    st.stop()
except Exception as exc:
    st.error(f"Could not process this CSV safely: {exc}")
    st.stop()

if warnings:
    for warning in warnings:
        st.warning(warning)

try:
    events = analyze_events(normalized, int(threshold), int(window_minutes))
except (ValueError, KeyError) as exc:
    st.error(f"Detection rules could not run: {exc}")
    st.stop()

st.info(f"**Data provenance:** {provenance} · {len(events):,} rows loaded. The collector produces a point-in-time snapshot, not a live stream.")

# Filters
with st.expander("🔎 Search and filter", expanded=True):
    categories = sorted(events["log_category"].replace("", "(unspecified)").unique().tolist())
    severities = [s for s in SEVERITY_ORDER if s in events["severity"].astype(str).unique()]
    col_category, col_severity, col_search = st.columns([1, 1, 2])
    selected_categories = col_category.multiselect("Log category", categories, default=categories)
    selected_severity = col_severity.multiselect("Severity", severities, default=severities)
    query = col_search.text_input("Search event messages", placeholder="Search message, provider, event ID…")
    valid_dates = events["timestamp"].dropna()
    if not valid_dates.empty:
        earliest, latest = valid_dates.min().date(), valid_dates.max().date()
        selected_dates = st.date_input("Date range", value=(earliest, latest), min_value=earliest, max_value=latest)
    else:
        selected_dates = ()

filtered = events.copy()
category_values = filtered["log_category"].replace("", "(unspecified)")
filtered = filtered[category_values.isin(selected_categories)]
filtered = filtered[filtered["severity"].astype(str).isin(selected_severity)]
if query.strip():
    needle = query.strip()
    searchable = filtered[["message", "provider", "event_id", "description", "computer_name"]].astype(str).agg(" ".join, axis=1)
    filtered = filtered[searchable.str.contains(needle, case=False, na=False, regex=False)]
if len(selected_dates) == 2:
    start_date, end_date = selected_dates
    filtered = filtered[filtered["timestamp"].isna() | filtered["timestamp"].dt.date.between(start_date, end_date)]

count = len(filtered)
suspicious = filtered[filtered["suspicious"]]
security_count = int(filtered["log_category"].str.casefold().eq("security").sum())
failed_count = int(filtered["event_id"].eq(4625).sum())

st.subheader("Overview · filtered events")
metrics = st.columns(4)
metrics[0].metric("Total events", f"{count:,}")
metrics[1].metric("Security events", f"{security_count:,}")
metrics[2].metric("Failed logons", f"{failed_count:,}")
metrics[3].metric("Suspicious signals", f"{len(suspicious):,}")
severity_cols = st.columns(4)
for col, severity in zip(severity_cols, SEVERITY_ORDER):
    col.metric(f"{severity} severity", f"{int(filtered['severity'].astype(str).eq(severity).sum()):,}")

left, right = st.columns(2)
with left:
    st.markdown("#### Event activity")
    chart_data = filtered.dropna(subset=["timestamp"]).copy()
    if chart_data.empty:
        st.caption("No valid timestamps available for the activity chart.")
    else:
        chart_data["time"] = chart_data["timestamp"].dt.floor("h")
        activity = chart_data.groupby(["time", "log_category"], observed=True).size().reset_index(name="Events")
        fig = px.area(activity, x="time", y="Events", color="log_category", template="plotly_dark")
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", legend_title_text="Log")
        st.plotly_chart(fig, width="stretch")
with right:
    st.markdown("#### Severity distribution")
    severity_data = filtered["severity"].astype(str).value_counts().reindex(SEVERITY_ORDER, fill_value=0).rename_axis("Severity").reset_index(name="Events")
    if count:
        fig = px.bar(severity_data, x="Severity", y="Events", color="Severity",
                     color_discrete_map={"High": "#f05252", "Medium": "#f59e0b", "Low": "#38bdf8", "Informational": "#64748b"}, template="plotly_dark")
        fig.update_layout(showlegend=False, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, width="stretch")
    else:
        st.caption("No events match the current filters.")

st.subheader("Suspicious signals and investigation queue")
st.caption("Signals are rule matches for analyst review; they are not confirmed attacks. Privileged logons and process creation are not automatically treated as malicious.")
alerts = filtered[(filtered["suspicious"]) | filtered["priority"].isin(["Review", "Investigate", "Investigate promptly"])]
alert_columns = ["timestamp", "event_id", "description", "severity", "priority", "detection", "log_category", "source"]
if alerts.empty:
    st.success("No alert-worthy events match the current filters.")
else:
    st.dataframe(alerts[alert_columns].sort_values("timestamp", ascending=False, na_position="last"),
                 width="stretch", hide_index=True)
    st.download_button("Download filtered alerts CSV", alerts.to_csv(index=False).encode("utf-8-sig"),
                       file_name="filtered_alerts.csv", mime="text/csv")

st.subheader("Recent events")
recent_columns = ["timestamp", "event_id", "description", "event_level", "severity", "log_category", "provider", "message"]
recent = filtered.sort_values("timestamp", ascending=False, na_position="last")
st.dataframe(recent[recent_columns].head(100), width="stretch", hide_index=True)
st.download_button("Download filtered events CSV", filtered.to_csv(index=False).encode("utf-8-sig"),
                   file_name="filtered_events.csv", mime="text/csv")

st.subheader("Inspect an event")
if filtered.empty:
    st.caption("No event to inspect under the current filters.")
else:
    options = filtered.sort_values("timestamp", ascending=False, na_position="last")
    def event_label(index: int) -> str:
        row = options.loc[index]
        stamp = row["timestamp"].strftime("%Y-%m-%d %H:%M:%S UTC") if pd.notna(row["timestamp"]) else "Unknown time"
        return f"{stamp} · ID {row['event_id']} · {row['description']} · row {index}"
    selected_index = st.selectbox("Select event", options.index.tolist(), format_func=event_label)
    selected = options.loc[selected_index]
    detail_left, detail_right = st.columns(2)
    with detail_left:
        st.markdown(f"**Detection:** {selected['detection']}  \n**Severity / priority:** {selected['severity']} / {selected['priority']}  \n**Guidance:** {selected['investigation_guidance']}")
        st.markdown(f"**Log / provider:** {selected['log_category']} / {selected['provider']}  \n**Computer:** {selected['computer_name'] or 'Not provided'}  \n**Source:** {selected['source'] or 'Not reliably available'}")
    with detail_right:
        st.markdown("**Event message**")
        st.text(selected["message"] or "No message available.")
        if selected.get("event_data"):
            with st.expander("Structured event data"):
                st.code(str(selected["event_data"]), language="json")

with st.expander("About the rules and privacy"):
    st.markdown("""
    - **1102** is high priority because it records a cleared Security audit log; validate authorized change context.
    - **4625** is a failed logon. A burst is raised only when a source value is explicitly present and reaches the configured threshold inside the time window.
    - Windows often omits or varies source fields by event/logon type. When source attribution is unavailable, the grouped rule is skipped and the limitation is shown.
    - **4672** and **4688** are contextual events, not inherently malicious. **4720** is an account creation that merits review.
    - Event messages may contain sensitive details. Keep exports local, limit access, and use only data you are authorized to review.
    """)
