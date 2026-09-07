"""Netra Live Threat Pipeline Console (Makeshift Streamlit UI)
Connects directly to the Layer 7 API Gateway and PostgreSQL persistence store to visualize
end-to-end threat intelligence, Layer 5 external telemetry, and Layer 6 Neo4j campaign graphs.
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import requests
import redis
import pandas as pd
import streamlit as st

# Setup configuration
API_GATEWAY_URL = os.getenv("API_GATEWAY_URL", "http://api_gateway:8080")
INGESTION_URL = os.getenv("INGESTION_URL", "http://ingestion:8000")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

st.set_page_config(
    page_title="Netra Threat Pipeline - Live Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .reportview-container { background: #0e1117; }
    .verdict-malicious {
        background-color: #b71c1c;
        color: white;
        padding: 16px;
        border-radius: 8px;
        text-align: center;
        font-size: 26px;
        font-weight: 800;
        letter-spacing: 1.5px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(183, 28, 28, 0.4);
    }
    .verdict-suspicious {
        background-color: #e65100;
        color: white;
        padding: 16px;
        border-radius: 8px;
        text-align: center;
        font-size: 26px;
        font-weight: 800;
        letter-spacing: 1.5px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(230, 81, 0, 0.4);
    }
    .verdict-benign {
        background-color: #1b5e20;
        color: white;
        padding: 16px;
        border-radius: 8px;
        text-align: center;
        font-size: 26px;
        font-weight: 800;
        letter-spacing: 1.5px;
        margin-bottom: 15px;
        box-shadow: 0 4px 12px rgba(27, 94, 32, 0.4);
    }
    .campaign-banner {
        background: linear-gradient(90deg, #4a148c 0%, #311b92 100%);
        color: white;
        padding: 12px 18px;
        border-radius: 8px;
        margin-bottom: 15px;
        font-weight: bold;
    }
    .badge-pass { background-color: #2e7d32; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-fail { background-color: #c62828; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-warn { background-color: #ef6c00; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
    .badge-info { background-color: #0277bd; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_redis_client():
    """Establish connection to Redis."""
    try:
        client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        client.ping()
        return client
    except Exception:
        return None


def fetch_reports_from_gateway() -> List[Dict[str, Any]]:
    """Retrieve list of threat reports from FastAPI API Gateway."""
    try:
        resp = requests.get(f"{API_GATEWAY_URL}/api/v1/reports?limit=50", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return []


def fetch_report_by_id(email_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full finalized threat report from API Gateway."""
    try:
        resp = requests.get(f"{API_GATEWAY_URL}/api/v1/reports/{email_id}", timeout=3)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def fetch_fallback_from_redis(client: redis.Redis) -> List[Dict[str, Any]]:
    """Fallback to Redis queue if PostgreSQL persistence is still ingesting."""
    if not client:
        return []
    for q in ["final_persistence_queue", "correlation_queue", "threat_intel_queue", "threat_engine_queue"]:
        try:
            raw_items = client.lrange(q, 0, 10)
            if raw_items:
                parsed = []
                for r in raw_items:
                    try:
                        parsed.append(json.loads(r))
                    except Exception:
                        continue
                if parsed:
                    return parsed
        except Exception:
            continue
    return []


def format_verdict_badge(verdict: str) -> str:
    """Return HTML colored badge for SPF/DKIM/DMARC verdicts."""
    v = (verdict or "missing").lower()
    if v == "pass":
        return f'<span class="badge-pass">PASS</span>'
    elif v in ("fail", "permerror"):
        return f'<span class="badge-fail">{v.upper()}</span>'
    elif v in ("softfail", "neutral"):
        return f'<span class="badge-warn">{v.upper()}</span>'
    else:
        return f'<span class="badge-info">{v.upper()}</span>'


# ==============================================================================
# SIDEBAR: INGESTION CONTROLS
# ==============================================================================
with st.sidebar:
    st.image("https://img.icons8.com/color/96/shield.png", width=64)
    st.title("Netra Pipeline")
    st.caption("Layer 1 Ingestion Gateway")

    ingest_mode = st.radio("Select Ingestion Mode", ["Paste Email Text", "Upload .EML File"])

    SAMPLE_PHISHING = """From: Security Desk <alert@micros0ft-support.com>
To: victim@corp.internal
Subject: Critical Security Notice: Reset Password Immediately
Date: Mon, 7 Sep 2026 12:00:00 +0000
Message-ID: <test101@micros0ft-support.com>
Authentication-Results: mx.corp.internal; spf=fail; dkim=none; dmarc=fail
Received: from mail.micros0ft-support.com ([198.51.100.42]) by mx.corp.internal; Mon, 7 Sep 2026 12:00:01 +0000

URGENT: Immediate action required! Your corporate login credentials have expired.
Please verify your account within 24 hours at https://micros0ft.com/account/login.php to avoid suspension.

Also review our backup portal at hxxps://paypal.security-verify[.]org"""

    SAMPLE_BEC = """From: CEO Executive Office <ceo@external-mail.net>
To: finance@corp.internal
Subject: Urgent: Confidential Wire Transfer Request
Date: Mon, 7 Sep 2026 12:15:00 +0000
Message-ID: <bec202@external-mail.net>
Received: from mail.external-mail.net ([198.51.100.25]) by mx.corp.internal; Mon, 7 Sep 2026 12:15:01 +0000

Please process an immediate wire transfer for the overdue invoice attached.
Updated banking details and routing number are in the portal at http://198.51.100.25/invoice-view.
Also expedite the requested apple gift card vouchers for the client meeting today.

Regards,
Chief Executive Officer"""

    if ingest_mode == "Paste Email Text":
        col_btn1, col_btn2 = st.columns(2)
        if col_btn1.button("Load Phishing"):
            st.session_state["raw_email_input"] = SAMPLE_PHISHING
        if col_btn2.button("Load BEC"):
            st.session_state["raw_email_input"] = SAMPLE_BEC

        text_content = st.text_area(
            "Raw RFC 5322 Email",
            value=st.session_state.get("raw_email_input", ""),
            height=260,
            placeholder="From: ...\nTo: ...\nSubject: ...\n\nEmail body...",
        )

        if st.button("🚀 Ingest Email Text", type="primary", use_container_width=True):
            if not text_content.strip():
                st.warning("Please enter email text before submitting.")
            else:
                with st.spinner("Submitting to Ingestion Service..."):
                    try:
                        resp = requests.post(
                            f"{INGESTION_URL}/api/v1/ingest/text",
                            json={"raw_email": text_content},
                            timeout=5,
                        )
                        if resp.status_code == 202:
                            data = resp.json()
                            st.success(f"Accepted! Email ID:\n`{data.get('email_id')}`")
                            st.toast("Email dispatched through pipeline!", icon="✅")
                        else:
                            st.error(f"Ingestion failed: HTTP {resp.status_code} - {resp.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to Ingestion API at {INGESTION_URL}: {e}")

    else:
        uploaded_file = st.file_uploader("Upload .eml File", type=["eml", "msg", "txt"])
        if st.button("🚀 Ingest .EML File", type="primary", use_container_width=True):
            if not uploaded_file:
                st.warning("Please select a file to upload.")
            else:
                with st.spinner("Uploading to Ingestion Service..."):
                    try:
                        files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "message/rfc822")}
                        resp = requests.post(
                            f"{INGESTION_URL}/api/v1/ingest/file",
                            files=files,
                            timeout=5,
                        )
                        if resp.status_code == 202:
                            data = resp.json()
                            st.success(f"Accepted! Email ID:\n`{data.get('email_id')}`")
                            st.toast("File uploaded to pipeline!", icon="✅")
                        else:
                            st.error(f"Upload failed: HTTP {resp.status_code} - {resp.text}")
                    except Exception as e:
                        st.error(f"Failed to connect to Ingestion API at {INGESTION_URL}: {e}")

    st.divider()
    st.caption("Pipeline Telemetry")
    redis_client = get_redis_client()
    if redis_client:
        q_intel = redis_client.llen("threat_intel_queue")
        q_corr = redis_client.llen("correlation_queue")
        q_persist = redis_client.llen("final_persistence_queue")
        st.caption(f"Threat Intel Queue (L5): **{q_intel}**")
        st.caption(f"Correlation Queue (L6): **{q_corr}**")
        st.caption(f"Final Persistence Queue (L7): **{q_persist}**")


# ==============================================================================
# MAIN PANEL: LIVE REPORTS & GRAPH VIEWER
# ==============================================================================
st.title("🛡️ Netra Threat Intelligence & Forensics Dashboard")
st.markdown("End-to-End Pipeline: **Ingestion (L1)** $\\rightarrow$ **Parsing (L2)** $\\rightarrow$ **Analysis (L3)** $\\rightarrow$ **Threat Engine (L4)** $\\rightarrow$ **Threat Intel (L5)** $\\rightarrow$ **Neo4j Graph (L6)** $\\rightarrow$ **PostgreSQL & API Gateway (L7/9)**")

top_col1, top_col2 = st.columns([6, 1])
with top_col2:
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

# 1. Try to fetch from API Gateway (PostgreSQL persistence)
reports_summary = fetch_reports_from_gateway()
selected_report: Optional[Dict[str, Any]] = None

if reports_summary:
    report_options = []
    for r in reports_summary:
        eid = r.get("email_id", "Unknown")[:8]
        subj = r.get("subject", "No Subject")
        score = r.get("risk_score", 0)
        verdict = r.get("classification", "UNKNOWN")
        camp = f" | {r.get('campaign_id')}" if r.get("campaign_id") else ""
        report_options.append(f"[{verdict} - {score}/100] {subj} ({eid}...{camp})")

    selected_label = st.selectbox(f"Select Threat Report (Source: PostgreSQL via API Gateway)", report_options)
    selected_idx = report_options.index(selected_label)
    selected_eid = reports_summary[selected_idx]["email_id"]
    selected_report = fetch_report_by_id(selected_eid)

else:
    # 2. Fallback to Redis queues if PostgreSQL is still writing
    fallback_items = fetch_fallback_from_redis(redis_client)
    if fallback_items:
        fb_options = []
        for idx, it in enumerate(fallback_items):
            eid = it.get("email_id", "Unknown")[:8]
            fb_options.append(f"#{idx+1}: Queued Email ({eid}...)")
        selected_label = st.selectbox("Select Email (Source: Redis Live Queue Fallback)", fb_options)
        selected_idx = fb_options.index(selected_label)
        selected_report = fallback_items[selected_idx]
    else:
        st.info("ℹ️ No finalized threat reports in PostgreSQL or Redis queues. Submit an email sample in the left sidebar to run the pipeline!")
        st.stop()

if not selected_report:
    st.warning("Could not retrieve report content.")
    st.stop()

# Helper accessors across schema wrappers (CorrelatedEmail vs EnrichedEmail vs ClassifiedEmail)
def get_layer(obj, key):
    curr = obj
    for k in key.split("."):
        if isinstance(curr, dict):
            curr = curr.get(k, {})
        else:
            return {}
    return curr

# Unpack layers
correlated_data = selected_report.get("correlation", {})
enriched_email = selected_report.get("enriched_email", selected_report)
enrichment = enriched_email.get("enrichment", {})
classified_email = enriched_email.get("classified_email", enriched_email)
assessment = classified_email.get("threat_assessment", {})
analyzed_email = classified_email.get("analyzed_email", classified_email)
parsed_email = analyzed_email.get("parsed_email", {})
headers = parsed_email.get("headers", {})
analysis = analyzed_email.get("analysis", {})

verdict = assessment.get("classification", "UNKNOWN")
risk_score = assessment.get("risk_score", 0)
matched_rules = assessment.get("matched_rules", [])
iocs = assessment.get("iocs", [])

# ==============================================================================
# PROMINENT THREAT VERDICT & CAMPAIGN BANNER
# ==============================================================================
if verdict == "MALICIOUS":
    st.markdown(f'<div class="verdict-malicious">🚨 VERDICT: MALICIOUS (Risk Score: {risk_score} / 100)</div>', unsafe_allow_html=True)
elif verdict == "SUSPICIOUS":
    st.markdown(f'<div class="verdict-suspicious">⚠️ VERDICT: SUSPICIOUS (Risk Score: {risk_score} / 100)</div>', unsafe_allow_html=True)
else:
    st.markdown(f'<div class="verdict-benign">✅ VERDICT: BENIGN (Risk Score: {risk_score} / 100)</div>', unsafe_allow_html=True)

# Campaign Banner if detected by Neo4j
camp_id = correlated_data.get("campaign_id")
if camp_id:
    st.markdown(
        f'<div class="campaign-banner">🕸️ NEO4J CORRELATION ALERT: Linked to Campaign Cluster <b>{camp_id}</b> '
        f'({correlated_data.get("campaign_name", "Attack Campaign")}) '
        f'— Shares {correlated_data.get("shared_ioc_count", 0)} indicators with {len(correlated_data.get("related_email_ids", []))} other emails!</div>',
        unsafe_allow_html=True
    )

# Metric Summary Banner
m1, m2, m3, m4 = st.columns(4)
m1.metric("Threat Classification", verdict)
m2.metric("Overall Risk Score", f"{risk_score} / 100")
m3.metric("Malicious External IOCs", enrichment.get("malicious_iocs_found", 0))
m4.metric("Attributed Threat Actors", len(enrichment.get("threat_actors", [])))

st.divider()

# Detailed Feature Tabs
tab_threat, tab_intel, tab_graph, tab_headers, tab_urls, tab_att, tab_json = st.tabs([
    "🛡️ Threat Assessment",
    "🌐 External Threat Intel (L5)",
    "🕸️ Neo4j Campaign Graph (L6)",
    "📬 Headers & Auth",
    "🔗 URLs & Typosquatting",
    "📎 Attachments",
    "💻 Full JSON Report",
])

# ------------------------------------------------------------------------------
# TAB 1: THREAT ASSESSMENT & RULES
# ------------------------------------------------------------------------------
with tab_threat:
    col_t1, col_t2 = st.columns([1, 1])
    with col_t1:
        st.subheader("Email Metadata")
        st.write(f"**Email ID:** `{selected_report.get('email_id')}`")
        st.write(f"**Subject:** {headers.get('subject', 'N/A')}")
        st.write(f"**From:** `{headers.get('from', 'N/A')}`")
        st.write(f"**To:** `{', '.join(headers.get('to', []))}`")
        st.write(f"**Date:** {headers.get('date', 'N/A')}")
        st.write(f"**Message-ID:** `{headers.get('message_id', 'N/A')}`")

    with col_t2:
        st.subheader("Risk Score Gauge")
        st.progress(risk_score / 100.0, text=f"Calculated Threat Score: {risk_score} / 100")
        c_res = analysis.get("content_analysis", {})
        cols_sig = st.columns(3)
        cols_sig[0].markdown(f"**Urgency:** {'🔴 Yes' if c_res.get('urgency_detected') else '🟢 No'}")
        cols_sig[1].markdown(f"**BEC / Wire:** {'🔴 Yes' if c_res.get('financial_intent_detected') else '🟢 No'}")
        cols_sig[2].markdown(f"**Credential Bait:** {'🔴 Yes' if c_res.get('credential_harvesting_detected') else '🟢 No'}")

    st.subheader("Triggered Scoring Rules (Points Breakdown)")
    if matched_rules:
        for rule in matched_rules:
            st.markdown(f"- 🔴 **{rule}**")
    else:
        st.success("No threat scoring rules were triggered for this email.")

# ------------------------------------------------------------------------------
# TAB 2: EXTERNAL THREAT INTEL (Layer 5 Highlight)
# ------------------------------------------------------------------------------
with tab_intel:
    st.subheader("External Intelligence Enrichment (VirusTotal, AbuseIPDB, URLhaus, MISP)")

    actors = enrichment.get("threat_actors", [])
    if actors:
        st.error(f"🚨 **Attributed Threat Actors:** {', '.join([f'`{a}`' for a in actors])}")
    else:
        st.info("No known advanced threat actors directly attributed to these IOCs.")

    enriched_iocs = enrichment.get("enriched_iocs", [])
    if enriched_iocs:
        st.caption(f"Enriched {len(enriched_iocs)} IOC indicators:")
        display_data = []
        for item in enriched_iocs:
            display_data.append({
                "Type": item.get("type"),
                "Indicator Value": item.get("value"),
                "Malicious?": "🔴 YES" if item.get("is_malicious") else "🟢 Clean",
                "Threat Score": f"{item.get('threat_score')}/100",
                "Provider": item.get("provider"),
                "Threat / Malware Families": ", ".join(item.get("threat_names", [])) or "None",
            })
        st.dataframe(pd.DataFrame(display_data), use_container_width=True)

        with st.expander("Detailed Provider Telemetry (Raw Response Dictionaries)"):
            for item in enriched_iocs:
                if item.get("details"):
                    st.write(f"**{item.get('value')}** ({item.get('provider')}):")
                    st.json(item.get("details"))
    else:
        st.write("No external IOC telemetry found.")

# ------------------------------------------------------------------------------
# TAB 3: NEO4J CAMPAIGN GRAPH CORRELATION (Layer 6 Highlight)
# ------------------------------------------------------------------------------
with tab_graph:
    st.subheader("Neo4j Attack Infrastructure & Campaign Topology")

    if correlated_data.get("is_part_of_campaign"):
        st.error(f"🕸️ **Phishing Campaign Cluster Identified: `{correlated_data.get('campaign_id')}`**")
        st.write(f"**Campaign Name:** {correlated_data.get('campaign_name')}")
        st.write(f"**Shared Infrastructure Count:** {correlated_data.get('shared_ioc_count')} overlapping IOC nodes")

        related = correlated_data.get("related_email_ids", [])
        if related:
            st.write("**Other Ingested Emails in this Campaign Cluster:**")
            for rid in related:
                st.code(rid)
    else:
        st.success("✅ **Standalone Attack Infrastructure**: No overlapping campaign links to previously ingested emails.")

    st.caption(f"Neo4j Threat Graph Nodes Processed: {correlated_data.get('graph_nodes_merged', 0)}")

# ------------------------------------------------------------------------------
# TAB 4: HEADERS & AUTHENTICATION
# ------------------------------------------------------------------------------
with tab_headers:
    h_res = analysis.get("header_analysis", {})
    st.subheader("Authentication Results (RFC 8601)")
    auth_col1, auth_col2, auth_col3 = st.columns(3)
    auth_col1.markdown(f"### SPF: {format_verdict_badge(h_res.get('spf_verdict'))}", unsafe_allow_html=True)
    auth_col2.markdown(f"### DKIM: {format_verdict_badge(h_res.get('dkim_verdict'))}", unsafe_allow_html=True)
    auth_col3.markdown(f"### DMARC: {format_verdict_badge(h_res.get('dmarc_verdict'))}", unsafe_allow_html=True)

    anomalies = h_res.get("auth_anomalies", [])
    if anomalies:
        st.warning("⚠️ **Authentication Anomalies Flagged:**")
        for anom in anomalies:
            st.markdown(f"- {anom}")

    with st.expander("Received Chain (Hops)"):
        chain = headers.get("received_chain", [])
        if chain:
            for idx, hop in enumerate(chain):
                st.code(f"Hop #{idx+1}:\n{hop}", language="text")

    with st.expander("Full Raw Headers Dictionary"):
        st.json(headers.get("raw_headers", {}))

# ------------------------------------------------------------------------------
# TAB 5: URLS & TYPOSQUATTING
# ------------------------------------------------------------------------------
with tab_urls:
    u_res = analysis.get("url_analysis", {})
    st.subheader(f"Extracted URLs ({u_res.get('total_urls_inspected', 0)} inspected)")

    typosquats = u_res.get("typosquat_detections", [])
    if typosquats:
        st.error(f"🚨 **{len(typosquats)} Typosquatting / Brand Impersonations Detected!**")
        st.dataframe(pd.DataFrame(typosquats), use_container_width=True)

    ip_hosts = u_res.get("ip_host_urls", [])
    if ip_hosts:
        st.warning(f"⚠️ **Bare IP Address Hosts Detected:**")
        for ip_u in ip_hosts:
            st.code(ip_u)

    defanged = u_res.get("defanged_urls", [])
    if defanged:
        st.info(f"🛡️ **Defanged URLs Identified:**")
        for df_u in defanged:
            st.code(df_u)

    st.write("**Root Domains Extracted:**")
    st.write(u_res.get("root_domains", []))

# ------------------------------------------------------------------------------
# TAB 6: ATTACHMENTS
# ------------------------------------------------------------------------------
with tab_att:
    a_res = analysis.get("attachment_analysis", {})
    st.subheader("Attachment Risk Analysis")
    att_list = a_res.get("flagged_attachments", [])

    if a_res.get("has_executable_attachment") or a_res.get("has_double_extension") or a_res.get("has_mime_mismatch"):
        st.error("🚨 **High-Risk Attachment Tactics Detected!**")
        if att_list:
            st.dataframe(pd.DataFrame(att_list), use_container_width=True)
    else:
        st.success("✅ No dangerous, double-extension, or mismatched attachments detected.")

    with st.expander(f"All Attached Files ({len(parsed_email.get('attachments', []))})"):
        st.json(parsed_email.get("attachments", []))

# ------------------------------------------------------------------------------
# TAB 7: FULL JSON REPORT
# ------------------------------------------------------------------------------
with tab_json:
    st.subheader("Complete Threat Report Schema (PostgreSQL JSONB)")
    st.json(selected_report)
