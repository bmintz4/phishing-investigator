import streamlit as st

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.models.predict import predict_email, predict_structured
from src.ingestion.html_email import html_to_text, parse_html_email_to_record
from src.ingestion.html_email_sanitizer import parse_html_email_to_sanitized_record
from src.security.language_rules import analyze_language_rules
from src.security.url_rules import analyze_url_rules
from src.security.score_calculation import risk_rating
from src.intel.url_reputation import analyze_url_reputation


SEVERITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
    "none": 3,
}

SEVERITY_COLORS = {
    "high": "red",
    "medium": "orange",
    "low": "yellow",
    "none": "blue",
}

st.set_page_config(page_title="Phishing Investigator", layout="centered")

st.title("Phishing Investigator")
st.write("Welcome to the phishing investigation assistant. Use this app to inspect suspicious emails and URLs.")

input_format = st.radio(
    "Input format",
    ["Text", "HTML"],
    horizontal=True,
)
email_input = st.text_area(f"Paste {input_format.lower()} Here:")

if st.button("Analyze Email"):
    raw_input = email_input.strip()
    text = html_to_text(raw_input) if input_format == "HTML" else raw_input

    if raw_input == "":
        st.warning("Please paste the email contents before analyzing.")

    else:
        if text == "":
            st.warning("The pasted HTML did not contain text to analyze.")
            st.stop()

        ## combine relevant security rule lists together 
        with st.spinner("Looking for common indicators..."):
            rules_list = analyze_language_rules(text)
            if input_format == "HTML":
                rules_list.extend(analyze_url_rules(raw_input))

            rules_list.sort(key=lambda rule: SEVERITY_ORDER[rule["severity"]])

        url_reputation = []
        if input_format == "HTML":
            with st.spinner("Checking URL reputation..."):
                api_key = ""
                try:
                    api_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
                except FileNotFoundError:
                    pass

                try:
                    url_reputation = analyze_url_reputation(raw_input, api_key)
                except ValueError as exc:
                    st.warning(str(exc))

        with st.spinner("Analyzing email..."):
            if input_format == "HTML":
                ## ml_result = predict_structured(parse_html_email_to_record(raw_input))
                ml_result = predict_structured(parse_html_email_to_sanitized_record(raw_input))
            else:
                ml_result = predict_email(text)

        ml_risk = round(float(ml_result["probability"]) * 100)
        overall_risk_rating, rule_risk = risk_rating(rules_list, ml_risk)
        overall_risk_rating = round(overall_risk_rating)

        ## display overall risk level, rule risk level, and ml risk level
        col1, col2, col3 = st.columns(3)
        col1.metric("Overall Risk Score", f"{overall_risk_rating}%")
        col1.caption("Combined, weighted risk scores from security rules and language model")
        col2.metric("Security Rule Score", f"{rule_risk}%")
        col2.caption("Rules-based risk score derived from common phishing indicators")
        col3.metric("Model Risk Score", f"{ml_risk}%")
        col3.caption("Risk score derived from machine learning language analysis")

        ## Overall Risk Level claim & basic explanation
        if overall_risk_rating < 30:
            st.subheader("Overall Risk Level: low")
            st.text("Email is very likely legitimate")
        elif overall_risk_rating < 60:
            st.subheader("Overall Risk Level: moderate")
            st.text("Email is likely legitimate, but proceed with caution")
        elif overall_risk_rating < 85:
            st.subheader("Overall Risk Level: high")
            st.text("Email has a significant chance of being malicious, proceed with caution")
        else:
            st.subheader("Overall Risk Level: critical")
            st.text("Email is very likely malicious")
        st.divider()

        if input_format == "HTML":
            st.subheader("URL Reputation")
            st.write(url_reputation)
            st.divider()

        ## print security rule findings in order of severity
        for rule in rules_list:
            rule_type = rule["type"]
            rule_subtype = rule["subtype"].replace("_", " ")
            severity = rule["severity"]
            st.badge(
                f'{rule_type}: {rule_subtype}',
                color=SEVERITY_COLORS[severity],
            )
            st.text(rule["evidence"])
