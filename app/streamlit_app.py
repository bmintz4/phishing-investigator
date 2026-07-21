import streamlit as st

from pathlib import Path
import sys
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.models.predict import predict_email, predict_structured
from src.ingestion.html_email import html_to_text, parse_html_email_to_record
from src.ingestion.html_email_sanitizer import parse_html_email_to_sanitized_record
from src.security.language_rules import analyze_language_rules
from src.security.url_rules import analyze_url_rules
from src.security.score_calculation import risk_rating, risk_rating_url
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


        ## call VirusTotal API to check URL reputation
        url_reputation = []
        VirusTotal_API_called = False
        if input_format == "HTML":
            with st.spinner("Checking URL reputation..."):
                api_key = ""
                try:
                    api_key = st.secrets.get("VIRUSTOTAL_API_KEY", "")
                except FileNotFoundError:
                    pass
                try:
                    url_reputation, VirusTotal_API_called = analyze_url_reputation(
                        raw_input, api_key
                    )
                except ValueError as exc:
                    st.warning(str(exc))


        ## analyze with ML model
        with st.spinner("Analyzing email..."):
            if input_format == "HTML":
                ## ml_result = predict_structured(parse_html_email_to_record(raw_input))
                ml_result = predict_structured(parse_html_email_to_sanitized_record(raw_input))
            else:
                ml_result = predict_email(text)

        ml_risk = round(float(ml_result["probability"]) * 100)


        ## 2-sore or 3-score analysis, depending on whether VirusTotal API was called successfully
        if VirusTotal_API_called:
            overall_risk_rating, rule_risk, url_risk, worst_url = risk_rating_url(rules_list, ml_risk, url_reputation)
            overall_risk_rating = round(overall_risk_rating)

            ## display overall risk score
            st.metric("Overall Risk Score", f"{overall_risk_rating}%")
            st.caption("Combined, weighted risk scores from security rules, language model, and URL analysis")

            ## display rule risk level, ml risk level, and URL analysis results
            col1, col2, col3 = st.columns(3)
            col1.metric("Security Rule Score", f"{rule_risk}%")
            col1.caption("Risk score derived from common phishing indicator rules")
            col2.metric("Model Risk Score", f"{ml_risk}%")
            col2.caption("Risk score derived from machine learning language analysis")
            col3.metric("VirusTotal Analysis Score", f"{url_risk}%")
            if worst_url is not None:
                col3.caption(f"highest-risk URL: {worst_url}")
            col3.caption("Risk score derived from  VirusTotal URL reputation analysis")
        else:
            overall_risk_rating, rule_risk = risk_rating(rules_list, ml_risk)
            overall_risk_rating = round(overall_risk_rating)

            ## display overall risk score
            st.metric("Overall Risk Score", f"{overall_risk_rating}%")
            st.caption("Combined, weighted risk scores from security rules and language model analysis")

            ## display rule risk level, ml risk level, and URL analysis results
            col1, col2 = st.columns(2)
            col1.metric("Security Rule Score", f"{rule_risk}%")
            col1.caption("Risk score derived from common phishing indicator rules")
            col2.metric("Model Risk Score", f"{ml_risk}%")
            col2.caption("Risk score derived from machine learning language analysis")


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

        if url_reputation:
            st.subheader("URL Reputation")
            untested = []
            tested_by_domain = {}
            for result in url_reputation:
                url = result["URL"]
                stats = result["last analysis stats"]

                # Failed and quota-limited lookups do not have usable stats.
                if result["status"] == "untested" or stats is None:
                    untested.append(url)
                    if result.get("Error"):
                        domain = (urlsplit(url).hostname or url).casefold()
                        st.warning(
                            f"VirusTotal could not analyze {domain}: "
                            f"{result['Error']}"
                        )
                    continue

                reputation_scores = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }
                highest_reputation, highest_score = max(
                    reputation_scores.items(), key=lambda item: item[1]
                )

                # A result with no classifications is not meaningfully tested.
                if highest_score == 0:
                    untested.append(url)
                    continue

                domain = (urlsplit(url).hostname or url).casefold()
                group = tested_by_domain.setdefault(
                    domain,
                    {
                        "status": "analyzed",
                        "reputation": highest_reputation,
                        "score": highest_score,
                        "urls": [],
                        "clone_count": 0,
                    },
                )
                group["urls"].append(url)
                if result["status"] == "clone":
                    group["clone_count"] += 1
                if result["status"] == "analyzed":
                    group["status"] = "analyzed"
                    group["reputation"] = highest_reputation
                    group["score"] = highest_score

            for domain, group in tested_by_domain.items():
                clone_label = (
                    f" + {group['clone_count']} clone"
                    f"{'s' if group['clone_count'] != 1 else ''}"
                    if group["clone_count"]
                    else ""
                )
                st.write(f"**{domain}** — {group['status']}{clone_label}")
                st.write(
                    f"Analysis: {group['reputation']} "
                    f"({group['score']} engines)"
                )
                with st.expander(f"URLs on {domain} ({len(group['urls'])})"):
                    for link in group["urls"]:
                        st.write(link)

            if untested:
                st.write("Untested URLs:")
                for link in untested:
                    st.write(link)
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
