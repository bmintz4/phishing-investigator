import streamlit as st

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.models.predict import predict_email
from src.ingestion.html_email import html_to_text
from src.security.language_rules import analyze_language_rules
from src.security.url_rules import analyze_url_rules


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
email_input = st.text_area(f"Paste {input_format.lower()} here:")

if st.button("Analyze Email"):
    raw_input = email_input.strip()
    text = html_to_text(raw_input) if input_format == "HTML" else raw_input

    if raw_input == "":
        st.warning("Please paste the email contents before analyzing.")

    else:
        if text == "":
            st.warning("The pasted HTML did not contain text to analyze.")
            st.stop()

        with st.spinner("Looking for common indicators..."):
            rules_list = analyze_language_rules(text)
            if input_format == "HTML":
                rules_list.extend(analyze_url_rules(raw_input))

            rules_list.sort(key=lambda rule: SEVERITY_ORDER[rule["severity"]])

        with st.spinner("Analyzing email..."):
            result = predict_email(text)

        for rule in rules_list:
            rule_type = rule["type"]
            rule_subtype = rule["subtype"].replace("_", " ")
            severity = rule["severity"]
            st.badge(
                f'{rule_type}: {rule_subtype}',
                color=SEVERITY_COLORS[severity],
            )
            st.text(rule["evidence"])

        if result["label"] == "phishing":
            st.badge("Likely Phishing", color="red")

        else:
            st.badge("Likely Legitimate", color="blue")

        prob = "Probability: " + str(result["probability"] * 100)[:5] + "%"
        st.badge(prob, color="gray")
