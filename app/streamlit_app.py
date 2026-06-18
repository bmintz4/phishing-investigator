import streamlit as st

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.models.predict import predict_email
from src.ingestion.html_email import extract_links, html_to_text
from src.security.rules import analyze_rules

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
        if input_format == "HTML":
            links = extract_links(raw_input)

            if links:
                for link in links:
                    st.text(f"Link found. Text: {link['text']} Address: {link['address']}")
            else:
                st.write("No links found in the HTML.")

        if text == "":
            st.warning("The pasted HTML did not contain text to analyze.")
            st.stop()

        with st.spinner("Looking for common indicators..."):
            rules_list = analyze_rules(text)

        with st.spinner("Analyzing email..."):
            result = predict_email(text)

        for rule in rules_list:
            rule_name = rule["rule"].replace("_", " ")
            st.write(
                f'{rule_name} language detected: "{rule["evidence"]}" '
                f'Severity: {rule["severity"]}'
            )

        if result["label"] == "phishing":
            st.badge("Likely Phishing", color="red")

        else:
            st.badge("Likely Legitimate", color="blue")

        prob = "Probability: " + str(result["probability"] * 100)[:5] + "%"
        st.badge(prob, color="gray")
