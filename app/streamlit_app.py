import streamlit as st

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from src.models.predict import predict_email

st.set_page_config(page_title="Phishing Investigator", layout="centered")

st.title("Phishing Investigator")
st.write("Welcome to the phishing investigation assistant. Use this app to inspect suspicious emails and URLs.")

email_text = st.text_area("Paste email contents here:")

if st.button("Analyze Email"):
    text = email_text.strip()
    if text == "":
        st.warning("Please paste the email contents before analyzing.")
    else:
        with st.spinner("Analyzing email..."):
            result = predict_email(text)
        if result["label"] == "phishing":
            st.badge("Likely Phishing", color="red")
        else:
            st.badge("Likely Legitimate", color="blue")
        prob = "Probability: " + str(result["probability"] * 100)[:5] + "%"
        st.badge(prob, color="gray")