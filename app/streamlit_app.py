import streamlit as st
import time

st.set_page_config(page_title="Phishing Investigator", layout="centered")

st.title("Phishing Investigator")
st.write("Welcome to the phishing investigation assistant. Use this app to inspect suspicious emails and URLs.")

email_text = st.text_area("Paste email contents here:")

if st.button("Analyze Email"):
    if email_text.strip() == "":
        st.warning("Please paste the email contents before analyzing.")
    else:
        with st.spinner("Analyzing email..."):
            time.sleep(2) #placeholder for actual analysis
        
        st.error("This doesn't actually do any analysis yet :(")
        