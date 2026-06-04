# AI-Assisted Phishing Investigator
A phishing email investigation tool powered by a custom-trained machine learning model that simulates a junior SOC analyst workflow for phishing investigation. The tool will ingest email text, extract evidence, score phishing risk using traditional machine learning and security rules, and later generate a grounded analyst-style report using an LLM.

### MVP Scope
The MVP will allow a user to paste email text into a Streamlit app and receive a phishing/legitimate label, a probability score, and basic evidence explaining the result.

### Project Principles
- Traditional ML and security rules analyze the email and produce the evidence.
- The LLM, added later, will summarize structured evidence rather than make the detection decision.
- The tool will use public or synthetic sample emails only.
- The project is a portfolio-grade phishing investigation aid, not a wide-use production email gateway.

## Planned Features
- Email text input
- Phishing probability score
- Security rule findings
- URL/domain analysis
- Threat intelligence lookup
- LLM-generated analyst report from structured evidence
