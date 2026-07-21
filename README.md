# AI-Assisted Phishing Investigator - Version 0.1
A phishing email investigation tool powered by a custom-trained machine learning model that simulates a junior SOC analyst workflow for phishing investigation. The tool will ingest email text, extract evidence, score phishing risk using traditional machine learning and security rules, and later generate a grounded analyst-style report using an LLM.


## Quick Start on Windows

After cloning the repository, double-click:

```text
run_app.bat
```

The launcher will check whether a local virtual environment exists and ask whether to create one if needed. It will also ask whether to install dependencies from `requirements.txt`.

You can also run the app manually using the instructions below.

## Running the App Locally

These instructions assume you have Python installed and are running commands from the root folder of the repository.

### 1. Clone the repository

```bash
git clone <repository-url>
cd ai-phishing-investigator
```

If you downloaded the repository as a ZIP file instead, extract it and open a terminal in the extracted project folder.

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

On Windows:

```bash
.venv\Scripts\activate
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Add your VirusTotal API key

Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml`, then replace the placeholder with your key.

### 6. Run the Streamlit app

```bash
streamlit run app/streamlit_app.py
```

After the command runs, Streamlit should open the app in your browser. If it does not open automatically, copy the local URL shown in the terminal into your browser.

## Project Usage

Paste email text into the input box and click the analysis button. The current version returns:

* Predicted label: phishing or safe
* Probability of label assigned by the model

This version uses a baseline machine-learning classifier that only analyzes language patterns. Planned features for future versions are below.

## Planned Features
- Security rule findings
- URL/domain analysis
- Threat intelligence lookup
- LLM-generated analyst report from structured evidence

### Project Principles
- Traditional ML model and security rules analyze the email and produce evidence.
- An LLM will be used later to summarize structured evidence provided by the model, but will not be doing decision-making itself.
- The tool will use public or synthetic sample emails only.
- The project is a portfolio-grade phishing investigation aid, not a wide-use production email gateway.
