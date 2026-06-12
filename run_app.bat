@echo off
echo Starting AI-Assisted Phishing Investigator...
echo.

REM Move to the folder where this script is located
cd /d "%~dp0"

REM Activate virtual environment if it exists
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else (
    echo Virtual environment not found.
    echo Please create one with: python -m venv .venv
    echo Then install requirements with: pip install -r requirements.txt
    pause
    exit /b
)

REM Start Streamlit app
streamlit run app/streamlit_app.py

pause