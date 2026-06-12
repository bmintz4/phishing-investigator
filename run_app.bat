@echo off
setlocal

echo Starting AI-Assisted Phishing Investigator...
echo.

REM Move to the folder where this script is located
cd /d "%~dp0"

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo Python was not found.
    echo Please install Python 3.11+ and try again.
    pause
    exit /b 1
)

REM Create virtual environment if missing
if not exist ".venv\Scripts\activate.bat" (
    echo Virtual environment not found.
    set /p CREATE_VENV="No virtual environment found. Create a virtual environment? (y/n): "

    if /i "%CREATE_VENV%"=="y" (
        echo Creating virtual environment...
        python -m venv .venv

        if errorlevel 1 (
            echo Failed to create virtual environment.
            pause
            exit /b 1
        )
    ) else (
        echo Cannot continue without a virtual environment.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
call ".venv\Scripts\activate.bat"

REM Check for requirements.txt
if not exist "requirements.txt" (
    echo requirements.txt not found.
    pause
    exit /b 1
)

REM Ask whether to install/update requirements
echo.
set /p INSTALL_REQS="Install/update dependencies from requirements.txt? (y/n): "

if /i "%INSTALL_REQS%"=="y" (
    echo Installing dependencies...
    python -m pip install --upgrade pip
    pip install -r requirements.txt

    if errorlevel 1 (
        echo Failed to install dependencies.
        pause
        exit /b 1
    )
)

REM Launch Streamlit app
echo.
echo Launching Phishing Investigator...
streamlit run app/streamlit_app.py

pause