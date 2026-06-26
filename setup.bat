@echo off
REM SentinelAI Setup Script for Windows

echo =================================================================
echo             SentinelAI Agent Setup ^& Installation
echo =================================================================
echo.

REM 1. Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not added to your system PATH.
    echo Please install Python 3.10+ from https://www.python.org/ and try again.
    pause
    exit /b 1
)

REM 2. Create Virtual Environment
if not exist venv (
    echo [INFO] Creating Python virtual environment (venv)...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [SUCCESS] Virtual environment created.
) else (
    echo [INFO] Virtual environment already exists. Skipping creation.
)

REM 3. Activate Virtual Environment and install packages
echo [INFO] Activating virtual environment and installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Dependency installation failed.
    pause
    exit /b 1
)
echo [SUCCESS] Dependencies installed successfully.
echo.

echo =================================================================
echo                       Setup Complete!
echo =================================================================
echo.
echo Quick-Start Instructions:
echo.
echo   1. Encrypt your API Key (Optional):
echo      python backend/cli.py set-key
echo.
echo   2. Run a CLI assessment scan:
echo      python backend/cli.py scan --profile ecommerce
echo.
echo   3. Start the FastAPI Web Server:
echo      python app.py
echo      (Open http://127.0.0.1:8000 in your browser)
echo.
echo =================================================================
echo.

set /p START_SERVER="Would you like to start the FastAPI Web Server now? (Y/N): "
if /i "%START_SERVER%"=="Y" (
    echo Starting FastAPI server...
    python app.py
) else (
    echo Setup finished. Run 'venv\Scripts\activate' to activate your env.
)
pause
