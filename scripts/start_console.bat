@echo off
REM Launches the SigilChain trace console (Streamlit UI).
REM Run this AFTER start_nodes.bat -- the console queries the 3 validator
REM nodes over HTTP, so they need to already be up.

cd /d "%~dp0.."

set VENV_ACTIVATE=
if exist "..\venv\Scripts\activate.bat" set VENV_ACTIVATE=..\venv\Scripts\activate.bat
if exist "..\..\venv\Scripts\activate.bat" set VENV_ACTIVATE=..\..\venv\Scripts\activate.bat

if not "%VENV_ACTIVATE%"=="" call %VENV_ACTIVATE%

echo Starting trace console -- your browser should open automatically.
echo (First run may ask for an email -- just press Enter to skip it.)
streamlit run trace_console\app.py
