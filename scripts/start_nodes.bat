@echo off
REM Launches all 3 SigilChain validator nodes, each in its own window,
REM each with its own ledger DB. Run this from inside the sigilchain\
REM folder (the one containing validator\, agent\, watermark\).
REM
REM Tries to auto-find and activate your venv at a couple of likely
REM relative locations, so this works whether your folder ended up
REM single- or double-nested.

cd /d "%~dp0.."

set VENV_ACTIVATE=
if exist "..\venv\Scripts\activate.bat" set VENV_ACTIVATE=..\venv\Scripts\activate.bat
if exist "..\..\venv\Scripts\activate.bat" set VENV_ACTIVATE=..\..\venv\Scripts\activate.bat

if "%VENV_ACTIVATE%"=="" (
    echo Could not auto-find venv\Scripts\activate.bat near this folder.
    echo Activate your venv manually in each node window if they fail to start.
) else (
    echo Found venv at: %VENV_ACTIVATE%
)

echo Starting Node 1 on port 8001...
start "SigilChain Node 1 (8001)" cmd /k "cd /d %cd% && if not "%VENV_ACTIVATE%"=="" call %VENV_ACTIVATE% && set SIGILCHAIN_LEDGER_DB=node1.db && uvicorn validator.node:app --port 8001"

echo Starting Node 2 on port 8002...
start "SigilChain Node 2 (8002)" cmd /k "cd /d %cd% && if not "%VENV_ACTIVATE%"=="" call %VENV_ACTIVATE% && set SIGILCHAIN_LEDGER_DB=node2.db && uvicorn validator.node:app --port 8002"

echo Starting Node 3 on port 8003...
start "SigilChain Node 3 (8003)" cmd /k "cd /d %cd% && if not "%VENV_ACTIVATE%"=="" call %VENV_ACTIVATE% && set SIGILCHAIN_LEDGER_DB=node3.db && uvicorn validator.node:app --port 8003"

echo.
echo All 3 node windows launched. Wait for each to print
echo "Uvicorn running on http://127.0.0.1:800X" before using them.
echo.
pause
