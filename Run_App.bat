@echo off
title Behavioral Threat Defense Launcher
cd /d "%~dp0"

:: Check if virtual environment exists
if not exist ".venv\Scripts\pythonw.exe" (
    echo ========================================================
    echo  ERROR: Virtual environment (.venv) was not found!
    echo  Please ensure the .venv directory exists in:
    echo  %~dp0
    echo ========================================================
    pause
    exit /b 1
)

:: Launch the application cleanly in the background without keeping a CMD window open
start "" ".venv\Scripts\pythonw.exe" gui.py
exit
