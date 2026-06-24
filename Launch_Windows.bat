@echo off
title NK-CyberSuite Mobile Launcher
echo [*] Starting NK-CyberSuite Mobile engine...
python auto_apk_v4.py
if %errorlevel% neq 0 (
    echo [-] Engine encountered a runtime configuration fault.
    pause
)