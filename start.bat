@echo off
chcp 65001 >nul
cd /d "%~dp0"
python campus_net.py
pause
