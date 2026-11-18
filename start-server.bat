@echo off
title Bethel Cakes Server
cd /d "%~dp0"

echo ==========================================
echo       BETHEL CAKES SERVER
echo ==========================================
echo.

echo Creating config.json...
(
echo {
echo   "port": 3000,
echo   "adminKey": "BethelAdmin2026",
echo   "smtp": {
echo     "host": "smtp.gmail.com",
echo     "port": 465,
echo     "secure": true,
echo     "user": "bethelcakesglobal@gmail.com",
echo     "pass": "hpiyuaeppegxzxuz",
echo     "from": "Bethel Cakes ^<bethelcakesglobal@gmail.com^>"
echo   }
echo }
) > config.json

echo Config created.
echo.

echo Installing required packages...
call npm install

echo.
echo Starting Bethel Cakes server...
echo.

node server.js

echo.
echo ==========================================
echo SERVER STOPPED
echo ==========================================
pause