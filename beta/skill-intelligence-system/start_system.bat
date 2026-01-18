@echo off
SETLOCAL EnableExtensions

echo ===================================================
echo   Holistic Skill Intelligence System - Startup
echo ===================================================

echo.
echo [1/3] Starting Backend...
echo       Using Virtual Environment at backend\venv
start "Backend Server" cmd /k "cd backend && venv\Scripts\uvicorn.exe app.main:app --reload --host 127.0.0.1 --port 8000"

echo.
echo [2/3] Starting Frontend...
echo       Listening on http://localhost:5173
start "Frontend Application" cmd /k "cd frontend && call npm install && npm run dev"

echo.
echo [3/3] Opening Application...
timeout /t 5 >nul
start http://localhost:5173

echo.
echo ===================================================
echo   System is running!
echo ===================================================
pause
