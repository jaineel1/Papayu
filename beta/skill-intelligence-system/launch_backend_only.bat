@echo off
echo ===========================================
echo   Final Repair: Installing Web Server
echo ===========================================

cd backend

echo.
echo [1/3] Activating venv...
call venv\Scripts\activate

echo.
echo [2/3] Force Installing Uvicorn...
python -m pip install uvicorn fastapi standard-imghdr

echo.
echo [3/3] Starting Backend Server...
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
