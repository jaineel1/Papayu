@echo off
echo ===========================================
echo   Setting up Isolated Python Environment
echo ===========================================

cd backend

echo.
echo [1/4] Creating Virtual Environment (venv)...
python -m venv venv

echo.
echo [2/4] Activating venv...
call venv\Scripts\activate

echo.
echo [3/4] Installing dependencies into venv...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install passlib[bcrypt] python-jose[cryptography] python-multipart
python -m pip install sqlalchemy

echo.
echo [4/4] Seeding Database...
REM Just in case sql_app.db is missing
python seed_data/seed.py

echo.
echo ===========================================
echo   Environment Setup Complete!
echo   You can now run start_system.bat
echo ===========================================
pause
