@echo off
echo ===================================================
echo   Running Database Repair & Seed Tool
echo ===================================================

cd backend

echo.
echo [1/2] Installing critical dependencies...
pip install sqlalchemy fastapi uvicorn pydantic passlib[bcrypt] python-jose[cryptography] python-multipart

echo.
echo [2/2] Creating Database and Demo User...
python seed_data/seed.py

echo.
echo ===================================================
echo   Repair Complete!
echo   If you see "Seed completed successfully", 
echo   you can now run start_system.bat and login.
echo ===================================================
pause
