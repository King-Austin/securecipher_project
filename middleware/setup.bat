@echo off
setlocal

echo ========================================================
echo    SecureCipher Project Setup for Windows (CMD Script)
echo ========================================================

REM 1) Check for Python
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.8+ and rerun this script.
    pause
    exit /b 1
)

REM 2) Ensure we're in project root
if not exist "requirements.txt" (
    echo ERROR: requirements.txt not found.
    echo Make sure you run this script from the project root.
    pause
    exit /b 1
)

REM 3) Create .env if missing
if not exist ".env" (
    if exist ".env.example" (
        echo .env not found → copying from .env.example...
        copy ".env.example" ".env" >nul
    ) else (
        echo WARNING: No .env or .env.example found.
        echo Create a .env with your environment variables now.
    )
)

echo.
echo STEP 1/4: Setting up virtual environment...
if not exist "venv\" (
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
) else (
    echo Virtual environment already exists.
)
call venv\Scripts\activate.bat

echo.
echo STEP 2/4: Upgrading pip and installing dependencies...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo ERROR: pip upgrade failed.
    pause
    exit /b 1
)
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo STEP 3/4: Applying database migrations and collecting static files...
python manage.py migrate --noinput
if errorlevel 1 (
    echo ERROR: Migrations failed.
    pause
    exit /b 1
)
python manage.py collectstatic --noinput
if errorlevel 1 (
    echo ERROR: collectstatic failed.
    pause
    exit /b 1
)

echo.
echo STEP 4/4: Creating default superuser...
python manage.py create_superuser
if errorlevel 1 (
    echo ERROR: Superuser creation failed.
    pause
    exit /b 1
)

echo.
echo ========================================================
echo ✅  Setup completed successfully!
echo To activate your environment later, run:
echo     call venv\Scripts\activate.bat
echo ========================================================
pause
endlocal