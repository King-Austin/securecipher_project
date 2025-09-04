@echo off
setlocal

echo ========================================================
echo    SecureCipher Banking API Setup for Windows
echo ========================================================

REM Check for Git
where git >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed or not in PATH.
    echo Please install Git and rerun this script.
    pause
    exit /b 1
)

REM Pull latest changes
echo Pulling latest changes...
git pull origin master
if errorlevel 1 (
    echo ERROR: Git pull failed.
    pause
    exit /b 1
)

REM 1) Check for Python
where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.8+ and rerun this script.
    pause
    exit /b 1
)

REM Create static directory if it doesn't exist
if not exist "static\" (
    echo Creating static directory...
    mkdir static
)

REM 2) Rest of your existing checks...
if not exist "requirements.txt" (
    echo ERROR: requirements.txt not found.
    echo Make sure you run this script from the project root.
    pause
    exit /b 1
)

REM 3) Create .env if missing
if not exist ".env" (
    if exist ".env.example" (
        echo Copying .env.example to .env...
        copy ".env.example" ".env" >nul
    ) else (
        echo WARNING: No .env or .env.example found.
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
)
call venv\Scripts\activate.bat

echo.
echo STEP 2/4: Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Dependency installation failed.
    pause
    exit /b 1
)

echo.
echo STEP 3/4: Setting up database...
python manage.py migrate --noinput
python manage.py collectstatic --noinput

echo.
echo STEP 4/4: Creating superuser...
python manage.py create_superuser

echo.
echo ========================================================
echo ✅ Setup completed! Starting development server...
echo ========================================================

REM Start the development server on port 8001 (different from middleware)
python manage.py runserver 0.0.0.0:8001

endlocal