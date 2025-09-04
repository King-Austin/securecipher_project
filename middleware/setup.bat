@echo off
echo Running SecureCipher Setup on Windows...

REM Check if Python is installed
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH
    exit /b 1
)

REM Create and activate virtual environment
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

REM Run Django commands
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py create_superuser

echo "✨ Setup completed successfully!"