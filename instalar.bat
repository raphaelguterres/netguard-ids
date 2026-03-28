@echo off
echo ============================================
echo  NetGuard IDS v3.0 - Instalacao de dependencias
echo ============================================
echo.

cd /d "%~dp0"

echo [1/2] Ativando ambiente virtual...
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo Criando ambiente virtual...
    python -m venv venv
    call venv\Scripts\activate.bat
)

echo [2/2] Instalando pacotes...
pip install flask flask-cors psutil scapy pyyaml pystray pillow plyer pywebview pyinstaller

echo.
echo ============================================
echo  Instalacao concluida!
echo  Execute: python netguard.py
echo ============================================
pause
