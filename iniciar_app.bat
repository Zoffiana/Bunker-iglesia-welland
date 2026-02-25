@echo off
REM Inicia la app de Tesorería (usa python -m porque streamlit puede no estar en PATH)
cd /d "%~dp0"
echo Iniciando Sistema de Tesorería...
echo Abriendo en http://localhost:8501
python -m streamlit run app.py --server.port 8501
if errorlevel 1 (
    echo.
    echo Si aparece error, instale dependencias con:
    echo   pip install -r requirements.txt
)
pause
