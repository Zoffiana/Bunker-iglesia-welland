@echo off
REM Inicia la app de Tesorería (funciona aunque streamlit no esté en PATH)
cd /d "%~dp0"
python -m streamlit run app.py --server.port 8501
pause
