# Inicia la app de Tesorería (PowerShell)
# Usa python -m streamlit porque "streamlit" puede no estar en PATH
Set-Location $PSScriptRoot
Write-Host "Iniciando Sistema de Tesorería..." -ForegroundColor Cyan
Write-Host "Abriendo en http://localhost:8501" -ForegroundColor Green
python -m streamlit run app.py --server.port 8501
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nSi aparece 'streamlit' no reconocido, instale dependencias:" -ForegroundColor Yellow
    Write-Host "  pip install -r requirements.txt" -ForegroundColor Yellow
    Read-Host "Presione Enter para salir"
}
