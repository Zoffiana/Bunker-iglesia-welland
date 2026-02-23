# Iglesia Pentecostal de Welland - Sistema de Tesorería
FROM python:3.11-slim

WORKDIR /app

# Tesseract para OCR (opcional, para detección de facturas)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-spa \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
