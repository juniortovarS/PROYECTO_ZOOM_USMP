# Imagen base de Python ligera
FROM python:3.11-slim

# Evitar que Python escriba archivos .pyc y forzar salida de consola inmediata
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Directorio de trabajo en el contenedor
WORKDIR /app

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todo el código fuente del proyecto
COPY . .

# Exponer el puerto del servidor FastAPI
EXPOSE 8000

# Comando para iniciar FastAPI en producción
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
