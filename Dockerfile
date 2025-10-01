FROM python:3.11-slim
LABEL authors="mruax"

# Устанавливаем зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl && \
    rm -rf /var/lib/apt/lists/*

# Создаем директорию для приложения
WORKDIR /app

# Устанавливаем Python-зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходники
COPY . .

# Запуск через Uvicorn
CMD ["uvicorn", "newparse:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]