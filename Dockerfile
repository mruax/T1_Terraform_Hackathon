FROM python:3.11-slim
LABEL authors="mruax"

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Создаем директорию для приложения
WORKDIR /app

# Копируем requirements и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем приложение
COPY app/ ./app/

# Копируем статические файлы
COPY static/ ./static/

# Копируем главный HTML файл и конфигурацию
COPY terraform_viewer.html .
COPY plugin_config.json .

# Скрипт ожидания готовности БД
COPY <<'EOF' /app/wait-for-db.sh
#!/bin/bash
set -e

host="$1"
shift
cmd="$@"

until pg_isready -h "$host" -U terraform -d terraform_logs; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 1
done

>&2 echo "Postgres is up - executing command"
exec $cmd
EOF

RUN chmod +x /app/wait-for-db.sh

# Expose port
EXPOSE 8000

# Запуск через Uvicorn с ожиданием БД
CMD ["./wait-for-db.sh", "postgres", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--log-level", "debug"]
