# 🚀 Terraform Log Viewer

Advanced Terraform log analysis system with plugin architecture, database persistence, monitoring integration, and interactive Gantt visualization.

![Python](https://img.shields.io/badge/python-3.11-green)
![FastAPI](https://img.shields.io/badge/fastapi-0.118-teal)
![PostgreSQL](https://img.shields.io/badge/postgresql-15-blue)

## Features

### Ключевые возможности
- **Полнотекстовый поисковый движок** - Возможность искать по простым запросам, полям или regexp-выражениям
- **Интерактивная диаграмма Ганта** - Визуализация операций Terraform по времени
- **База данных** - Хранение всех логов в PostgreSQL
- **Система gRPC плагинов** - Модульная обработка логов (5 встроенных плагинов)
- **Поддержка безопасности** - Возможность автоматического редактирования конфиденциальных данных

## Быстрый старт

### Преквизиты
- Docker & Docker Compose
- 4GB RAM

### Запуск

1. **Склонировать репозиторий**

```bash
git clone https://github.com/mruax/T1_Terraform_Hackathon
cd T1_Terraform_Hackathon
```

2. **Запуск docker compose**

```bash
docker compose up --build
```

3. **Доступ к интерфейсу**

Открыть UI по адресу: `http://localhost:8000`

### Первые шаги

1. Нажмите "Drop log file here" или перетащите Terraform log файл на главной странице
2. Просмотр распаршенных логов на вкладке **Logs**
3. Для просмотра графиков Terraform операций переключиться на вкладку **Gantt Chart**
4. Проверить общие метрики сервиса можно на вкладке **Monitoring**

## Использование

### Веб Интерфейс

#### Логи
- **Загрузка**: Выбранный `.json` файл нужно перенести или нажать на кнопку загрузки
- **Фильтрация**: Поиск по тексту, фильтрам, regex или уровням логов (TRACE/DEBUG/INFO/WARN/ERROR/FATAL)
- **Прочтенные/непрочтенные**: Пометить логи как прочитанные/непрочитанные и отфильтровать по их статусу прочтения
- **Выбор логов**: Левый sidebar отображает список загруженных логов

#### Диаграмма Ганта
- **Просмотр временной шкалы**: Интерактивная визуализация Terraform операций
- **Информация по операциям**: При наведении на операции высвечивается краткое описание и их длительность
- **Детальная информация**: При нажатии на операцию открывается подробная информация об операции

#### Мониторинг
- **Дешборд с метриками**: Общее количество файлов, ошибки, предупреждения, health status
- **График**: Визуальное представление загрузки логов с течением времени

### API Usage

Описание апи нужно добавить TODO: 123 `http://localhost:8000/docs`

## Плагины

### 1. SensitiveDataPlugin
Автоматически редактирует конфиденциальную информацию.

**Обнаруживает:**
- Токены и ключи API
- Пароли
- Bearer tokens
- Заголовки авторизации
- Ключи AWS
- Токены JWT

### 2. FieldFilterPlugin
Включение или исключение определенных полей из логов.

### 3. LogLevelFilterPlugin
Фильтрация логов по уровню.

### 4. NoiseFilterPlugin
Удаление повторяющихся/шумных строк логов.

### 5. HTTPBodyCompressionPlugin
Сжатие больших HTTP тел запросов/ответов.

## Схема БД

### log_files
```sql
CREATE TABLE log_files (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_entries INTEGER,
    error_count INTEGER,
    warn_count INTEGER,
    metadata JSONB
);
```

### log_entries
```sql
CREATE TABLE log_entries (
    id SERIAL PRIMARY KEY,
    file_id INTEGER REFERENCES log_files(id) ON DELETE CASCADE,
    timestamp TIMESTAMP,
    level VARCHAR(10),
    message TEXT,
    raw_json JSONB,
    section_type VARCHAR(50),
    req_id VARCHAR(100)
);
```

## Дополнительная конфигурация (опционально)

### Переменные окружения

```bash
# Database URL
DATABASE_URL=postgresql://terraform:terraform@postgres:5432/terraform_logs

# API Settings
HOST=0.0.0.0
PORT=8000
```

## Интеграция с API

Возможные варианты интеграции.

### Prometheus

```yaml
scrape_configs:
  - job_name: 'terraform-logs'
    metrics_path: '/api/v1/health'
    static_configs:
      - targets: ['localhost:8000']
```

### Grafana

Создать JSON API data source направляющий на:
```
http://localhost:8000/api/v1/metrics
```

### PagerDuty

```python
import requests

alerts = requests.get("http://localhost:8000/api/v1/alerts?severity=ERROR").json()

for alert in alerts['alerts']:
    pagerduty_create_incident(
        title=f"Terraform Error: {alert['message']}",
        details=alert
    )
```

## Разработка

### Локальный запуск

```bash
# Install dependencies
pip install -r requirements.txt

# Start PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_USER=terraform \
  -e POSTGRES_PASSWORD=terraform \
  -e POSTGRES_DB=terraform_logs \
  postgres:15-alpine

# Run the application
uvicorn terraform_log_parser:app --reload
```

### Добавление кастомных плагинов

```python
from terraform_log_parser import LogPlugin, LogEntry

class CustomPlugin(LogPlugin):
    def process_json(self, json_obj):
        # Modify JSON before parsing
        return json_obj
    
    def process_entry(self, entry: LogEntry):
        # Modify or filter parsed entry
        return entry

# Use it
parser = TerraformLogParser(plugins=[CustomPlugin()])
```

## Советы по оптимизации

1. Используйте `compress_bodies=true` при больших размерах тел HTTP запросов
2. Примените `min_level=INFO` и `remove_noise=true` для уменьшения шума
3. Используйте фильтрацию полей для уменьшения размера поиска данных

## Безопасность

### Лучшие практики

1. **Всегда включайте** `redact_sensitive` в production среде
2. **Используйте переменные среды** для учетных данных базы данных
3. **Включите HTTPS** для production развертываний
4. **Ограничьте доступ к API** с помощью промежуточного программного обеспечения для проверки подлинности
5. **Регулярное резервное копирование** базы данных PostgreSQL

## Планы на будущее

1. Система авторизации
2. Улучшенный ui, больше видов диаграмм для анализа данных, более сложный поисковой движок

---

С уважением, команда **Позвоночник ► Вежливость**
