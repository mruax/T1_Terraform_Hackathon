# 🚀 Terraform Log Viewer

Advanced Terraform log analysis system with plugin architecture, database persistence, monitoring integration, and interactive Gantt visualization.

![Python](https://img.shields.io/badge/python-3.11-green)
![FastAPI](https://img.shields.io/badge/fastapi-0.118-teal)
![PostgreSQL](https://img.shields.io/badge/postgresql-15-blue)

## Features

### Core Features
- **Interactive Gantt Chart** - Visualize Terraform operation timelines
- **Database Persistence** - PostgreSQL storage for all logs
- **Plugin System** - Modular log processing (5 built-in plugins)
- **Security** - Automatic sensitive data redaction
- **Read/Unread Tracking** - Mark logs as read/unread

## Quick Start

### Prerequisites
- Docker & Docker Compose
- 4GB RAM recommended

### Installation

1. **Clone the repository**

```bash
git clone <repository-url>
cd T1_Terraform_Hackathon
```

2. **Start the services**

```bash
docker compose up --build
```

3. **Access the interface**

Open your browser: `http://localhost:8000`

That's it! The system is ready to use.

### First Steps

1. Click "Drop log file here" or drag & drop a Terraform log file
2. View parsed logs in the **Logs** tab
3. Switch to **Gantt Chart** tab to see operation timeline
4. Check **Monitoring** tab for overall metrics

## Usage

### Web Interface

#### Logs Tab
- **Upload**: Drag & drop or click to upload `.log`, `.txt`, or `.json` files
- **Filter**: Search by text, filter by log level (TRACE/DEBUG/INFO/WARN/ERROR/FATAL)
- **Read/Unread**: Mark logs as read and filter by unread status
- **File Selector**: Left sidebar shows all uploaded files

#### Gantt Chart Tab
- **Timeline View**: Interactive visualization of Terraform operations
- **Duration Info**: Hover over bars to see operation duration
- **Operation Details**: Click bars to see detailed information

#### Monitoring Tab
- **Metrics Dashboard**: Total files, errors, warnings, health status
- **Charts**: Visual representation of log uploads over time

### API Usage

Use `http://localhost:8000/docs`

## Plugins

### 1. SensitiveDataPlugin
Automatically redacts sensitive information.

**Detects:**
- API tokens and keys
- Passwords
- Bearer tokens
- Authorization headers
- AWS keys
- JWT tokens

### 2. FieldFilterPlugin
Include or exclude specific fields from logs.

### 3. LogLevelFilterPlugin
Filter logs by minimum level.

### 4. NoiseFilterPlugin
Remove repetitive, noisy log messages.

### 5. HTTPBodyCompressionPlugin
Compress large HTTP request/response bodies.

## Database Schema

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

## Configuration

### Environment Variables

```bash
# Database URL
DATABASE_URL=postgresql://terraform:terraform@postgres:5432/terraform_logs

# API Settings
HOST=0.0.0.0
PORT=8000
```

### Plugin Presets

**Production (Secure):**
```bash
?redact_sensitive=true&min_level=INFO&remove_noise=true&compress_bodies=true
```

**Development (Full Debug):**
```bash
?redact_sensitive=false&min_level=TRACE&remove_noise=false&compress_bodies=false
```

**Monitoring (Errors Only):**
```bash
?min_level=ERROR&remove_noise=true
```

## API Integration

### Prometheus

```yaml
scrape_configs:
  - job_name: 'terraform-logs'
    metrics_path: '/api/v1/health'
    static_configs:
      - targets: ['localhost:8000']
```

### Grafana

Create a JSON API data source pointing to:
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

## Development

### Local Setup

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

### Adding Custom Plugins

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

## Optimization Tips

1. Use `compress_bodies=true` for large HTTP payloads
2. Apply `min_level=INFO` to reduce noise
3. Enable `remove_noise=true` for production logs
4. Use field filtering to reduce database size

## Security

### Best Practices

1. **Always enable** `redact_sensitive` in production
2. **Use environment variables** for database credentials
3. **Enable HTTPS** for production deployments
4. **Restrict API access** with authentication middleware
5. **Regular backups** of PostgreSQL database

---

**Sincerely yours, Pozvonochnik Vezhlivost**
