# Terraform Log Processor API Documentation

## Overview

Terraform Log Processor API v2.0 provides advanced log analysis, monitoring integration, and visualization capabilities.

**Base URL:** `http://localhost:8000`

**API Version:** 2.0.0

---

## Table of Contents

1. [Log Management](#log-management)
2. [Monitoring & Integration](#monitoring--integration)
3. [Visualization](#visualization)
4. [Plugin Configuration](#plugin-configuration)

---

## Log Management

### Upload Log File

Upload and parse a Terraform log file with configurable plugins.

**Endpoint:** `POST /upload-log/`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `file` | file | required | Log file (.log, .txt, .json) |
| `redact_sensitive` | boolean | true | Remove sensitive data (tokens, passwords) |
| `min_level` | string | TRACE | Minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL) |
| `remove_noise` | boolean | false | Filter noisy repetitive logs |
| `compress_bodies` | boolean | false | Compress large HTTP bodies |
| `exclude_fields` | string | null | Comma-separated fields to exclude |
| `include_fields` | string | null | Comma-separated fields to include (whitelist) |

**Example Request:**

```bash
curl -X POST "http://localhost:8000/upload-log/?redact_sensitive=true&min_level=INFO&exclude_fields=@caller,internal_id" \
  -F "file=@terraform.log"
```

**Response:**

```json
{
  "status": "success",
  "file_id": 1,
  "total_entries": 1523,
  "entries": [...],
  "sections_detected": ["plan", "apply"],
  "linked_pairs": 45,
  "plugins_applied": [
    "SensitiveDataPlugin",
    "FieldFilterPlugin",
    "LogLevelFilterPlugin"
  ]
}
```

---

### List Log Files

Get all uploaded log files with metadata.

**Endpoint:** `GET /logs/`

**Example Request:**

```bash
curl "http://localhost:8000/logs/"
```

**Response:**

```json
[
  {
    "id": 1,
    "filename": "terraform-apply.log",
    "upload_date": "2025-10-01T14:30:00",
    "total_entries": 1523,
    "error_count": 3,
    "warn_count": 12
  }
]
```

---

### Get Log Details

Retrieve all entries from a specific log file.

**Endpoint:** `GET /logs/{file_id}`

**Example Request:**

```bash
curl "http://localhost:8000/logs/1"
```

**Response:**

```json
{
  "file_id": 1,
  "total_entries": 1523,
  "entries": [
    {
      "timestamp": "2025-10-01T14:25:30.123456",
      "level": "INFO",
      "message": "Terraform version: 1.13.1",
      "section_type": "init"
    }
  ]
}
```

---

### Delete Log File

Delete a log file and all its entries.

**Endpoint:** `DELETE /logs/{file_id}`

**Example Request:**

```bash
curl -X DELETE "http://localhost:8000/logs/1"
```

**Response:**

```json
{
  "status": "deleted",
  "file_id": 1
}
```

---

## Monitoring & Integration

### Health Status

Get overall system health for monitoring tools (Prometheus, Datadog, etc.).

**Endpoint:** `GET /api/v1/health`

**Example Request:**

```bash
curl "http://localhost:8000/api/v1/health"
```

**Response:**

```json
{
  "status": "healthy",
  "total_errors": 15,
  "total_warnings": 48,
  "recent_files": 5
}
```

**Status Values:**
- `healthy` - No critical errors
- `degraded` - Errors detected

**Integration Example (Prometheus):**

```yaml
scrape_configs:
  - job_name: 'terraform-logs'
    metrics_path: '/api/v1/health'
    static_configs:
      - targets: ['localhost:8000']
```

---

### Get Alerts

Retrieve log entries matching alert severity for incident management systems.

**Endpoint:** `GET /api/v1/alerts`

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `severity` | string | ERROR | ERROR or WARN |

**Example Request:**

```bash
curl "http://localhost:8000/api/v1/alerts?severity=ERROR"
```

**Response:**

```json
{
  "severity": "ERROR",
  "count": 15,
  "alerts": [
    {
      "file_id": 1,
      "filename": "terraform-apply.log",
      "timestamp": "2025-10-01T14:30:45",
      "level": "ERROR",
      "message": "Failed to acquire state lock",
      "section": "plan"
    }
  ]
}
```

**Integration Example (PagerDuty):**

```python
import requests

alerts = requests.get("http://localhost:8000/api/v1/alerts?severity=ERROR").json()

for alert in alerts['alerts']:
    if alert['level'] == 'ERROR':
        # Send to PagerDuty
        pagerduty_create_incident(
            title=f"Terraform Error: {alert['message']}",
            details=alert
        )
```

---

### Get Metrics

Retrieve aggregated metrics for monitoring dashboards.

**Endpoint:** `GET /api/v1/metrics`

**Example Request:**

```bash
curl "http://localhost:8000/api/v1/metrics"
```

**Response:**

```json
{
  "total_files": 10,
  "total_logs": 15234,
  "total_errors": 45,
  "total_warnings": 132,
  "error_rate": 0.295,
  "files_by_date": {
    "2025-10-01": 3,
    "2025-09-30": 7
  }
}
```

**Integration Example (Grafana):**

```sql
-- JSON API Data Source
SELECT 
  total_errors,
  total_warnings,
  error_rate
FROM json_api('http://localhost:8000/api/v1/metrics')
```

---

## Visualization

### Gantt Chart Data

Get timeline data for Terraform operations visualization.

**Endpoint:** `GET /api/v1/gantt/{file_id}`

**Example Request:**

```bash
curl "http://localhost:8000/api/v1/gantt/1"
```

**Response:**

```json
{
  "file_id": 1,
  "gantt_data": [
    {
      "task": "plan",
      "start": "2025-10-01T14:25:30",
      "end": "2025-10-01T14:26:15",
      "duration": 45.0,
      "log_count": 234
    },
    {
      "task": "apply",
      "start": "2025-10-01T14:26:20",
      "end": "2025-10-01T14:28:45",
      "duration": 145.0,
      "log_count": 567
    }
  ]
}
```

---

## Plugin Configuration

### Available Plugins

1. **SensitiveDataPlugin** - Redacts API tokens, passwords, secrets
2. **FieldFilterPlugin** - Include/exclude specific fields
3. **LogLevelFilterPlugin** - Filter by log level
4. **NoiseFilterPlugin** - Remove repetitive logs
5. **HTTPBodyCompressionPlugin** - Compress large HTTP bodies

### Configuration Examples

**Basic Security (Production):**

```bash
curl -X POST "http://localhost:8000/upload-log/\
?redact_sensitive=true\
&min_level=INFO\
&remove_noise=true\
&compress_bodies=true" \
  -F "file=@terraform.log"
```

**Debugging Mode:**

```bash
curl -X POST "http://localhost:8000/upload-log/\
?redact_sensitive=false\
&min_level=TRACE\
&remove_noise=false" \
  -F "file=@terraform.log"
```

**Field Filtering:**

```bash
# Whitelist mode - only keep important fields
curl -X POST "http://localhost:8000/upload-log/\
?include_fields=@message,@level,@timestamp,tf_req_id" \
  -F "file=@terraform.log"

# Blacklist mode - remove specific fields
curl -X POST "http://localhost:8000/upload-log/\
?exclude_fields=@caller,internal_id,debug_info" \
  -F "file=@terraform.log"
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Invalid request (wrong file type, invalid parameters) |
| 404 | Resource not found (log file doesn't exist) |
| 500 | Internal server error |

---

## Rate Limits

No rate limits currently enforced. Recommended for internal use only.

For production deployment, consider adding rate limiting:

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/upload-log/")
@limiter.limit("10/minute")
async def upload_log(...):
    ...
```

---

## WebSocket Support (Future)

Real-time log streaming coming in v2.1:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/logs/1');
ws.onmessage = (event) => {
  const log = JSON.parse(event.data);
  console.log('New log:', log);
};
```

---

## Client Libraries

### Python

```python
import requests

class TerraformLogClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
    
    def upload_log(self, filepath, redact=True, min_level="INFO"):
        with open(filepath, 'rb') as f:
            response = requests.post(
                f"{self.base_url}/upload-log/",
                files={'file': f},
                params={
                    'redact_sensitive': redact,
                    'min_level': min_level
                }
            )
        return response.json()
    
    def get_alerts(self, severity="ERROR"):
        response = requests.get(
            f"{self.base_url}/api/v1/alerts",
            params={'severity': severity}
        )
        return response.json()

# Usage
client = TerraformLogClient()
result = client.upload_log('terraform.log')
alerts = client.get_alerts()
```

### JavaScript

```javascript
class TerraformLogClient {
  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl;
  }
  
  async uploadLog(file, options = {}) {
    const formData = new FormData();
    formData.append('file', file);
    
    const params = new URLSearchParams({
      redact_sensitive: options.redact ?? true,
      min_level: options.minLevel ?? 'INFO'
    });
    
    const response = await fetch(
      `${this.baseUrl}/upload-log/?${params}`,
      {
        method: 'POST',
        body: formData
      }
    );
    
    return await response.json();
  }
  
  async getMetrics() {
    const response = await fetch(`${this.baseUrl}/api/v1/metrics`);
    return await response.json();
  }
}

// Usage
const client = new TerraformLogClient();
const result = await client.uploadLog(fileInput.files[0]);
```

---

## OpenAPI Specification

Full OpenAPI 3.0 spec available at:

```
http://localhost:8000/docs
http://localhost:8000/redoc
http://localhost:8000/openapi.json
```

---

## Support

For issues and feature requests, please visit our GitHub repository or contact the development team.
