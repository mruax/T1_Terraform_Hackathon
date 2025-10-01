import re
import json
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod

# ==================== ENHANCED LOG LEVEL & TIMESTAMP EXTRACTION ====================

class LogLevel(Enum):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARN = 3
    ERROR = 4
    FATAL = 5

@dataclass
class LogEntry:
    timestamp: datetime
    level: LogLevel
    message: str
    raw_json: Optional[Dict[str, Any]] = None
    caller: Optional[str] = None
    module: Optional[str] = None
    terraform_metadata: Optional[Dict[str, Any]] = None
    http_request: Optional[Dict[str, Any]] = None
    http_response: Optional[Dict[str, Any]] = None
    section_type: Optional[str] = None
    req_id: Optional[str] = None
    rpc: Optional[str] = None


# ==================== PLUGIN SYSTEM ====================

class LogPlugin(ABC):
    """Base class for log processing plugins"""
    
    @abstractmethod
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """
        Process a log entry. Return None to filter it out.
        Return modified entry to transform it.
        """
        pass
    
    @abstractmethod
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw JSON object before parsing"""
        pass


class SensitiveDataPlugin(LogPlugin):
    """Remove sensitive data like API tokens, passwords, secrets"""
    
    SENSITIVE_KEYS = {
        'token', 'api_key', 'apikey', 'password', 'secret', 
        'authorization', 'auth', 'api_token', 'access_token',
        'refresh_token', 'bearer', 'credentials', 'private_key'
    }
    
    # Patterns for detecting sensitive data in strings
    TOKEN_PATTERN = re.compile(r'(?:bearer\s+|token[\s:=]+)[a-zA-Z0-9_\-\.]+', re.I)
    KEY_PATTERN = re.compile(r'(?:api[_\-]?key[\s:=]+)[a-zA-Z0-9_\-]+', re.I)
    
    def __init__(self, redact_value: str = "[REDACTED]"):
        self.redact_value = redact_value
    
    def _redact_value(self, value: Any) -> Any:
        """Redact a sensitive value"""
        if isinstance(value, str) and len(value) > 10:
            # Keep first 4 chars for debugging
            return f"{value[:4]}...{self.redact_value}"
        return self.redact_value
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize dictionary"""
        sanitized = {}
        
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if key contains sensitive term
            if any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS):
                sanitized[key] = self._redact_value(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            elif isinstance(value, str):
                # Check if value contains sensitive patterns
                if self.TOKEN_PATTERN.search(value) or self.KEY_PATTERN.search(value):
                    sanitized[key] = self._redact_value(value)
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize JSON object"""
        return self._sanitize_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Sanitize log entry"""
        if entry.http_request:
            entry.http_request = self._sanitize_dict(entry.http_request)
        if entry.http_response:
            entry.http_response = self._sanitize_dict(entry.http_response)
        if entry.terraform_metadata:
            entry.terraform_metadata = self._sanitize_dict(entry.terraform_metadata)
        
        return entry


class FieldFilterPlugin(LogPlugin):
    """Remove unnecessary fields from logs"""
    
    def __init__(self, exclude_fields: List[str] = None, include_fields: List[str] = None):
        """
        Args:
            exclude_fields: List of field names to exclude
            include_fields: If set, only keep these fields (whitelist mode)
        """
        self.exclude_fields = set(exclude_fields or [])
        self.include_fields = set(include_fields) if include_fields else None
    
    def _filter_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Filter dictionary fields"""
        if self.include_fields:
            # Whitelist mode
            return {k: v for k, v in data.items() if k in self.include_fields}
        else:
            # Blacklist mode
            return {k: v for k, v in data.items() if k not in self.exclude_fields}
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Filter JSON fields"""
        return self._filter_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Entry is already parsed, no additional filtering needed here"""
        return entry


class LogLevelFilterPlugin(LogPlugin):
    """Filter out logs below a certain level"""
    
    def __init__(self, min_level: LogLevel = LogLevel.TRACE):
        self.min_level = min_level
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """No JSON processing needed"""
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Filter by log level"""
        if entry.level.value < self.min_level.value:
            return None  # Filter out
        return entry


class NoiseFilterPlugin(LogPlugin):
    """Filter out noisy/repetitive log messages"""
    
    def __init__(self, noise_patterns: List[str] = None):
        """
        Args:
            noise_patterns: List of regex patterns to filter out
        """
        default_patterns = [
            r'Schema\s+for\s+provider.*is\s+in\s+the\s+global\s+cache',
            r'Checking\s+.*\s+lock',
            r'ignoring\s+non-existing\s+provider',
        ]
        patterns = noise_patterns or default_patterns
        self.noise_regexes = [re.compile(p, re.I) for p in patterns]
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """No JSON processing needed"""
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Filter noisy messages"""
        for pattern in self.noise_regexes:
            if pattern.search(entry.message):
                return None  # Filter out
        return entry


class HTTPBodyCompressionPlugin(LogPlugin):
    """Compress large HTTP bodies by summarizing"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
    
    def _compress_body(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Compress body if too large"""
        body_str = json.dumps(body)
        
        if len(body_str) > self.max_size:
            # Keep only structure and first few items
            compressed = {
                "_compressed": True,
                "_original_size": len(body_str),
                "_summary": {}
            }
            
            for key, value in list(body.items())[:5]:
                if isinstance(value, list) and len(value) > 3:
                    compressed["_summary"][key] = f"[Array with {len(value)} items]"
                elif isinstance(value, dict):
                    compressed["_summary"][key] = f"{{Object with {len(value)} keys}}"
                else:
                    compressed["_summary"][key] = value
            
            return compressed
        
        return body
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """No JSON processing needed"""
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Compress HTTP bodies"""
        if entry.http_request:
            entry.http_request = self._compress_body(entry.http_request)
        if entry.http_response:
            entry.http_response = self._compress_body(entry.http_response)
        return entry


# ==================== TERRAFORM LOG PARSER WITH PLUGINS ====================

class TerraformLogParser:
    # Регулярные выражения для извлечения timestamp
    ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?')
    TIME_RE = re.compile(r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b')
    EPOCH_MS_RE = re.compile(r'\b1[0-9]{12}\b')
    EPOCH_S_RE = re.compile(r'\b1[0-9]{9,10}\b')
    
    # Регулярные выражения для log level
    LEVEL_RE = re.compile(r'\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b', re.I)
    
    # Секции Terraform
    SECTION_PATTERNS = {
        'plan_start': re.compile(r'backend/local:\s+starting\s+Plan\s+operation', re.I),
        'apply_start': re.compile(r'backend/local:\s+starting\s+Apply\s+operation', re.I),
        'validation_start': re.compile(r'running\s+validation\s+operation', re.I),
        'plan_end': re.compile(r'Plan:\s+\d+\s+to\s+add', re.I),
        'apply_end': re.compile(r'Apply\s+complete', re.I),
    }
    
    def __init__(self, plugins: List[LogPlugin] = None):
        self.current_section = None
        self.plugins = plugins or []
    
    def add_plugin(self, plugin: LogPlugin):
        """Add a plugin to the parser"""
        self.plugins.append(plugin)
    
    def extract_timestamp(self, log_str: str, json_obj: Optional[Dict] = None) -> Optional[datetime]:
        """Эвристическое извлечение timestamp из строки или JSON"""
        if json_obj and '@timestamp' in json_obj:
            try:
                ts_str = json_obj['@timestamp']
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        
        m = self.ISO_RE.search(log_str)
        if m:
            try:
                return datetime.fromisoformat(m.group(0).replace('Z', '+00:00'))
            except ValueError:
                pass
        
        m = self.TIME_RE.search(log_str)
        if m:
            try:
                today = datetime.utcnow().date()
                return datetime.fromisoformat(f"{today}T{m.group(0)}")
            except ValueError:
                pass
        
        m = self.EPOCH_MS_RE.search(log_str)
        if m:
            try:
                return datetime.utcfromtimestamp(int(m.group(0)) / 1000.0)
            except (ValueError, OSError):
                pass
        
        m = self.EPOCH_S_RE.search(log_str)
        if m:
            try:
                return datetime.utcfromtimestamp(int(m.group(0)))
            except (ValueError, OSError):
                pass
        
        return None
    
    def extract_level(self, log_str: str, json_obj: Optional[Dict] = None) -> LogLevel:
        """Эвристическое извлечение log level"""
        if json_obj and '@level' in json_obj:
            level_str = str(json_obj['@level']).upper()
            try:
                return LogLevel[level_str]
            except KeyError:
                pass
        
        m = self.LEVEL_RE.search(log_str)
        if m:
            level_str = m.group(1).upper()
            if level_str == 'WARNING':
                level_str = 'WARN'
            try:
                return LogLevel[level_str]
            except KeyError:
                pass
        
        lower_str = log_str.lower()
        if any(kw in lower_str for kw in ['exception', 'failed', 'panic', 'fatal', 'error']):
            return LogLevel.ERROR
        if any(kw in lower_str for kw in ['warning', 'warn']):
            return LogLevel.WARN
        if any(kw in lower_str for kw in ['debug']):
            return LogLevel.DEBUG
        if any(kw in lower_str for kw in ['trace']):
            return LogLevel.TRACE
        
        return LogLevel.INFO
    
    def detect_section(self, message: str) -> Optional[str]:
        """Определение секции Terraform операции"""
        for section_name, pattern in self.SECTION_PATTERNS.items():
            if pattern.search(message):
                if section_name.endswith('_start'):
                    self.current_section = section_name.replace('_start', '')
                elif section_name.endswith('_end'):
                    section = self.current_section
                    self.current_section = None
                    return section
                return self.current_section
        return self.current_section
    
    def extract_http_bodies(self, json_obj: Dict[str, Any]) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Извлечение и парсинг HTTP request/response bodies"""
        http_req = None
        http_resp = None
        
        if 'tf_http_req_body' in json_obj:
            try:
                body_str = json_obj['tf_http_req_body']
                if isinstance(body_str, str) and body_str.strip():
                    http_req = json.loads(body_str)
            except json.JSONDecodeError:
                http_req = {'raw': json_obj['tf_http_req_body']}
        
        if 'tf_http_res_body' in json_obj:
            try:
                body_str = json_obj['tf_http_res_body']
                if isinstance(body_str, str) and body_str.strip():
                    http_resp = json.loads(body_str)
            except json.JSONDecodeError:
                http_resp = {'raw': json_obj['tf_http_res_body']}
        
        return http_req, http_resp
    
    def extract_terraform_metadata(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        """Извлечение метаданных Terraform"""
        metadata = {}
        
        tf_keys = [
            'tf_provider_addr', 'tf_resource_type', 'tf_data_source_type',
            'tf_req_id', 'tf_rpc', 'tf_proto_version', 'tf_mux_provider'
        ]
        
        for key in tf_keys:
            if key in json_obj:
                metadata[key] = json_obj[key]
        
        return metadata if metadata else None
    
    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Парсинг одной строки лога"""
        if not line.strip():
            return None
        
        json_obj = None
        
        try:
            json_obj = json.loads(line)
            
            # Apply JSON plugins
            for plugin in self.plugins:
                json_obj = plugin.process_json(json_obj)
                
        except json.JSONDecodeError:
            pass
        
        timestamp = self.extract_timestamp(line, json_obj)
        if not timestamp:
            timestamp = datetime.utcnow()
        
        level = self.extract_level(line, json_obj)
        
        if json_obj and '@message' in json_obj:
            message = json_obj['@message']
        else:
            message = line
        
        section = self.detect_section(message)
        
        http_req, http_resp = None, None
        if json_obj:
            http_req, http_resp = self.extract_http_bodies(json_obj)
        
        tf_metadata = None
        if json_obj:
            tf_metadata = self.extract_terraform_metadata(json_obj)
        
        caller = json_obj.get('@caller') if json_obj else None
        module = json_obj.get('@module') if json_obj else None
        req_id = json_obj.get('tf_req_id') if json_obj else None
        rpc = json_obj.get('tf_rpc') if json_obj else None
        
        entry = LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            raw_json=json_obj,
            caller=caller,
            module=module,
            terraform_metadata=tf_metadata,
            http_request=http_req,
            http_response=http_resp,
            section_type=section,
            req_id=req_id,
            rpc=rpc
        )
        
        # Apply entry plugins
        for plugin in self.plugins:
            entry = plugin.process_entry(entry)
            if entry is None:
                return None  # Filtered out
        
        return entry
    
    def parse_file(self, file_path: str) -> List[LogEntry]:
        """Парсинг файла с логами"""
        entries = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                entry = self.parse_line(line)
                if entry:
                    entries.append(entry)
        
        return entries


# ==================== FASTAPI ENDPOINT ====================

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import io

app = FastAPI(title="Terraform Log Processor with Plugins")

class LogEntryResponse(BaseModel):
    timestamp: str
    level: str
    message: str
    caller: Optional[str] = None
    module: Optional[str] = None
    section_type: Optional[str] = None
    terraform_metadata: Optional[Dict[str, Any]] = None
    has_http_request: bool = False
    has_http_response: bool = False
    req_id: Optional[str] = None
    rpc: Optional[str] = None

@app.post("/upload-log/")
async def upload_log(
    file: UploadFile = File(...),
    redact_sensitive: bool = Query(True, description="Remove sensitive data like tokens"),
    min_level: str = Query("TRACE", description="Minimum log level to include"),
    remove_noise: bool = Query(False, description="Filter out noisy repetitive logs"),
    compress_bodies: bool = Query(False, description="Compress large HTTP bodies")
):
    """
    Upload and parse Terraform log file with configurable plugins
    """
    if not file.filename.endswith(('.log', '.txt', '.json')):
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    try:
        # Configure plugins
        plugins = []
        
        if redact_sensitive:
            plugins.append(SensitiveDataPlugin())
        
        try:
            level_enum = LogLevel[min_level.upper()]
            plugins.append(LogLevelFilterPlugin(level_enum))
        except KeyError:
            pass
        
        if remove_noise:
            plugins.append(NoiseFilterPlugin())
        
        if compress_bodies:
            plugins.append(HTTPBodyCompressionPlugin())
        
        # Initialize parser with plugins
        parser = TerraformLogParser(plugins=plugins)
        
        # Read and parse file
        content = await file.read()
        lines = content.decode('utf-8').splitlines()
        
        entries = []
        for line in lines:
            entry = parser.parse_line(line)
            if entry:
                entries.append(entry)
        
        # Build request-response map
        req_resp_map = {}
        for i, entry in enumerate(entries):
            if entry.req_id:
                if entry.req_id not in req_resp_map:
                    req_resp_map[entry.req_id] = {}
                if entry.http_request:
                    req_resp_map[entry.req_id]['request'] = i
                if entry.http_response:
                    req_resp_map[entry.req_id]['response'] = i
        
        # Convert to response format
        response_entries = []
        for entry in entries[:100]:
            response_entries.append(LogEntryResponse(
                timestamp=entry.timestamp.isoformat(),
                level=entry.level.name,
                message=entry.message,
                caller=entry.caller,
                module=entry.module,
                section_type=entry.section_type,
                terraform_metadata=entry.terraform_metadata,
                has_http_request=entry.http_request is not None,
                has_http_response=entry.http_response is not None,
                req_id=entry.req_id,
                rpc=entry.rpc
            ))
        
        return {
            "status": "success",
            "total_entries": len(entries),
            "entries": response_entries,
            "sections_detected": list(set(e.section_type for e in entries if e.section_type)),
            "linked_pairs": len(req_resp_map),
            "plugins_applied": [type(p).__name__ for p in plugins]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing log: {str(e)}")

@app.get("/")
async def root():
    return {
        "message": "Terraform Log Processor API with Plugin System",
        "endpoints": {
            "/upload-log/": "POST - Upload and process log file",
            "/docs": "Swagger UI documentation"
        },
        "available_plugins": [
            "SensitiveDataPlugin - Redact API tokens and secrets",
            "FieldFilterPlugin - Remove unnecessary fields",
            "LogLevelFilterPlugin - Filter by minimum log level",
            "NoiseFilterPlugin - Remove repetitive logs",
            "HTTPBodyCompressionPlugin - Compress large bodies"
        ]
    }


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    # Example: Using parser with plugins
    plugins = [
        SensitiveDataPlugin(redact_value="***"),
        LogLevelFilterPlugin(min_level=LogLevel.INFO),
        NoiseFilterPlugin(),
    ]
    
    parser = TerraformLogParser(plugins=plugins)
    
    sample_log = '''{"@level":"info","@message":"Terraform version: 1.13.1","@timestamp":"2025-09-09T15:31:32.757289+03:00"}
{"@level":"trace","@message":"Schema for provider is in the global cache","@timestamp":"2025-09-09T15:31:32.758000+03:00"}
{"@level":"error","@message":"Authentication failed","api_token":"secret123","@timestamp":"2025-09-09T15:31:33.000000+03:00"}'''
    
    print("=== Terraform Log Parser with Plugins ===\n")
    
    for line in sample_log.splitlines():
        entry = parser.parse_line(line)
        if entry:
            print(f"[{entry.timestamp}] {entry.level.name}: {entry.message}")
            if entry.section_type:
                print(f"  → Section: {entry.section_type}")
    
    print("\n=== To run FastAPI server ===")
    print("uvicorn script_name:app --reload")
    print("\n=== Example API call ===")
    print("curl -X POST 'http://localhost:8000/upload-log/?redact_sensitive=true&min_level=INFO' \\")
    print("  -F 'file=@terraform.log'")
