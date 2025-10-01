import re
import json
import logging
import traceback
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod
import asyncpg
from contextlib import asynccontextmanager
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== CONFIG LOADER ====================

class PluginConfigLoader:
    """Load plugin configurations from JSON file"""
    
    def __init__(self, config_path: str = "plugin_config.json"):
        self.config_path = Path(config_path)
        self.configs = {}
        self.load_configs()
    
    def load_configs(self):
        """Load all configurations from JSON file"""
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}, using defaults")
            self.configs = self._get_default_config()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                self.configs = json.load(f)
            logger.info(f"Loaded configurations: {list(self.configs.keys())}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.configs = self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default configuration if file not found"""
        return {
            "default": {
                "SensitiveDataPlugin": {
                    "enabled": True,
                    "redact_value": "[REDACTED]",
                    "keep_prefix": 4
                },
                "LogLevelFilterPlugin": {
                    "enabled": True,
                    "min_level": "TRACE"
                },
                "NoiseFilterPlugin": {
                    "enabled": False,
                    "use_defaults": True,
                    "deduplicate": False,
                    "max_repeats": 3
                },
                "HTTPBodyCompressionPlugin": {
                    "enabled": False,
                    "max_size": 1000
                }
            }
        }
    
    def get_config(self, profile: str = "default") -> Dict:
        """Get configuration for specific profile"""
        return self.configs.get(profile, self.configs.get("default", {}))
    
    def create_plugins_from_config(self, profile: str = "default") -> List:
        """Create plugin instances from configuration"""
        config = self.get_config(profile)
        plugins = []
        
        for plugin_name, plugin_config in config.items():
            if not plugin_config.get("enabled", False):
                continue
            
            try:
                if plugin_name == "SensitiveDataPlugin":
                    plugins.append(SensitiveDataPlugin(
                        redact_value=plugin_config.get("redact_value", "[REDACTED]"),
                        keep_prefix=plugin_config.get("keep_prefix", 4)
                    ))
                elif plugin_name == "FieldFilterPlugin":
                    plugins.append(FieldFilterPlugin(
                        exclude_fields=plugin_config.get("exclude_fields"),
                        include_fields=plugin_config.get("include_fields")
                    ))
                elif plugin_name == "LogLevelFilterPlugin":
                    level_str = plugin_config.get("min_level", "TRACE")
                    plugins.append(LogLevelFilterPlugin(
                        min_level=LogLevel[level_str]
                    ))
                elif plugin_name == "NoiseFilterPlugin":
                    plugins.append(NoiseFilterPlugin(
                        noise_patterns=plugin_config.get("noise_patterns"),
                        use_defaults=plugin_config.get("use_defaults", True),
                        deduplicate=plugin_config.get("deduplicate", False),
                        max_repeats=plugin_config.get("max_repeats", 3)
                    ))
                elif plugin_name == "HTTPBodyCompressionPlugin":
                    plugins.append(HTTPBodyCompressionPlugin(
                        max_size=plugin_config.get("max_size", 1000),
                        max_items_preview=plugin_config.get("max_items_preview", 3),
                        max_depth=plugin_config.get("max_depth", 3)
                    ))
                
                logger.info(f"Created plugin: {plugin_name}")
            except Exception as e:
                logger.error(f"Error creating plugin {plugin_name}: {e}")
        
        return plugins


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
        pass
    
    @abstractmethod
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        pass


class SensitiveDataPlugin(LogPlugin):
    """Remove sensitive data like API tokens, passwords, secrets"""
    
    SENSITIVE_KEYS = {
        'token', 'api_key', 'apikey', 'password', 'secret', 
        'authorization', 'auth', 'api_token', 'access_token',
        'refresh_token', 'bearer', 'credentials', 'private_key'
    }
    
    TOKEN_PATTERN = re.compile(r'(?:bearer\s+|token[\s:=]+)[a-zA-Z0-9_\-\.]+', re.I)
    KEY_PATTERN = re.compile(r'(?:api[_\-]?key[\s:=]+)[a-zA-Z0-9_\-]+', re.I)
    
    def __init__(self, redact_value: str = "[REDACTED]", keep_prefix: int = 4):
        self.redact_value = redact_value
        self.keep_prefix = keep_prefix
    
    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str) and len(value) > 10:
            if self.keep_prefix > 0:
                return f"{value[:self.keep_prefix]}...{self.redact_value}"
        return self.redact_value
    
    def _sanitize_string(self, text: str) -> str:
        """Remove tokens from text using patterns"""
        if self.TOKEN_PATTERN.search(text) or self.KEY_PATTERN.search(text):
            text = self.TOKEN_PATTERN.sub(self.redact_value, text)
            text = self.KEY_PATTERN.sub(self.redact_value, text)
        return text
    
    def _sanitize_dict(self, data: Any) -> Any:
        """Recursively sanitize data structure (dict, list, or scalar)"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                key_lower = key.lower()
                
                if any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS):
                    sanitized[key] = self._redact_value(value)
                else:
                    sanitized[key] = self._sanitize_dict(value)
            return sanitized
        
        elif isinstance(data, list):
            return [self._sanitize_dict(item) for item in data]
        
        elif isinstance(data, str):
            return self._sanitize_string(data)
        
        else:
            return data
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(json_obj, dict):
            return json_obj
        return self._sanitize_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        if entry.http_request:
            entry.http_request = self._sanitize_dict(entry.http_request)
        if entry.http_response:
            entry.http_response = self._sanitize_dict(entry.http_response)
        if entry.terraform_metadata:
            entry.terraform_metadata = self._sanitize_dict(entry.terraform_metadata)
        if entry.message and isinstance(entry.message, str):
            entry.message = self._sanitize_string(entry.message)
        
        return entry


class FieldFilterPlugin(LogPlugin):
    """Remove unnecessary fields from logs"""
    
    def __init__(self, exclude_fields: List[str] = None, include_fields: List[str] = None):
        self.exclude_fields = set(exclude_fields or [])
        self.include_fields = set(include_fields) if include_fields else None
    
    def _filter_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if self.include_fields:
            return {k: v for k, v in data.items() if k in self.include_fields}
        else:
            return {k: v for k, v in data.items() if k not in self.exclude_fields}
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        return self._filter_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        return entry


class LogLevelFilterPlugin(LogPlugin):
    """Filter out logs below a certain level"""
    
    def __init__(self, min_level: LogLevel = LogLevel.TRACE):
        self.min_level = min_level
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        if entry.level.value < self.min_level.value:
            return None
        return entry


class NoiseFilterPlugin(LogPlugin):
    """Filter out noisy/repetitive log messages"""
    
    def __init__(
        self, 
        noise_patterns: List[str] = None,
        use_defaults: bool = True,
        deduplicate: bool = False,
        max_repeats: int = 3
    ):
        default_patterns = [
            r'Schema\s+for\s+provider.*is\s+in\s+the\s+global\s+cache',
            r'Checking\s+.*\s+lock',
            r'ignoring\s+non-existing\s+provider',
        ]
        
        patterns = []
        if use_defaults:
            patterns.extend(default_patterns)
        if noise_patterns:
            patterns.extend(noise_patterns)
            
        self.noise_regexes = [re.compile(p, re.I) for p in patterns]
        self.deduplicate = deduplicate
        self.max_repeats = max_repeats
        self.message_counts = {}
    
    def _is_noisy(self, message: str) -> bool:
        for pattern in self.noise_regexes:
            if pattern.search(message):
                return True
        return False
    
    def _is_duplicate(self, message: str) -> bool:
        if not self.deduplicate:
            return False
        
        normalized = re.sub(r'\d+', 'N', message)
        normalized = re.sub(r'/[^\s]+', '/PATH', normalized)
        
        count = self.message_counts.get(normalized, 0)
        self.message_counts[normalized] = count + 1
        
        return count >= self.max_repeats
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        if self._is_noisy(entry.message):
            return None
        if self._is_duplicate(entry.message):
            return None
        return entry


class HTTPBodyCompressionPlugin(LogPlugin):
    """Compress large HTTP bodies by summarizing"""
    
    def __init__(self, max_size: int = 1000, max_items_preview: int = 3, max_depth: int = 3):
        self.max_size = max_size
        self.max_items_preview = max_items_preview
        self.max_depth = max_depth
    
    def _get_structure_info(self, obj: Any, depth: int = 0) -> Any:
        if depth > self.max_depth:
            return "[Too Deep]"
        
        if isinstance(obj, dict):
            result = {}
            for i, (key, value) in enumerate(obj.items()):
                if i >= self.max_items_preview:
                    result["..."] = f"+ {len(obj) - i} more keys"
                    break
                result[key] = self._get_structure_info(value, depth + 1)
            return result
        
        elif isinstance(obj, list):
            if len(obj) == 0:
                return []
            
            result = []
            for i in range(min(len(obj), self.max_items_preview)):
                result.append(self._get_structure_info(obj[i], depth + 1))
            
            if len(obj) > self.max_items_preview:
                result.append(f"... + {len(obj) - self.max_items_preview} more items")
            
            return result
        
        elif isinstance(obj, str):
            if len(obj) > 50:
                return f"{obj[:50]}... (length: {len(obj)})"
            return obj
        
        else:
            return obj
    
    def _compress_body(self, body: Dict[str, Any]) -> Dict[str, Any]:
        body_str = json.dumps(body)
        
        if len(body_str) > self.max_size:
            compressed = {
                "_compressed": True,
                "_original_size": len(body_str),
                "_summary": self._get_structure_info(body)
            }
            return compressed
        
        return body
    
    def process_json(self, json_obj: Dict[str, Any]) -> Dict[str, Any]:
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        if entry.http_request:
            entry.http_request = self._compress_body(entry.http_request)
        if entry.http_response:
            entry.http_response = self._compress_body(entry.http_response)
        return entry


# ==================== TERRAFORM LOG PARSER WITH PLUGINS ====================

class TerraformLogParser:
    ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?')
    TIME_RE = re.compile(r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b')
    EPOCH_MS_RE = re.compile(r'\b1[0-9]{12}\b')
    EPOCH_S_RE = re.compile(r'\b1[0-9]{9,10}\b')
    
    LEVEL_RE = re.compile(r'\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b', re.I)
    
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
        self.plugins.append(plugin)
    
    def extract_timestamp(self, log_str: str, json_obj: Optional[Dict] = None) -> Optional[datetime]:
        if json_obj and '@timestamp' in json_obj:
            try:
                ts_str = json_obj['@timestamp']
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except (ValueError, TypeError) as e:
                logger.debug(f"Error parsing @timestamp: {e}")
        
        m = self.ISO_RE.search(log_str)
        if m:
            try:
                return datetime.fromisoformat(m.group(0).replace('Z', '+00:00'))
            except ValueError as e:
                logger.debug(f"Error parsing ISO timestamp: {e}")
        
        return datetime.now(timezone.utc)
    
    def extract_level(self, log_str: str, json_obj: Optional[Dict] = None) -> LogLevel:
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
        
        return LogLevel.INFO
    
    def detect_section(self, message: str) -> Optional[str]:
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
        if not line.strip():
            return None
        
        json_obj = None
        
        try:
            json_obj = json.loads(line)
            
            for plugin in self.plugins:
                json_obj = plugin.process_json(json_obj)
                
        except json.JSONDecodeError:
            pass
        
        timestamp = self.extract_timestamp(line, json_obj)
        if not timestamp:
            timestamp = datetime.now(timezone.utc)
        
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
        
        for plugin in self.plugins:
            entry = plugin.process_entry(entry)
            if entry is None:
                return None
        
        return entry
    
    def parse_lines(self, lines: List[str]) -> List[LogEntry]:
        entries = []
        for line in lines:
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
        return entries


# ==================== DATABASE ====================

class DatabaseManager:
    def __init__(self, db_url: str):
        self.db_url = db_url
        self.pool = None
        logger.info(f"DatabaseManager initialized with URL: {db_url}")
    
    async def connect(self):
        logger.info("Connecting to database...")
        try:
            self.pool = await asyncpg.create_pool(self.db_url, min_size=2, max_size=10)
            logger.info("Database connection pool created")
            await self._create_tables()
            logger.info("Database tables verified/created")
        except Exception as e:
            logger.error(f"Failed to connect to database: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    async def disconnect(self):
        if self.pool:
            logger.info("Closing database connection pool")
            await self.pool.close()
    
    async def _create_tables(self):
        async with self.pool.acquire() as conn:
            # Drop old table if exists and recreate with file_hash
            await conn.execute('DROP TABLE IF EXISTS log_entries CASCADE')
            await conn.execute('DROP TABLE IF EXISTS log_files CASCADE')
            
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS log_files (
                    id SERIAL PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    file_hash VARCHAR(64) UNIQUE NOT NULL,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_entries INTEGER,
                    error_count INTEGER,
                    warn_count INTEGER,
                    metadata JSONB
                )
            ''')
            
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS log_entries (
                    id SERIAL PRIMARY KEY,
                    file_id INTEGER REFERENCES log_files(id) ON DELETE CASCADE,
                    timestamp TIMESTAMP,
                    level VARCHAR(10),
                    message TEXT,
                    raw_json JSONB,
                    section_type VARCHAR(50),
                    req_id VARCHAR(100),
                    UNIQUE(file_id, timestamp, message)
                )
            ''')
            
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_log_entries_file_id ON log_entries(file_id)
            ''')
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_log_entries_level ON log_entries(level)
            ''')
            
            logger.info("Database schema created/updated successfully with file_hash column")
    
    async def file_exists(self, file_hash: str) -> Optional[int]:
        """Check if file with this hash already exists"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                'SELECT id FROM log_files WHERE file_hash = $1',
                file_hash
            )
            return result
    
    async def save_log_file(self, filename: str, file_hash: str, entries: List[LogEntry]) -> int:
        error_count = sum(1 for e in entries if e.level == LogLevel.ERROR)
        warn_count = sum(1 for e in entries if e.level == LogLevel.WARN)
        
        logger.info(f"Saving log file: {filename}, entries: {len(entries)}, errors: {error_count}, warnings: {warn_count}")
        
        async with self.pool.acquire() as conn:
            try:
                file_id = await conn.fetchval('''
                    INSERT INTO log_files (filename, file_hash, total_entries, error_count, warn_count)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                ''', filename, file_hash, len(entries), error_count, warn_count)
                
                logger.info(f"Created log_files record with id: {file_id}")
                
                entry_count = 0
                for i, entry in enumerate(entries):
                    try:
                        if isinstance(entry.timestamp, str):
                            ts = datetime.fromisoformat(entry.timestamp.replace('Z', '+00:00'))
                        else:
                            ts = entry.timestamp
                        
                        if ts.tzinfo is not None:
                            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
                        
                        raw_json_str = json.dumps(entry.raw_json) if entry.raw_json else None
                        
                        await conn.execute('''
                            INSERT INTO log_entries (file_id, timestamp, level, message, raw_json, section_type, req_id)
                            VALUES ($1, $2, $3, $4, $5, $6, $7)
                            ON CONFLICT DO NOTHING
                        ''', file_id, ts, entry.level.name, entry.message, 
                        raw_json_str, entry.section_type, entry.req_id)
                        
                        entry_count += 1
                        
                        if i % 100 == 0:
                            logger.debug(f"Saved {i}/{len(entries)} entries")
                            
                    except Exception as entry_error:
                        logger.error(f"Error saving entry {i}: {str(entry_error)}")
                        if i < 3:
                            logger.error(f"Full entry: {entry}")
                        raise
                
                logger.info(f"Successfully saved {entry_count} entries")
                return file_id
                
            except Exception as e:
                logger.error(f"Error in save_log_file: {str(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                raise
    
    async def get_log_files(self) -> List[Dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, filename, upload_date, total_entries, error_count, warn_count
                FROM log_files
                ORDER BY upload_date DESC
            ''')
            return [dict(row) for row in rows]
    
    async def get_log_entries(self, file_id: int) -> List[Dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch('''
                SELECT timestamp, level, message, raw_json, section_type, req_id
                FROM log_entries
                WHERE file_id = $1
                ORDER BY timestamp
            ''', file_id)
            return [dict(row) for row in rows]
    
    async def delete_log_file(self, file_id: int):
        async with self.pool.acquire() as conn:
            await conn.execute('DELETE FROM log_files WHERE id = $1', file_id)


# ==================== FASTAPI ENDPOINT ====================

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import io

# Initialize config loader
config_loader = PluginConfigLoader()

db_manager = DatabaseManager("postgresql://terraform:terraform@postgres:5432/terraform_logs")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db_manager.connect()
    yield
    await db_manager.disconnect()

app = FastAPI(
    title="Terraform Log Processor API",
    description="Advanced Terraform log analysis with JSON-configured plugins",
    version="2.3.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

class LogFileInfo(BaseModel):
    id: int
    filename: str
    upload_date: str
    total_entries: int
    error_count: int
    warn_count: int

class HealthStatus(BaseModel):
    status: str
    total_errors: int
    total_warnings: int
    recent_files: int

@app.get("/api/v1/configs", tags=["Configuration"])
async def get_available_configs():
    """Get list of available plugin configurations"""
    return {
        "profiles": list(config_loader.configs.keys()),
        "configs": config_loader.configs
    }

@app.post("/upload-log/", tags=["Logs"])
async def upload_log(
    file: UploadFile = File(...),
    config: str = Query("default", description="Plugin configuration profile")
):
    """Upload and parse Terraform log file"""
    logger.info(f"Received file upload: {file.filename} with config profile: {config}")
    
    if not file.filename.endswith(('.log', '.txt', '.json')):
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    try:
        # Read file content
        content = await file.read()
        logger.info(f"Read {len(content)} bytes from file")
        
        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Check if file already exists
        existing_id = await db_manager.file_exists(file_hash)
        if existing_id:
            logger.warning(f"File already exists with id: {existing_id}")
            raise HTTPException(
                status_code=409, 
                detail=f"This file has already been uploaded (File ID: {existing_id})"
            )
        
        # Load plugins from configuration
        plugins = config_loader.create_plugins_from_config(config)
        
        parser = TerraformLogParser(plugins=plugins)
        logger.info(f"Parser initialized with {len(plugins)} plugins from '{config}' profile")
        
        lines = content.decode('utf-8').splitlines()
        logger.info(f"Split into {len(lines)} lines")
        
        # Parse lines
        entries = []
        parse_errors = 0
        for i, line in enumerate(lines):
            try:
                entry = parser.parse_line(line)
                if entry:
                    entries.append(entry)
            except Exception as e:
                parse_errors += 1
                if parse_errors <= 5:
                    logger.error(f"Error parsing line {i}: {str(e)}\nLine: {line[:100]}")
        
        logger.info(f"Parsed {len(entries)} entries, {parse_errors} errors")
        
        if len(entries) == 0:
            raise HTTPException(status_code=400, detail="No valid log entries found in file")
        
        # Save to database
        logger.info("Attempting to save to database")
        try:
            file_id = await db_manager.save_log_file(file.filename, file_hash, entries)
            logger.info(f"Saved to database with file_id: {file_id}")
        except Exception as db_error:
            logger.error(f"Database save error: {str(db_error)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(db_error)}")
        
        # Build request-response pairs
        req_resp_map = {}
        for i, entry in enumerate(entries):
            if entry.req_id:
                if entry.req_id not in req_resp_map:
                    req_resp_map[entry.req_id] = {'indices': []}
                req_resp_map[entry.req_id]['indices'].append(i)
                if entry.http_request:
                    req_resp_map[entry.req_id]['has_request'] = True
                if entry.http_response:
                    req_resp_map[entry.req_id]['has_response'] = True
        
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
        
        logger.info("Upload completed successfully")
        return {
            "status": "success",
            "file_id": file_id,
            "total_entries": len(entries),
            "entries": response_entries,
            "sections_detected": list(set(e.section_type for e in entries if e.section_type)),
            "request_response_chains": len(req_resp_map),
            "plugins_applied": [type(p).__name__ for p in plugins],
            "config_profile": config,
            "parse_errors": parse_errors
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in upload_log: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error processing log: {str(e)}")

@app.get("/logs/", response_model=List[LogFileInfo], tags=["Logs"])
async def list_log_files():
    """Get list of all uploaded log files"""
    files = await db_manager.get_log_files()
    return [
        LogFileInfo(
            id=f['id'],
            filename=f['filename'],
            upload_date=f['upload_date'].isoformat(),
            total_entries=f['total_entries'],
            error_count=f['error_count'],
            warn_count=f['warn_count']
        )
        for f in files
    ]

@app.get("/logs/{file_id}", tags=["Logs"])
async def get_log_file(file_id: int):
    """Get detailed entries for a specific log file"""
    entries = await db_manager.get_log_entries(file_id)
    if not entries:
        raise HTTPException(status_code=404, detail="Log file not found")
    
    # Build request-response chains
    req_chains = {}
    for i, entry in enumerate(entries):
        req_id = entry.get('req_id')
        if req_id:
            if req_id not in req_chains:
                req_chains[req_id] = []
            req_chains[req_id].append(i)
    
    return {
        "file_id": file_id,
        "total_entries": len(entries),
        "entries": entries,
        "request_chains": req_chains
    }

@app.delete("/logs/{file_id}", tags=["Logs"])
async def delete_log_file(file_id: int):
    """Delete a log file and all its entries"""
    await db_manager.delete_log_file(file_id)
    return {"status": "deleted", "file_id": file_id}

# ==================== MONITORING & INTEGRATION API ====================

@app.get("/api/v1/health", response_model=HealthStatus, tags=["Monitoring"])
async def get_health_status():
    """Get overall system health status for monitoring integration"""
    files = await db_manager.get_log_files()
    
    total_errors = sum(f['error_count'] for f in files)
    total_warnings = sum(f['warn_count'] for f in files)
    recent_files = len([f for f in files if (datetime.now() - f['upload_date']).days < 7])
    
    return HealthStatus(
        status="healthy" if total_errors == 0 else "degraded",
        total_errors=total_errors,
        total_warnings=total_warnings,
        recent_files=recent_files
    )

@app.get("/api/v1/alerts", tags=["Monitoring"])
async def get_alerts(severity: str = Query("ERROR", description="ERROR or WARN")):
    """Get all log entries matching alert severity for incident management"""
    files = await db_manager.get_log_files()
    
    all_alerts = []
    for file_info in files:
        entries = await db_manager.get_log_entries(file_info['id'])
        alerts = [e for e in entries if e['level'] == severity]
        
        for alert in alerts:
            all_alerts.append({
                "file_id": file_info['id'],
                "filename": file_info['filename'],
                "timestamp": alert['timestamp'].isoformat(),
                "level": alert['level'],
                "message": alert['message'],
                "section": alert['section_type']
            })
    
    return {
        "severity": severity,
        "count": len(all_alerts),
        "alerts": all_alerts[:50]
    }

@app.get("/api/v1/metrics", tags=["Monitoring"])
async def get_metrics():
    """Get aggregated metrics for monitoring dashboards"""
    files = await db_manager.get_log_files()
    
    metrics = {
        "total_files": len(files),
        "total_logs": sum(f['total_entries'] for f in files),
        "total_errors": sum(f['error_count'] for f in files),
        "total_warnings": sum(f['warn_count'] for f in files),
        "error_rate": 0.0,
        "files_by_date": {}
    }
    
    if metrics["total_logs"] > 0:
        metrics["error_rate"] = (metrics["total_errors"] / metrics["total_logs"]) * 100
    
    for f in files:
        date_key = f['upload_date'].date().isoformat()
        if date_key not in metrics["files_by_date"]:
            metrics["files_by_date"][date_key] = 0
        metrics["files_by_date"][date_key] += 1
    
    return metrics

@app.get("/api/v1/gantt/{file_id}", tags=["Visualization"])
async def get_gantt_data(file_id: int):
    """Get detailed Gantt chart data with microsecond-level operations"""
    entries = await db_manager.get_log_entries(file_id)
    if not entries:
        raise HTTPException(status_code=404, detail="Log file not found")
    
    # Group by sections with all logs
    sections = {}
    current_section = None
    section_start = None
    
    for entry in entries:
        if entry['section_type'] and entry['section_type'] != current_section:
            if current_section and section_start:
                sections[current_section]['end'] = entry['timestamp']
            
            current_section = entry['section_type']
            section_start = entry['timestamp']
            
            if current_section not in sections:
                sections[current_section] = {
                    'name': current_section,
                    'start': section_start,
                    'end': None,
                    'operations': []
                }
        
        if current_section:
            sections[current_section]['operations'].append({
                'timestamp': entry['timestamp'].isoformat(),
                'level': entry['level'],
                'message': entry['message'],
                'req_id': entry['req_id']
            })
    
    if current_section and section_start and sections[current_section]['end'] is None:
        sections[current_section]['end'] = entries[-1]['timestamp']
    
    gantt_data = []
    for section_name, section_data in sections.items():
        if section_data['end']:
            duration = (section_data['end'] - section_data['start']).total_seconds()
            
            # Group operations by req_id for sub-operations
            operations_by_req = {}
            for op in section_data['operations']:
                req_id = op.get('req_id', 'general')
                if req_id not in operations_by_req:
                    operations_by_req[req_id] = []
                operations_by_req[req_id].append(op)
            
            # Create sub-operations
            sub_operations = []
            for req_id, ops in operations_by_req.items():
                if len(ops) > 1 and req_id != 'general':
                    op_start = datetime.fromisoformat(ops[0]['timestamp'])
                    op_end = datetime.fromisoformat(ops[-1]['timestamp'])
                    op_duration = (op_end - op_start).total_seconds()
                    
                    sub_operations.append({
                        'id': req_id,
                        'start': ops[0]['timestamp'],
                        'end': ops[-1]['timestamp'],
                        'duration': op_duration,
                        'log_count': len(ops),
                        'logs': ops
                    })
            
            gantt_data.append({
                'task': section_name,
                'start': section_data['start'].isoformat(),
                'end': section_data['end'].isoformat(),
                'duration': duration,
                'log_count': len(section_data['operations']),
                'sub_operations': sub_operations
            })
    
    return {
        "file_id": file_id,
        "gantt_data": gantt_data
    }

@app.get("/")
async def root():
    return FileResponse("terraform_viewer.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
