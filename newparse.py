import re
import json
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

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
    section_type: Optional[str] = None  # 'plan', 'apply', 'validation', etc.

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
    
    def __init__(self):
        self.current_section = None
    
    def extract_timestamp(self, log_str: str, json_obj: Optional[Dict] = None) -> Optional[datetime]:
        """Эвристическое извлечение timestamp из строки или JSON"""
        # 1. Попытка из JSON поля @timestamp
        if json_obj and '@timestamp' in json_obj:
            try:
                ts_str = json_obj['@timestamp']
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            except (ValueError, TypeError):
                pass
        
        # 2. ISO формат в строке
        m = self.ISO_RE.search(log_str)
        if m:
            try:
                return datetime.fromisoformat(m.group(0).replace('Z', '+00:00'))
            except ValueError:
                pass
        
        # 3. Время без даты (предполагаем сегодняшнюю дату)
        m = self.TIME_RE.search(log_str)
        if m:
            try:
                today = datetime.utcnow().date()
                return datetime.fromisoformat(f"{today}T{m.group(0)}")
            except ValueError:
                pass
        
        # 4. Epoch timestamp в миллисекундах
        m = self.EPOCH_MS_RE.search(log_str)
        if m:
            try:
                return datetime.utcfromtimestamp(int(m.group(0)) / 1000.0)
            except (ValueError, OSError):
                pass
        
        # 5. Epoch timestamp в секундах
        m = self.EPOCH_S_RE.search(log_str)
        if m:
            try:
                return datetime.utcfromtimestamp(int(m.group(0)))
            except (ValueError, OSError):
                pass
        
        return None
    
    def extract_level(self, log_str: str, json_obj: Optional[Dict] = None) -> LogLevel:
        """Эвристическое извлечение log level"""
        # 1. Из JSON поля @level
        if json_obj and '@level' in json_obj:
            level_str = str(json_obj['@level']).upper()
            try:
                return LogLevel[level_str]
            except KeyError:
                pass
        
        # 2. Из строки по регулярке
        m = self.LEVEL_RE.search(log_str)
        if m:
            level_str = m.group(1).upper()
            if level_str == 'WARNING':
                level_str = 'WARN'
            try:
                return LogLevel[level_str]
            except KeyError:
                pass
        
        # 3. Эвристика по ключевым словам
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
        
        # tf_http_req_body
        if 'tf_http_req_body' in json_obj:
            try:
                body_str = json_obj['tf_http_req_body']
                if isinstance(body_str, str) and body_str.strip():
                    http_req = json.loads(body_str)
            except json.JSONDecodeError:
                http_req = {'raw': json_obj['tf_http_req_body']}
        
        # tf_http_res_body
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
        
        # Попытка распарсить как JSON
        try:
            json_obj = json.loads(line)
        except json.JSONDecodeError:
            pass
        
        # Извлечение timestamp
        timestamp = self.extract_timestamp(line, json_obj)
        if not timestamp:
            timestamp = datetime.utcnow()  # fallback
        
        # Извлечение level
        level = self.extract_level(line, json_obj)
        
        # Извлечение message
        if json_obj and '@message' in json_obj:
            message = json_obj['@message']
        else:
            message = line
        
        # Определение секции
        section = self.detect_section(message)
        
        # Извлечение HTTP bodies
        http_req, http_resp = None, None
        if json_obj:
            http_req, http_resp = self.extract_http_bodies(json_obj)
        
        # Извлечение метаданных Terraform
        tf_metadata = None
        if json_obj:
            tf_metadata = self.extract_terraform_metadata(json_obj)
        
        # Caller и module
        caller = json_obj.get('@caller') if json_obj else None
        module = json_obj.get('@module') if json_obj else None
        
        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            raw_json=json_obj,
            caller=caller,
            module=module,
            terraform_metadata=tf_metadata,
            http_request=http_req,
            http_response=http_resp,
            section_type=section
        )
    
    def parse_multiline_json(self, lines: List[str], start_idx: int) -> Tuple[Optional[Dict], int]:
        """Извлечение многострочного JSON блока"""
        depth = 0
        started = False
        collected = []
        
        for i in range(start_idx, len(lines)):
            line = lines[i]
            
            for ch in line:
                if ch == '{':
                    depth += 1
                    started = True
                elif ch == '}':
                    depth -= 1
            
            if started:
                collected.append(line)
            
            if depth == 0 and started:
                try:
                    text = "\n".join(collected)
                    obj = json.loads(text)
                    return obj, i
                except json.JSONDecodeError:
                    continue
        
        return None, start_idx
    
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

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List
import io

app = FastAPI(title="Terraform Log Processor")

parser = TerraformLogParser()

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

@app.post("/upload-log/")
async def upload_log(file: UploadFile = File(...)):
    """
    Upload and parse Terraform log file
    """
    if not file.filename.endswith(('.log', '.txt', '.json')):
        raise HTTPException(status_code=400, detail="Invalid file type. Expected .log, .txt, or .json")
    
    try:
        # Читаем файл
        content = await file.read()
        lines = content.decode('utf-8').splitlines()
        
        # Парсим
        entries = []
        for line in lines:
            entry = parser.parse_line(line)
            if entry:
                entries.append(entry)
        
        # Преобразуем в ответ
        response_entries = []
        for entry in entries:
            response_entries.append(LogEntryResponse(
                timestamp=entry.timestamp.isoformat(),
                level=entry.level.name,
                message=entry.message,
                caller=entry.caller,
                module=entry.module,
                section_type=entry.section_type,
                terraform_metadata=entry.terraform_metadata,
                has_http_request=entry.http_request is not None,
                has_http_response=entry.http_response is not None
            ))
        
        return {
            "status": "success",
            "total_entries": len(entries),
            "entries": response_entries[:100],  # Первые 100 для preview
            "sections_detected": list(set(e.section_type for e in entries if e.section_type))
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing log: {str(e)}")

@app.get("/")
async def root():
    return {
        "message": "Terraform Log Processor API",
        "endpoints": [
            "/upload-log/ - POST multipart/form-data with log file",
            "/docs - Swagger UI documentation"
        ]
    }


# ==================== USAGE EXAMPLE ====================

if __name__ == "__main__":
    # Пример использования парсера
    sample_log = '''{"@level":"info","@message":"Terraform version: 1.13.1","@timestamp":"2025-09-09T15:31:32.757289+03:00"}
{"@level":"trace","@message":"backend/local: starting Plan operation","@timestamp":"2025-09-09T15:31:32.814270+03:00"}'''
    
    print("=== Terraform Log Parser Example ===\n")
    
    parser = TerraformLogParser()
    for line in sample_log.splitlines():
        entry = parser.parse_line(line)
        if entry:
            print(f"[{entry.timestamp}] {entry.level.name}: {entry.message}")
            if entry.section_type:
                print(f"  → Section: {entry.section_type}")
    
    print("\n=== To run FastAPI server ===")
    print("uvicorn script_name:app --reload")