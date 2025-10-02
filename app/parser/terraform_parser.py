# app/parser/terraform_parser.py
"""
Парсер для логов Terraform с поддержкой плагинов
Путь: app/parser/terraform_parser.py
"""

import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from app.models.log_entry import LogEntry, LogLevel
from app.plugins.base import LogPlugin

logger = logging.getLogger(__name__)


class TerraformLogParser:
    """
    Парсер для логов Terraform
    
    Извлекает из логов:
    - Временные метки
    - Уровни логирования
    - Сообщения
    - HTTP запросы/ответы
    - Метаданные Terraform
    - Секции операций (plan, apply и т.д.)
    
    Example:
        >>> from app.plugins import SensitiveDataPlugin
        >>> parser = TerraformLogParser(plugins=[SensitiveDataPlugin()])
        >>> entries = parser.parse_lines(log_lines)
    """
    
    # Регулярные выражения для извлечения временных меток
    ISO_RE = re.compile(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'
    )
    TIME_RE = re.compile(r'\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b')
    EPOCH_MS_RE = re.compile(r'\b1[0-9]{12}\b')
    EPOCH_S_RE = re.compile(r'\b1[0-9]{9,10}\b')
    
    # Регулярное выражение для уровней логирования
    LEVEL_RE = re.compile(
        r'\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b', 
        re.I
    )
    
    # Паттерны для определения секций операций
    SECTION_PATTERNS = {
        'plan_start': re.compile(
            r'backend/local:\s+starting\s+Plan\s+operation', 
            re.I
        ),
        'apply_start': re.compile(
            r'backend/local:\s+starting\s+Apply\s+operation', 
            re.I
        ),
        'validation_start': re.compile(
            r'running\s+validation\s+operation', 
            re.I
        ),
        'plan_end': re.compile(r'Plan:\s+\d+\s+to\s+add', re.I),
        'apply_end': re.compile(r'Apply\s+complete', re.I),
    }
    
    def __init__(self, plugins: List[LogPlugin] = None):
        """
        Args:
            plugins: Список плагинов для обработки логов
        """
        self.current_section = None
        self.plugins = plugins or []
    
    def add_plugin(self, plugin: LogPlugin):
        """Добавить плагин к парсеру"""
        self.plugins.append(plugin)
    
    def extract_timestamp(
        self, 
        log_str: str, 
        json_obj: Optional[Dict] = None
    ) -> Optional[datetime]:
        """
        Извлекает временную метку из лога
        
        Проверяет в порядке приоритета:
        1. Поле @timestamp в JSON
        2. ISO формат в тексте
        3. Текущее время (fallback)
        """
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
    
    def extract_level(
        self, 
        log_str: str, 
        json_obj: Optional[Dict] = None
    ) -> LogLevel:
        """
        Извлекает уровень логирования
        
        Проверяет в порядке приоритета:
        1. Поле @level в JSON
        2. Уровень в тексте лога
        3. INFO (fallback)
        """
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
        """
        Определяет секцию операции Terraform
        
        Отслеживает начало и конец секций (plan, apply и т.д.)
        """
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
    
    def extract_http_bodies(
        self, 
        json_obj: Dict[str, Any]
    ) -> Tuple[Optional[Dict], Optional[Dict]]:
        """
        Извлекает HTTP запрос и ответ из лога
        
        Returns:
            Tuple (http_request, http_response)
        """
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
    
    def extract_terraform_metadata(
        self, 
        json_obj: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Извлекает метаданные Terraform из лога
        
        Включает:
        - Адрес провайдера
        - Тип ресурса
        - ID запроса
        - RPC метод
        - и другие tf_* поля
        """
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
        """
        Парсит одну строку лога
        
        Args:
            line: Строка лога (может быть JSON или текст)
            
        Returns:
            LogEntry или None если строка отфильтрована плагинами
        """
        if not line.strip():
            return None
        
        json_obj = None
        
        # Пытаемся распарсить как JSON
        try:
            json_obj = json.loads(line)
            
            # Применяем плагины к JSON
            for plugin in self.plugins:
                json_obj = plugin.process_json(json_obj)
                if json_obj is None:
                    return None
        except json.JSONDecodeError:
            pass
        
        # Извлекаем основные поля
        timestamp = self.extract_timestamp(line, json_obj)
        if not timestamp:
            timestamp = datetime.now(timezone.utc)
        
        level = self.extract_level(line, json_obj)
        
        if json_obj and '@message' in json_obj:
            message = json_obj['@message']
        else:
            message = line
        
        section = self.detect_section(message)
        
        # Извлекаем HTTP данные
        http_req, http_resp = None, None
        if json_obj:
            http_req, http_resp = self.extract_http_bodies(json_obj)
        
        # Извлекаем метаданные Terraform
        tf_metadata = None
        if json_obj:
            tf_metadata = self.extract_terraform_metadata(json_obj)
        
        # Дополнительные поля
        caller = json_obj.get('@caller') if json_obj else None
        module = json_obj.get('@module') if json_obj else None
        req_id = json_obj.get('tf_req_id') if json_obj else None
        rpc = json_obj.get('tf_rpc') if json_obj else None
        
        # Создаем LogEntry
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
        
        # Применяем плагины к entry
        for plugin in self.plugins:
            entry = plugin.process_entry(entry)
            if entry is None:
                return None
        
        return entry
    
    def parse_lines(self, lines: List[str]) -> List[LogEntry]:
        """
        Парсит несколько строк логов
        
        Args:
            lines: Список строк логов
            
        Returns:
            Список LogEntry объектов
        """
        entries = []
        for line in lines:
            entry = self.parse_line(line)
            if entry:
                entries.append(entry)
        return entries
