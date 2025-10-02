# app/plugins/sensitive_data.py
"""
Плагин для удаления чувствительных данных из логов
Путь: app/plugins/sensitive_data.py
"""

import re
from typing import Dict, Any, Optional, Set
from app.plugins.base import LogPlugin
from app.models.log_entry import LogEntry


class SensitiveDataPlugin(LogPlugin):
    """
    Плагин для удаления чувствительных данных из логов
    
    Удаляет или маскирует:
    - API токены и ключи
    - Пароли
    - Bearer токены
    - Authorization заголовки
    - Приватные ключи
    - Секреты
    
    Example:
        >>> plugin = SensitiveDataPlugin(redact_value="***HIDDEN***")
        >>> plugin = SensitiveDataPlugin(keep_prefix=4)
    """
    
    # Ключи, которые считаются чувствительными
    SENSITIVE_KEYS: Set[str] = {
        'token', 'api_key', 'apikey', 'api-key',
        'password', 'passwd', 'pwd',
        'secret', 'private_key', 'privatekey',
        'authorization', 'auth', 'bearer',
        'access_token', 'refresh_token',
        'client_secret', 'credentials',
        'session', 'cookie'
    }
    
    # Регулярные выражения для поиска токенов в тексте
    PATTERNS = [
        re.compile(r'bearer\s+[a-zA-Z0-9_\-\.]{10,}', re.IGNORECASE),
        re.compile(r'api[_\-]?key[\s:=]+[a-zA-Z0-9_\-\.]{10,}', re.IGNORECASE),
        re.compile(r'token[\s:=]+[a-zA-Z0-9_\-\.]{10,}', re.IGNORECASE),
        re.compile(r'AKIA[0-9A-Z]{16}'),
        re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'),
    ]
    
    def __init__(self, redact_value: str = "[REDACTED]", keep_prefix: int = 0):
        """
        Args:
            redact_value: Значение для замены чувствительных данных
            keep_prefix: Количество символов для показа в начале (для отладки)
        """
        self.redact_value = redact_value
        self.keep_prefix = keep_prefix
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Проверяет, является ли ключ чувствительным"""
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in self.SENSITIVE_KEYS)
    
    def _redact_value(self, value: Any) -> str:
        """Маскирует значение"""
        if not isinstance(value, str):
            return self.redact_value
        
        if self.keep_prefix > 0 and len(value) > self.keep_prefix:
            return f"{value[:self.keep_prefix]}...{self.redact_value}"
        
        return self.redact_value
    
    def _sanitize_string(self, text: str) -> str:
        """Удаляет токены из текста по паттернам"""
        for pattern in self.PATTERNS:
            text = pattern.sub(self.redact_value, text)
        return text
    
    def _sanitize_dict(self, data: Any) -> Any:
        """Рекурсивно очищает структуру данных от чувствительной информации"""
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                if self._is_sensitive_key(key):
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
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Очищает JSON от чувствительных данных"""
        if not isinstance(json_obj, dict):
            return json_obj
        return self._sanitize_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Очищает entry от чувствительных данных"""
        if entry.http_request:
            entry.http_request = self._sanitize_dict(entry.http_request)
        
        if entry.http_response:
            entry.http_response = self._sanitize_dict(entry.http_response)
        
        if entry.terraform_metadata:
            entry.terraform_metadata = self._sanitize_dict(entry.terraform_metadata)
        
        if entry.message and isinstance(entry.message, str):
            entry.message = self._sanitize_string(entry.message)
        
        return entry
