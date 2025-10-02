# app/plugins/http_compression.py
"""
Плагин для сжатия больших HTTP тел запросов/ответов
Путь: app/plugins/http_compression.py
"""

import json
from typing import Dict, Any, Optional
from app.plugins.base import LogPlugin
from app.models.log_entry import LogEntry


class HTTPBodyCompressionPlugin(LogPlugin):
    """
    Плагин для сжатия больших HTTP тел запросов/ответов
    
    Когда HTTP body слишком большой:
    - Оставляет только summary со структурой
    - Показывает размеры массивов и объектов
    - Сохраняет первые N элементов для просмотра
    
    Example:
        # Сжимать bodies больше 1KB
        >>> plugin = HTTPBodyCompressionPlugin(max_size=1000)
        
        # Более агрессивное сжатие
        >>> plugin = HTTPBodyCompressionPlugin(
        ...     max_size=500,
        ...     max_items_preview=2,
        ...     max_depth=2
        ... )
    """
    
    def __init__(
        self,
        max_size: int = 1000,
        max_items_preview: int = 3,
        max_depth: int = 3
    ):
        """
        Args:
            max_size: Максимальный размер body в символах
            max_items_preview: Сколько элементов массива показывать
            max_depth: Максимальная глубина вложенности для сохранения
        """
        self.max_size = max_size
        self.max_items_preview = max_items_preview
        self.max_depth = max_depth
    
    def _get_structure_info(self, obj: Any, depth: int = 0) -> Any:
        """Получает информацию о структуре объекта"""
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
        """Сжимает HTTP body если он слишком большой"""
        body_str = json.dumps(body)
        
        if len(body_str) <= self.max_size:
            return body
        
        # Создаем сжатую версию
        compressed = {
            "_compressed": True,
            "_original_size_bytes": len(body_str),
            "_structure": self._get_structure_info(body)
        }
        
        return compressed
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """JSON обрабатывается без изменений"""
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Сжимает HTTP bodies в entry"""
        if entry.http_request:
            entry.http_request = self._compress_body(entry.http_request)
        
        if entry.http_response:
            entry.http_response = self._compress_body(entry.http_response)
        
        return entry
