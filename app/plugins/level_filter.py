# app/plugins/level_filter.py
"""
Плагин для фильтрации логов по уровню
Путь: app/plugins/level_filter.py
"""

from typing import Dict, Any, Optional
from app.plugins.base import LogPlugin
from app.models.log_entry import LogEntry, LogLevel


class LogLevelFilterPlugin(LogPlugin):
    """
    Плагин для фильтрации логов по уровню
    
    Пропускает только логи с уровнем >= min_level
    
    Example:
        # Показывать только INFO и выше
        >>> plugin = LogLevelFilterPlugin(min_level=LogLevel.INFO)
        
        # Показывать только ошибки и критические
        >>> plugin = LogLevelFilterPlugin(min_level=LogLevel.ERROR)
    """
    
    def __init__(self, min_level: LogLevel = LogLevel.TRACE):
        """
        Args:
            min_level: Минимальный уровень логирования для показа
        """
        self.min_level = min_level
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """JSON обрабатывается без изменений"""
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Фильтрует по уровню логирования"""
        if entry.level.value < self.min_level.value:
            return None
        return entry
