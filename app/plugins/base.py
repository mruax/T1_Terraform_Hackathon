# app/plugins/base.py
"""
Базовый класс для плагинов обработки логов
Путь: app/plugins/base.py
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.models.log_entry import LogEntry


class LogPlugin(ABC):
    """
    Базовый класс для всех плагинов обработки логов
    
    Каждый плагин может:
    1. Обрабатывать сырой JSON перед парсингом (process_json)
    2. Обрабатывать или фильтровать готовую запись (process_entry)
    """
    
    @abstractmethod
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Обработка сырого JSON объекта
        
        Args:
            json_obj: Словарь с данными из JSON строки лога
            
        Returns:
            Обработанный словарь или None для фильтрации
        """
        pass
    
    @abstractmethod
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """
        Обработка готовой записи лога
        
        Args:
            entry: Объект LogEntry после парсинга
            
        Returns:
            Обработанный LogEntry или None для фильтрации
        """
        pass
