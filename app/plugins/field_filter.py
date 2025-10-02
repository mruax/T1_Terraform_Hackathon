# app/plugins/field_filter.py
"""
Плагин для фильтрации полей в логах
Путь: app/plugins/field_filter.py
"""

from typing import Dict, Any, Optional, List, Set
from app.plugins.base import LogPlugin
from app.models.log_entry import LogEntry


class FieldFilterPlugin(LogPlugin):
    """
    Плагин для фильтрации полей в логах
    
    Работает в двух режимах:
    1. Blacklist (exclude_fields) - удаляет указанные поля
    2. Whitelist (include_fields) - оставляет только указанные поля
    
    Example:
        # Удалить ненужные поля
        >>> plugin = FieldFilterPlugin(exclude_fields=['@caller', 'internal_id'])
        
        # Оставить только важные поля
        >>> plugin = FieldFilterPlugin(include_fields=['@message', '@level', '@timestamp'])
    """
    
    def __init__(
        self, 
        exclude_fields: Optional[List[str]] = None,
        include_fields: Optional[List[str]] = None
    ):
        """
        Args:
            exclude_fields: Список полей для удаления (blacklist режим)
            include_fields: Список полей для сохранения (whitelist режим)
                           Если указан, exclude_fields игнорируется
        """
        if include_fields and exclude_fields:
            raise ValueError("Нельзя использовать одновременно include и exclude режимы")
        
        self.exclude_fields = set(exclude_fields or [])
        self.include_fields = set(include_fields) if include_fields else None
        self.mode = 'whitelist' if include_fields else 'blacklist'
    
    def _filter_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Фильтрует поля в словаре"""
        if self.mode == 'whitelist':
            return {k: v for k, v in data.items() if k in self.include_fields}
        else:
            return {k: v for k, v in data.items() if k not in self.exclude_fields}
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Фильтрует поля в JSON"""
        return self._filter_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Entry уже отфильтрован на уровне JSON"""
        return entry
