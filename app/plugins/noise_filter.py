# app/plugins/noise_filter.py
"""
Плагин для удаления шумных/повторяющихся логов
Путь: app/plugins/noise_filter.py
"""

import re
from typing import Dict, Any, Optional, List
from app.plugins.base import LogPlugin
from app.models.log_entry import LogEntry


class NoiseFilterPlugin(LogPlugin):
    """
    Плагин для удаления шумных/повторяющихся логов
    
    Фильтрует логи, которые:
    - Соответствуют заданным паттернам
    - Повторяются слишком часто
    - Не несут полезной информации
    
    Example:
        # Удалить логи про кэш и несуществующие провайдеры
        >>> plugin = NoiseFilterPlugin(
        ...     noise_patterns=[
        ...         r'Schema.*is in the global cache',
        ...         r'ignoring non-existing provider'
        ...     ]
        ... )
        
        # С дедупликацией повторов
        >>> plugin = NoiseFilterPlugin(
        ...     noise_patterns=['cache', 'ignoring'],
        ...     deduplicate=True,
        ...     max_repeats=3
        ... )
    """
    
    # Паттерны по умолчанию для Terraform логов
    DEFAULT_PATTERNS = [
        r'Schema\s+for\s+provider.*is\s+in\s+the\s+global\s+cache',
        r'ignoring\s+non-existing\s+provider\s+search\s+directory',
        r'Checking\s+.*\s+lock',
        r'terraform\.contextPlugins:.*is\s+in\s+the\s+global\s+cache',
        r'Found\s+resource\s+type',
        r'Checking\s+DataSourceTypes\s+lock',
    ]
    
    def __init__(
        self,
        noise_patterns: Optional[List[str]] = None,
        use_defaults: bool = True,
        deduplicate: bool = False,
        max_repeats: int = 3
    ):
        """
        Args:
            noise_patterns: Список regex паттернов для фильтрации
            use_defaults: Использовать ли паттерны по умолчанию
            deduplicate: Включить дедупликацию повторяющихся сообщений
            max_repeats: Максимальное количество повторов одного сообщения
        """
        patterns = []
        
        if use_defaults:
            patterns.extend(self.DEFAULT_PATTERNS)
        
        if noise_patterns:
            patterns.extend(noise_patterns)
        
        self.noise_regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
        
        self.deduplicate = deduplicate
        self.max_repeats = max_repeats
        self.message_counts: Dict[str, int] = {}
    
    def _is_noisy(self, message: str) -> bool:
        """Проверяет, является ли сообщение шумным"""
        for pattern in self.noise_regexes:
            if pattern.search(message):
                return True
        return False
    
    def _is_duplicate(self, message: str) -> bool:
        """Проверяет, не повторяется ли сообщение слишком часто"""
        if not self.deduplicate:
            return False
        
        # Нормализуем сообщение (убираем числа и пути)
        normalized = re.sub(r'\d+', 'N', message)
        normalized = re.sub(r'/[^\s]+', '/PATH', normalized)
        
        count = self.message_counts.get(normalized, 0)
        self.message_counts[normalized] = count + 1
        
        return count >= self.max_repeats
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """JSON обрабатывается без изменений"""
        return json_obj
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Фильтрует шумные логи"""
        if self._is_noisy(entry.message):
            return None
        
        if self._is_duplicate(entry.message):
            return None
        
        return entry
