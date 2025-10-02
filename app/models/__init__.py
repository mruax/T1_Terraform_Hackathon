# app/models/__init__.py
"""
Модели данных для логов
Путь: app/models/__init__.py
"""

from app.models.log_entry import LogLevel, LogEntry

__all__ = ['LogLevel', 'LogEntry']
