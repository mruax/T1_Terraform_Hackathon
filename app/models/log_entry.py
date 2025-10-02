# app/models/log_entry.py
"""
Модели данных для логов Terraform
Путь: app/models/log_entry.py
"""

from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, Optional


class LogLevel(Enum):
    """Уровни логирования"""
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARN = 3
    ERROR = 4
    FATAL = 5


@dataclass
class LogEntry:
    """
    Структура одной записи лога
    
    Attributes:
        timestamp: Временная метка записи
        level: Уровень логирования
        message: Текст сообщения
        raw_json: Необработанный JSON объект (если есть)
        caller: Информация о вызывающем коде
        module: Модуль Terraform
        terraform_metadata: Метаданные Terraform (provider, resource type и т.д.)
        http_request: HTTP запрос (если есть)
        http_response: HTTP ответ (если есть)
        section_type: Тип секции (plan, apply, validation и т.д.)
        req_id: ID запроса для связывания логов
        rpc: RPC метод
    """
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
