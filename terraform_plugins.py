"""
Terraform Log Parser - Plugin System
Модульная система для обработки и фильтрации логов
"""

import re
import json
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass
from enum import Enum


# ==================== BASE CLASSES ====================

class LogLevel(Enum):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARN = 3
    ERROR = 4
    FATAL = 5


@dataclass
class LogEntry:
    """Структура одной записи лога"""
    timestamp: str
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


# ==================== PLUGIN 1: SENSITIVE DATA REDACTION ====================

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
        >>> plugin = SensitiveDataPlugin(keep_prefix=4)  # Показывает первые 4 символа
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
        # Bearer токены: Bearer abc123xyz
        re.compile(r'bearer\s+[a-zA-Z0-9_\-\.]{10,}', re.IGNORECASE),
        
        # API ключи: api_key=abc123 или apiKey: abc123
        re.compile(r'api[_\-]?key[\s:=]+[a-zA-Z0-9_\-\.]{10,}', re.IGNORECASE),
        
        # Токены: token=abc123
        re.compile(r'token[\s:=]+[a-zA-Z0-9_\-\.]{10,}', re.IGNORECASE),
        
        # AWS ключи
        re.compile(r'AKIA[0-9A-Z]{16}'),
        
        # JWT токены (базовая проверка)
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
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Рекурсивно очищает словарь от чувствительных данных"""
        sanitized = {}
        
        for key, value in data.items():
            # Проверяем ключ
            if self._is_sensitive_key(key):
                sanitized[key] = self._redact_value(value)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_dict(item) if isinstance(item, dict)
                    else self._sanitize_string(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            elif isinstance(value, str):
                # Проверяем строку на паттерны
                sanitized[key] = self._sanitize_string(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Очищает JSON от чувствительных данных"""
        return self._sanitize_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Очищает entry от чувствительных данных"""
        if entry.http_request:
            entry.http_request = self._sanitize_dict(entry.http_request)
        
        if entry.http_response:
            entry.http_response = self._sanitize_dict(entry.http_response)
        
        if entry.terraform_metadata:
            entry.terraform_metadata = self._sanitize_dict(entry.terraform_metadata)
        
        # Очищаем сообщение
        entry.message = self._sanitize_string(entry.message)
        
        return entry


# ==================== PLUGIN 2: FIELD FILTER ====================

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
            # Whitelist: оставляем только указанные поля
            return {k: v for k, v in data.items() if k in self.include_fields}
        else:
            # Blacklist: удаляем указанные поля
            return {k: v for k, v in data.items() if k not in self.exclude_fields}
    
    def process_json(self, json_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Фильтрует поля в JSON"""
        return self._filter_dict(json_obj)
    
    def process_entry(self, entry: LogEntry) -> Optional[LogEntry]:
        """Entry уже отфильтрован на уровне JSON"""
        return entry


# ==================== PLUGIN 3: LOG LEVEL FILTER ====================

class LogLevelFilterPlugin(LogPlugin):
    """
    Плагин для фильтрации логов по уровню
    
    Пропускает только логи с уровнем >= min_level
    
    Example:
        # Показывать только INFO и выше (убирает TRACE и DEBUG)
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
            return None  # Отфильтровать эту запись
        return entry


# ==================== PLUGIN 4: NOISE FILTER ====================

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
        
        # Дедупликация
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


# ==================== PLUGIN 5: HTTP BODY COMPRESSION ====================

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
            return body  # Не нужно сжимать
        
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


# ==================== USAGE EXAMPLES ====================

def example_usage():
    """Примеры использования плагинов"""
    
    print("=" * 60)
    print("TERRAFORM LOG PLUGINS - EXAMPLES")
    print("=" * 60)
    
    # ============ ПРИМЕР 1: Один плагин ============
    print("\n1. Использование одного плагина:")
    print("-" * 60)
    
    sensitive_plugin = SensitiveDataPlugin(redact_value="***", keep_prefix=4)
    
    test_data = {
        "@message": "Authentication with token abc123xyz",
        "api_key": "secret_key_12345",
        "user": "john"
    }
    
    cleaned = sensitive_plugin.process_json(test_data)
    print(f"Исходные данные: {test_data}")
    print(f"После обработки: {cleaned}")
    
    # ============ ПРИМЕР 2: Несколько плагинов ============
    print("\n\n2. Использование нескольких плагинов вместе:")
    print("-" * 60)
    
    plugins = [
        SensitiveDataPlugin(),
        LogLevelFilterPlugin(min_level=LogLevel.INFO),
        NoiseFilterPlugin(use_defaults=True),
    ]
    
    print(f"Активные плагины: {[type(p).__name__ for p in plugins]}")
    
    # ============ ПРИМЕР 3: Конфигурация для production ============
    print("\n\n3. Production конфигурация:")
    print("-" * 60)
    
    production_plugins = [
        # Удаляем все секреты
        SensitiveDataPlugin(
            redact_value="[HIDDEN]",
            keep_prefix=0
        ),
        
        # Оставляем только важные поля
        FieldFilterPlugin(
            include_fields=['@message', '@level', '@timestamp', 'tf_req_id']
        ),
        
        # Фильтруем DEBUG логи
        LogLevelFilterPlugin(min_level=LogLevel.INFO),
        
        # Убираем шум
        NoiseFilterPlugin(
            use_defaults=True,
            deduplicate=True,
            max_repeats=2
        ),
        
        # Сжимаем большие HTTP bodies
        HTTPBodyCompressionPlugin(
            max_size=500,
            max_items_preview=2
        )
    ]
    
    for plugin in production_plugins:
        print(f"✓ {type(plugin).__name__}")
    
    # ============ ПРИМЕР 4: Конфигурация для debugging ============
    print("\n\n4. Debug конфигурация (показываем всё):")
    print("-" * 60)
    
    debug_plugins = [
        # Маскируем, но показываем начало токенов
        SensitiveDataPlugin(keep_prefix=8),
        
        # Показываем все уровни
        LogLevelFilterPlugin(min_level=LogLevel.TRACE),
        
        # Не убираем шум (для полной картины)
        # NoiseFilterPlugin отключен
    ]
    
    for plugin in debug_plugins:
        print(f"✓ {type(plugin).__name__}")
    
    # ============ ПРИМЕР 5: Кастомные паттерны ============
    print("\n\n5. Кастомные фильтры:")
    print("-" * 60)
    
    custom_noise = NoiseFilterPlugin(
        noise_patterns=[
            r'connecting\s+to\s+database',
            r'heartbeat\s+check',
            r'health\s+check\s+passed',
        ],
        use_defaults=False,
        deduplicate=True,
        max_repeats=5
    )
    
    print("Кастомные паттерны для фильтрации:")
    print("- Логи подключения к БД")
    print("- Heartbeat проверки")
    print("- Health checks")
    print(f"- Дедупликация после {5} повторов")


if __name__ == "__main__":
    example_usage()
    
    print("\n" + "=" * 60)
    print("КАК ПОДКЛЮЧИТЬ ПЛАГИНЫ К ПАРСЕРУ")
    print("=" * 60)
    print("""
# Шаг 1: Импортировать плагины
from terraform_plugins import (
    SensitiveDataPlugin,
    FieldFilterPlugin,
    LogLevelFilterPlugin,
    NoiseFilterPlugin,
    HTTPBodyCompressionPlugin,
    LogLevel
)

# Шаг 2: Создать нужные плагины
plugins = [
    SensitiveDataPlugin(),
    LogLevelFilterPlugin(min_level=LogLevel.INFO),
    NoiseFilterPlugin(),
    HTTPBodyCompressionPlugin(max_size=1000)
]

# Шаг 3: Передать в парсер
parser = TerraformLogParser(plugins=plugins)

# Шаг 4: Парсить логи
entries = parser.parse_file('terraform.log')

# ИЛИ в FastAPI:
@app.post("/upload-log/")
async def upload_log(
    file: UploadFile,
    redact_sensitive: bool = True,
    min_level: str = "INFO"
):
    plugins = []
    
    if redact_sensitive:
        plugins.append(SensitiveDataPlugin())
    
    plugins.append(LogLevelFilterPlugin(LogLevel[min_level]))
    
    parser = TerraformLogParser(plugins=plugins)
    # ... обработка файла
    """)