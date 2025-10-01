"""
ПОЛНОЕ РУКОВОДСТВО ПО ПОДКЛЮЧЕНИЮ ПЛАГИНОВ
==========================================

Этот файл показывает все способы подключения и использования плагинов
"""

from terraform_plugins import (
    SensitiveDataPlugin,
    FieldFilterPlugin,
    LogLevelFilterPlugin,
    NoiseFilterPlugin,
    HTTPBodyCompressionPlugin,
    LogLevel,
    LogEntry
)
from typing import List


# ==================== СПОСОБ 1: БАЗОВОЕ ПОДКЛЮЧЕНИЕ ====================

def basic_usage():
    """Самый простой способ - создать и использовать один плагин"""
    
    # Создаем плагин
    plugin = SensitiveDataPlugin()
    
    # Используем для обработки данных
    test_data = {
        "@message": "User authenticated",
        "api_key": "secret123",
        "username": "john"
    }
    
    # Обрабатываем JSON
    cleaned_data = plugin.process_json(test_data)
    print(f"Cleaned: {cleaned_data}")
    
    # Результат: {'@message': 'User authenticated', 'api_key': '[REDACTED]', 'username': 'john'}


# ==================== СПОСОБ 2: МНОЖЕСТВЕННЫЕ ПЛАГИНЫ ====================

def multiple_plugins():
    """Использование нескольких плагинов в цепочке"""
    
    # Создаем список плагинов
    plugins = [
        SensitiveDataPlugin(redact_value="***"),
        NoiseFilterPlugin(use_defaults=True),
        LogLevelFilterPlugin(min_level=LogLevel.INFO),
    ]
    
    # Применяем плагины последовательно
    test_data = {"@level": "debug", "@message": "Cache hit", "token": "abc123"}
    
    result = test_data
    for plugin in plugins:
        result = plugin.process_json(result)
        if result is None:
            print("Filtered out by plugin")
            break
    
    print(f"Result: {result}")


# ==================== СПОСОБ 3: ИНТЕГРАЦИЯ С ПАРСЕРОМ ====================

class TerraformLogParser:
    """Парсер с поддержкой плагинов"""
    
    def __init__(self, plugins: List = None):
        self.plugins = plugins or []
    
    def add_plugin(self, plugin):
        """Добавить плагин динамически"""
        self.plugins.append(plugin)
    
    def parse_line(self, line: str) -> LogEntry:
        """Парсит одну строку с применением плагинов"""
        import json
        
        # Парсим JSON
        try:
            json_obj = json.loads(line)
        except:
            return None
        
        # Применяем плагины к JSON
        for plugin in self.plugins:
            json_obj = plugin.process_json(json_obj)
            if json_obj is None:
                return None  # Отфильтровано
        
        # Создаем LogEntry (упрощенно)
        entry = LogEntry(
            timestamp=json_obj.get('@timestamp', ''),
            level=LogLevel[json_obj.get('@level', 'INFO').upper()],
            message=json_obj.get('@message', ''),
            raw_json=json_obj
        )
        
        # Применяем плагины к entry
        for plugin in self.plugins:
            entry = plugin.process_entry(entry)
            if entry is None:
                return None  # Отфильтровано
        
        return entry


def parser_integration():
    """Пример интеграции с парсером"""
    
    # Создаем парсер с плагинами
    parser = TerraformLogParser(plugins=[
        SensitiveDataPlugin(),
        LogLevelFilterPlugin(min_level=LogLevel.INFO)
    ])
    
    # Или добавляем плагины потом
    parser.add_plugin(NoiseFilterPlugin())
    
    # Парсим лог
    log_line = '{"@level":"info","@message":"Success","api_key":"secret"}'
    entry = parser.parse_line(log_line)
    
    if entry:
        print(f"Parsed: {entry.message}")


# ==================== СПОСОБ 4: КОНФИГУРАЦИЯ ЧЕРЕЗ ФАЙЛ ====================

import json

def load_plugins_from_config(config_path: str) -> List:
    """Загружает конфигурацию плагинов из JSON файла"""
    
    with open(config_path, 'r') as f:
        config = json.load(f)
    
    plugins = []
    
    for plugin_config in config['plugins']:
        plugin_type = plugin_config['type']
        params = plugin_config.get('params', {})
        
        if plugin_type == 'SensitiveDataPlugin':
            plugins.append(SensitiveDataPlugin(**params))
        
        elif plugin_type == 'FieldFilterPlugin':
            plugins.append(FieldFilterPlugin(**params))
        
        elif plugin_type == 'LogLevelFilterPlugin':
            # Конвертируем строку в enum
            if 'min_level' in params:
                params['min_level'] = LogLevel[params['min_level']]
            plugins.append(LogLevelFilterPlugin(**params))
        
        elif plugin_type == 'NoiseFilterPlugin':
            plugins.append(NoiseFilterPlugin(**params))
        
        elif plugin_type == 'HTTPBodyCompressionPlugin':
            plugins.append(HTTPBodyCompressionPlugin(**params))
    
    return plugins


def config_file_example():
    """Пример использования конфигурационного файла"""
    
    # Создаем пример конфига
    config = {
        "plugins": [
            {
                "type": "SensitiveDataPlugin",
                "params": {
                    "redact_value": "[HIDDEN]",
                    "keep_prefix": 4
                }
            },
            {
                "type": "LogLevelFilterPlugin",
                "params": {
                    "min_level": "INFO"
                }
            },
            {
                "type": "NoiseFilterPlugin",
                "params": {
                    "use_defaults": True,
                    "deduplicate": True,
                    "max_repeats": 3
                }
            }
        ]
    }
    
    # Сохраняем в файл
    with open('plugin_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    # Загружаем плагины из файла
    plugins = load_plugins_from_config('plugin_config.json')
    
    print(f"Loaded {len(plugins)} plugins from config")


# ==================== СПОСОБ 5: FASTAPI ИНТЕГРАЦИЯ ====================

from fastapi import FastAPI, UploadFile, File, Query

app = FastAPI()

@app.post("/upload-log/")
async def upload_log(
    file: UploadFile = File(...),
    # Параметры для плагинов
    redact_sensitive: bool = Query(True, description="Remove API tokens and secrets"),
    min_level: str = Query("TRACE", description="Minimum log level (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)"),
    remove_noise: bool = Query(False, description="Filter out repetitive logs"),
    compress_bodies: bool = Query(False, description="Compress large HTTP bodies"),
    max_body_size: int = Query(1000, description="Max HTTP body size in bytes before compression"),
    # Дополнительные параметры
    exclude_fields: str = Query(None, description="Comma-separated fields to exclude"),
    include_fields: str = Query(None, description="Comma-separated fields to include (whitelist mode)")
):
    """
    Upload and process Terraform logs with configurable plugins
    
    Example usage:
        curl -X POST "http://localhost:8000/upload-log/?redact_sensitive=true&min_level=INFO&remove_noise=true" \
             -F "file=@terraform.log"
    """
    
    # Собираем плагины на основе параметров
    plugins = []
    
    # 1. Sensitive data
    if redact_sensitive:
        plugins.append(SensitiveDataPlugin(redact_value="[REDACTED]"))
    
    # 2. Field filter
    if exclude_fields:
        plugins.append(FieldFilterPlugin(
            exclude_fields=exclude_fields.split(',')
        ))
    elif include_fields:
        plugins.append(FieldFilterPlugin(
            include_fields=include_fields.split(',')
        ))
    
    # 3. Log level filter
    try:
        level = LogLevel[min_level.upper()]
        plugins.append(LogLevelFilterPlugin(min_level=level))
    except KeyError:
        pass  # Игнорируем неверный уровень
    
    # 4. Noise filter
    if remove_noise:
        plugins.append(NoiseFilterPlugin(
            use_defaults=True,
            deduplicate=True,
            max_repeats=3
        ))
    
    # 5. HTTP body compression
    if compress_bodies:
        plugins.append(HTTPBodyCompressionPlugin(
            max_size=max_body_size,
            max_items_preview=3
        ))
    
    # Создаем парсер с плагинами
    parser = TerraformLogParser(plugins=plugins)
    
    # Читаем и обрабатываем файл
    content = await file.read()
    lines = content.decode('utf-8').splitlines()
    
    processed_entries = []
    filtered_count = 0
    
    for line in lines:
        entry = parser.parse_line(line)
        if entry:
            processed_entries.append(entry)
        else:
            filtered_count += 1
    
    return {
        "status": "success",
        "total_lines": len(lines),
        "processed_entries": len(processed_entries),
        "filtered_entries": filtered_count,
        "plugins_applied": [type(p).__name__ for p in plugins],
        "entries": [
            {
                "timestamp": e.timestamp,
                "level": e.level.name,
                "message": e.message
            }
            for e in processed_entries[:100]  # Первые 100
        ]
    }


# ==================== СПОСОБ 6: СОЗДАНИЕ СВОЕГО ПЛАГИНА ====================

from terraform_plugins import LogPlugin

class CustomPlugin(LogPlugin):
    """
    Пример создания собственного плагина
    
    Этот плагин считает количество ошибок и предупреждений
    """
    
    def __init__(self):
        self.error_count = 0
        self.warn_count = 0
    
    def process_json(self, json_obj):
        """Не меняем JSON"""
        return json_obj
    
    def process_entry(self, entry):
        """Считаем ошибки и предупреждения"""
        if entry.level == LogLevel.ERROR:
            self.error_count += 1
        elif entry.level == LogLevel.WARN:
            self.warn_count += 1
        
        return entry  # Пропускаем запись дальше
    
    def get_stats(self):
        """Получить статистику"""
        return {
            "errors": self.error_count,
            "warnings": self.warn_count
        }


def custom_plugin_example():
    """Пример использования своего плагина"""
    
    stats_plugin = CustomPlugin()
    
    parser = TerraformLogParser(plugins=[
        SensitiveDataPlugin(),
        stats_plugin  # Наш плагин
    ])
    
    # Парсим логи...
    # parser.parse_file('terraform.log')
    
    # Получаем статистику
    print(stats_plugin.get_stats())


# ==================== ПРЕДУСТАНОВЛЕННЫЕ КОНФИГУРАЦИИ ====================

class PluginPresets:
    """Готовые наборы плагинов для разных сценариев"""
    
    @staticmethod
    def production():
        """Конфигурация для production - безопасность и производительность"""
        return [
            SensitiveDataPlugin(redact_value="[HIDDEN]", keep_prefix=0),
            FieldFilterPlugin(include_fields=['@message', '@level', '@timestamp', 'tf_req_id']),
            LogLevelFilterPlugin(min_level=LogLevel.INFO),
            NoiseFilterPlugin(use_defaults=True, deduplicate=True, max_repeats=2),
            HTTPBodyCompressionPlugin(max_size=500, max_items_preview=2)
        ]
    
    @staticmethod
    def development():
        """Конфигурация для разработки - показываем больше деталей"""
        return [
            SensitiveDataPlugin(keep_prefix=8),  # Показываем начало токенов
            LogLevelFilterPlugin(min_level=LogLevel.DEBUG),
            NoiseFilterPlugin(use_defaults=True, max_repeats=5)
        ]
    
    @staticmethod
    def debugging():
        """Конфигурация для отладки - показываем всё"""
        return [
            SensitiveDataPlugin(keep_prefix=16),  # Больше символов для отладки
            LogLevelFilterPlugin(min_level=LogLevel.TRACE)  # Всё, включая TRACE
            # Без NoiseFilter - показываем все логи
        ]
    
    @staticmethod
    def minimal():
        """Минимальная конфигурация - только критичное"""
        return [
            SensitiveDataPlugin(),
            LogLevelFilterPlugin(min_level=LogLevel.ERROR)  # Только ошибки
        ]
    
    @staticmethod
    def audit():
        """Конфигурация для аудита - максимум информации, минимум фильтров"""
        return [
            SensitiveDataPlugin(keep_prefix=4),  # Частичная маскировка для идентификации
            # Не фильтруем по уровню
            # Не убираем шум
        ]


def preset_usage():
    """Использование готовых конфигураций"""
    
    # Для production
    prod_parser = TerraformLogParser(plugins=PluginPresets.production())
    
    # Для разработки
    dev_parser = TerraformLogParser(plugins=PluginPresets.development())
    
    # Для отладки
    debug_parser = TerraformLogParser(plugins=PluginPresets.debugging())
    
    print("Available presets:")
    print("- production: Безопасность + производительность")
    print("- development: Баланс между детализацией и удобством")
    print("- debugging: Максимум информации")
    print("- minimal: Только ошибки")
    print("- audit: Для аудита и расследований")


# ==================== ГЛАВНАЯ ФУНКЦИЯ ====================

def main():
    """Демонстрация всех способов использования"""
    
    print("=" * 70)
    print("СПОСОБЫ ПОДКЛЮЧЕНИЯ ПЛАГИНОВ К TERRAFORM LOG PARSER")
    print("=" * 70)
    
    print("\n1. Базовое использование")
    print("-" * 70)
    basic_usage()
    
    print("\n2. Множественные плагины")
    print("-" * 70)
    multiple_plugins()
    
    print("\n3. Интеграция с парсером")
    print("-" * 70)
    parser_integration()
    
    print("\n4. Конфигурация через файл")
    print("-" * 70)
    config_file_example()
    
    print("\n5. Использование пресетов")
    print("-" * 70)
    preset_usage()
    
    print("\n" + "=" * 70)
    print("ПОЛНАЯ ДОКУМЕНТАЦИЯ")
    print("=" * 70)
    
    print("""
БЫСТРЫЙ СТАРТ:
--------------
1. Импортируйте нужные плагины:
   from terraform_plugins import SensitiveDataPlugin, LogLevelFilterPlugin

2. Создайте список плагинов:
   plugins = [SensitiveDataPlugin(), LogLevelFilterPlugin(LogLevel.INFO)]

3. Передайте в парсер:
   parser = TerraformLogParser(plugins=plugins)

4. Парсите логи:
   entries = parser.parse_file('terraform.log')


ДОСТУПНЫЕ ПЛАГИНЫ:
------------------
1. SensitiveDataPlugin - Удаление токенов и секретов
   Параметры: redact_value="[REDACTED]", keep_prefix=0

2. FieldFilterPlugin - Фильтрация полей
   Параметры: exclude_fields=['field1'], include_fields=['field2']

3. LogLevelFilterPlugin - Фильтр по уровню логов
   Параметры: min_level=LogLevel.INFO

4. NoiseFilterPlugin - Удаление шумных логов
   Параметры: noise_patterns=[], use_defaults=True, deduplicate=False

5. HTTPBodyCompressionPlugin - Сжатие HTTP тел
   Параметры: max_size=1000, max_items_preview=3


ГОТОВЫЕ ПРЕСЕТЫ:
---------------
- PluginPresets.production()   - Для продакшена
- PluginPresets.development()  - Для разработки
- PluginPresets.debugging()    - Для отладки
- PluginPresets.minimal()      - Минимальный набор
- PluginPresets.audit()        - Для аудита


СОЗДАНИЕ СВОЕГО ПЛАГИНА:
-----------------------
class MyPlugin(LogPlugin):
    def process_json(self, json_obj):
        # Обработка JSON
        return json_obj
    
    def process_entry(self, entry):
        # Обработка LogEntry
        return entry  # или None для фильтрации


API ENDPOINTS:
-------------
POST /upload-log/?redact_sensitive=true&min_level=INFO&remove_noise=true

Параметры:
- redact_sensitive: bool - Удалять чувствительные данные
- min_level: str - Минимальный уровень (TRACE/DEBUG/INFO/WARN/ERROR/FATAL)
- remove_noise: bool - Убирать шумные логи
- compress_bodies: bool - Сжимать HTTP bodies
- exclude_fields: str - Поля для исключения (через запятую)
- include_fields: str - Поля для включения (whitelist)
    """)


if __name__ == "__main__":
    main()
