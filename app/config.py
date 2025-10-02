# app/config.py
"""
Конфигурационный модуль для загрузки настроек плагинов
Путь: app/config.py
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

from app.models.log_entry import LogLevel
from app.plugins import (
    SensitiveDataPlugin,
    FieldFilterPlugin,
    LogLevelFilterPlugin,
    NoiseFilterPlugin,
    HTTPBodyCompressionPlugin,
)

logger = logging.getLogger(__name__)


class PluginConfigLoader:
    """
    Загрузчик конфигураций плагинов из JSON файла
    
    Поддерживает множественные профили конфигурации:
    - default: базовые настройки
    - production: для продакшена
    - debug: для отладки
    
    Example:
        >>> loader = PluginConfigLoader("plugin_config.json")
        >>> plugins = loader.create_plugins_from_config("production")
    """
    
    def __init__(self, config_path: str = "plugin_config.json"):
        """
        Args:
            config_path: Путь к JSON файлу с конфигурациями
        """
        self.config_path = Path(config_path)
        self.configs = {}
        self.load_configs()
    
    def load_configs(self):
        """Загружает все конфигурации из JSON файла"""
        if not self.config_path.exists():
            logger.warning(
                f"Config file not found: {self.config_path}, using defaults"
            )
            self.configs = self._get_default_config()
            return
        
        try:
            with open(self.config_path, 'r') as f:
                self.configs = json.load(f)
            logger.info(f"Loaded configurations: {list(self.configs.keys())}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.configs = self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Возвращает конфигурацию по умолчанию"""
        return {
            "default": {
                "SensitiveDataPlugin": {
                    "enabled": True,
                    "redact_value": "[REDACTED]",
                    "keep_prefix": 4
                },
                "LogLevelFilterPlugin": {
                    "enabled": True,
                    "min_level": "TRACE"
                },
                "NoiseFilterPlugin": {
                    "enabled": False,
                    "use_defaults": True,
                    "deduplicate": False,
                    "max_repeats": 3
                },
                "HTTPBodyCompressionPlugin": {
                    "enabled": False,
                    "max_size": 1000
                }
            }
        }
    
    def get_config(self, profile: str = "default") -> Dict:
        """
        Получить конфигурацию для определенного профиля
        
        Args:
            profile: Имя профиля конфигурации
            
        Returns:
            Словарь с настройками плагинов
        """
        return self.configs.get(profile, self.configs.get("default", {}))
    
    def create_plugins_from_config(self, profile: str = "default") -> List:
        """
        Создает экземпляры плагинов из конфигурации
        
        Args:
            profile: Имя профиля конфигурации
            
        Returns:
            Список инициализированных плагинов
        """
        config = self.get_config(profile)
        plugins = []
        
        for plugin_name, plugin_config in config.items():
            if not plugin_config.get("enabled", False):
                continue
            
            try:
                if plugin_name == "SensitiveDataPlugin":
                    plugins.append(SensitiveDataPlugin(
                        redact_value=plugin_config.get("redact_value", "[REDACTED]"),
                        keep_prefix=plugin_config.get("keep_prefix", 4)
                    ))
                
                elif plugin_name == "FieldFilterPlugin":
                    plugins.append(FieldFilterPlugin(
                        exclude_fields=plugin_config.get("exclude_fields"),
                        include_fields=plugin_config.get("include_fields")
                    ))
                
                elif plugin_name == "LogLevelFilterPlugin":
                    level_str = plugin_config.get("min_level", "TRACE")
                    plugins.append(LogLevelFilterPlugin(
                        min_level=LogLevel[level_str]
                    ))
                
                elif plugin_name == "NoiseFilterPlugin":
                    plugins.append(NoiseFilterPlugin(
                        noise_patterns=plugin_config.get("noise_patterns"),
                        use_defaults=plugin_config.get("use_defaults", True),
                        deduplicate=plugin_config.get("deduplicate", False),
                        max_repeats=plugin_config.get("max_repeats", 3)
                    ))
                
                elif plugin_name == "HTTPBodyCompressionPlugin":
                    plugins.append(HTTPBodyCompressionPlugin(
                        max_size=plugin_config.get("max_size", 1000),
                        max_items_preview=plugin_config.get("max_items_preview", 3),
                        max_depth=plugin_config.get("max_depth", 3)
                    ))
                
                logger.info(f"Created plugin: {plugin_name}")
            
            except Exception as e:
                logger.error(f"Error creating plugin {plugin_name}: {e}")
        
        return plugins
