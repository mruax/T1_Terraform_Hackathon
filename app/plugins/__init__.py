# app/plugins/__init__.py
"""
Плагины для обработки логов Terraform
Путь: app/plugins/__init__.py
"""

from app.plugins.base import LogPlugin
from app.plugins.sensitive_data import SensitiveDataPlugin
from app.plugins.field_filter import FieldFilterPlugin
from app.plugins.level_filter import LogLevelFilterPlugin
from app.plugins.noise_filter import NoiseFilterPlugin
from app.plugins.http_compression import HTTPBodyCompressionPlugin

__all__ = [
    'LogPlugin',
    'SensitiveDataPlugin',
    'FieldFilterPlugin',
    'LogLevelFilterPlugin',
    'NoiseFilterPlugin',
    'HTTPBodyCompressionPlugin',
]
