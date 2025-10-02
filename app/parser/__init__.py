# app/parser/__init__.py
"""
Парсеры для логов Terraform
Путь: app/parser/__init__.py
"""

from app.parser.terraform_parser import TerraformLogParser

__all__ = ['TerraformLogParser']
