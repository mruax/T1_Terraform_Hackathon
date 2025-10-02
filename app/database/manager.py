# app/database/manager.py
"""
Менеджер для работы с PostgreSQL базой данных
Путь: app/database/manager.py
"""

import json
import logging
import traceback
from datetime import datetime, timezone
from typing import List, Dict, Optional

import asyncpg

from app.models.log_entry import LogEntry, LogLevel

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Менеджер базы данных для хранения логов
    
    Управляет:
    - Подключением к PostgreSQL
    - Созданием таблиц
    - Сохранением и получением логов
    - Дедупликацией файлов по хешу
    
    Example:
        >>> db = DatabaseManager("postgresql://user:pass@localhost/dbname")
        >>> await db.connect()
        >>> file_id = await db.save_log_file("app.log", "hash123", entries)
    """
    
    def __init__(self, db_url: str):
        """
        Args:
            db_url: URL подключения к PostgreSQL
        """
        self.db_url = db_url
        self.pool = None
        logger.info(f"DatabaseManager initialized with URL: {db_url}")
    
    async def connect(self):
        """Создает пул подключений к базе данных"""
        logger.info("Connecting to database...")
        try:
            self.pool = await asyncpg.create_pool(
                self.db_url, 
                min_size=2, 
                max_size=10
            )
            logger.info("Database connection pool created")
            await self._create_tables()
            logger.info("Database tables verified/created")
        except Exception as e:
            logger.error(f"Failed to connect to database: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    async def disconnect(self):
        """Закрывает пул подключений"""
        if self.pool:
            logger.info("Closing database connection pool")
            await self.pool.close()
    
    async def _create_tables(self):
        """Создает необходимые таблицы в базе данных"""
        async with self.pool.acquire() as conn:
            # Удаляем старые таблицы если есть
            await conn.execute('DROP TABLE IF EXISTS log_entries CASCADE')
            await conn.execute('DROP TABLE IF EXISTS log_files CASCADE')
            
            # Таблица файлов логов
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS log_files (
                    id SERIAL PRIMARY KEY,
                    filename VARCHAR(255) NOT NULL,
                    file_hash VARCHAR(64) UNIQUE NOT NULL,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_entries INTEGER,
                    error_count INTEGER,
                    warn_count INTEGER,
                    metadata JSONB
                )
            ''')
            
            # Таблица записей логов
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS log_entries (
                    id SERIAL PRIMARY KEY,
                    file_id INTEGER REFERENCES log_files(id) ON DELETE CASCADE,
                    timestamp TIMESTAMP,
                    level VARCHAR(10),
                    message TEXT,
                    raw_json JSONB,
                    section_type VARCHAR(50),
                    req_id VARCHAR(100),
                    UNIQUE(file_id, timestamp, message)
                )
            ''')
            
            # Индексы для оптимизации запросов
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_log_entries_file_id 
                ON log_entries(file_id)
            ''')
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_log_entries_level 
                ON log_entries(level)
            ''')
            
            logger.info("Database schema created/updated successfully")
    
    async def file_exists(self, file_hash: str) -> Optional[int]:
        """
        Проверяет существование файла по хешу
        
        Args:
            file_hash: SHA256 хеш файла
            
        Returns:
            ID файла если существует, иначе None
        """
        async with self.pool.acquire() as conn:
            result = await conn.fetchval(
                'SELECT id FROM log_files WHERE file_hash = $1',
                file_hash
            )
            return result
    
    async def save_log_file(
        self, 
        filename: str, 
        file_hash: str, 
        entries: List[LogEntry]
    ) -> int:
        """
        Сохраняет файл логов и все его записи
        
        Args:
            filename: Имя файла
            file_hash: SHA256 хеш файла
            entries: Список записей логов
            
        Returns:
            ID созданного файла
        """
        error_count = sum(1 for e in entries if e.level == LogLevel.ERROR)
        warn_count = sum(1 for e in entries if e.level == LogLevel.WARN)
        
        logger.info(
            f"Saving log file: {filename}, entries: {len(entries)}, "
            f"errors: {error_count}, warnings: {warn_count}"
        )
        
        async with self.pool.acquire() as conn:
            try:
                # Создаем запись файла
                file_id = await conn.fetchval('''
                    INSERT INTO log_files 
                    (filename, file_hash, total_entries, error_count, warn_count)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                ''', filename, file_hash, len(entries), error_count, warn_count)
                
                logger.info(f"Created log_files record with id: {file_id}")
                
                # Сохраняем записи логов
                entry_count = 0
                for i, entry in enumerate(entries):
                    try:
                        # Обработка временной метки
                        if isinstance(entry.timestamp, str):
                            ts = datetime.fromisoformat(
                                entry.timestamp.replace('Z', '+00:00')
                            )
                        else:
                            ts = entry.timestamp
                        
                        # Убираем timezone для PostgreSQL
                        if ts.tzinfo is not None:
                            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
                        
                        # Сериализуем JSON
                        raw_json_str = (
                            json.dumps(entry.raw_json) 
                            if entry.raw_json else None
                        )
                        
                        # Вставляем запись
                        await conn.execute('''
                            INSERT INTO log_entries 
                            (file_id, timestamp, level, message, raw_json, 
                             section_type, req_id)
                            VALUES ($1, $2, $3, $4, $5, $6, $7)
                            ON CONFLICT DO NOTHING
                        ''', file_id, ts, entry.level.name, entry.message, 
                        raw_json_str, entry.section_type, entry.req_id)
                        
                        entry_count += 1
                        
                        if i % 100 == 0:
                            logger.debug(f"Saved {i}/{len(entries)} entries")
                            
                    except Exception as entry_error:
                        logger.error(f"Error saving entry {i}: {str(entry_error)}")
                        if i < 3:
                            logger.error(f"Full entry: {entry}")
                        raise
                
                logger.info(f"Successfully saved {entry_count} entries")
                return file_id
                
            except Exception as e:
                logger.error(f"Error in save_log_file: {str(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")
                raise
    
    async def get_log_files(self) -> List[Dict]:
        """
        Получает список всех файлов логов
        
        Returns:
            Список словарей с информацией о файлах
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, filename, upload_date, total_entries, 
                       error_count, warn_count
                FROM log_files
                ORDER BY upload_date DESC
            ''')
            return [dict(row) for row in rows]
    
    async def get_log_entries(self, file_id: int) -> List[Dict]:
        """
        Получает все записи логов для файла
        
        Args:
            file_id: ID файла
            
        Returns:
            Список записей логов
        """
        async with self.pool.acquire() as conn:
            rows = await conn.fetch('''
                SELECT timestamp, level, message, raw_json, 
                       section_type, req_id
                FROM log_entries
                WHERE file_id = $1
                ORDER BY timestamp
            ''', file_id)
            return [dict(row) for row in rows]
    
    async def delete_log_file(self, file_id: int):
        """
        Удаляет файл логов и все его записи
        
        Args:
            file_id: ID файла для удаления
        """
        async with self.pool.acquire() as conn:
            await conn.execute('DELETE FROM log_files WHERE id = $1', file_id)
