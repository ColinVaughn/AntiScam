import asyncio
import logging
import json
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from enum import Enum

from ..database import DatabaseManager, SystemLog

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LogComponent(Enum):
    BOT = "bot"
    DETECTOR = "detector"
    OCR = "ocr"
    LLM = "llm"
    ACTIONER = "actioner"
    DASHBOARD = "dashboard"
    DATABASE = "database"
    PIPELINE = "pipeline"

@dataclass
class LogEntry:
    """Structured log entry"""
    level: LogLevel
    component: LogComponent
    message: str
    guild_id: Optional[str] = None
    user_id: Optional[str] = None
    message_id: Optional[str] = None
    channel_id: Optional[str] = None
    extra_data: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

class AntiScamLogger:
    """Comprehensive logging system for the Anti-Scam Bot"""
    
    def __init__(self, db_manager: DatabaseManager, enable_db_logging: bool = True):
        self.db_manager = db_manager
        self.enable_db_logging = enable_db_logging
        
        # Configure standard Python logger
        self.logger = logging.getLogger("antiscam")
        self.logger.setLevel(logging.INFO)
        
        # Create formatters
        self.console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        self.file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        
        # Setup handlers
        self._setup_handlers()
        
        # Statistics tracking
        self.stats = {
            'total_logs': 0,
            'error_count': 0,
            'warning_count': 0,
            'db_write_failures': 0,
            'last_cleanup': datetime.utcnow()
        }

    def _setup_handlers(self):
        """Setup logging handlers"""
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(self.console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler
        import os
        log_dir = os.getenv('LOG_DIR', './logs')
        os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.FileHandler(
            os.path.join(log_dir, 'antiscam.log'),
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(self.file_formatter)
        self.logger.addHandler(file_handler)

    async def log(self, entry: LogEntry):
        """Log an entry with both Python logging and database storage"""
        try:
            # Update statistics
            self.stats['total_logs'] += 1
            if entry.level == LogLevel.ERROR:
                self.stats['error_count'] += 1
            elif entry.level == LogLevel.WARNING:
                self.stats['warning_count'] += 1
            
            # Standard Python logging
            python_level = getattr(logging, entry.level.value)
            extra_info = f" [Guild: {entry.guild_id}]" if entry.guild_id else ""
            extra_info += f" [User: {entry.user_id}]" if entry.user_id else ""
            extra_info += f" [Message: {entry.message_id}]" if entry.message_id else ""
            
            log_message = f"[{entry.component.value.upper()}] {entry.message}{extra_info}"
            
            if entry.extra_data:
                log_message += f" | Extra: {json.dumps(entry.extra_data, default=str)}"
            
            self.logger.log(python_level, log_message)
            
            # Database logging (if enabled)
            if self.enable_db_logging:
                await self._log_to_database(entry)
                
        except Exception as e:
            # Fallback logging - don't let logging failures break the application
            self.logger.error(f"Failed to log entry: {str(e)}")
            self.stats['db_write_failures'] += 1

    async def _log_to_database(self, entry: LogEntry):
        """Store log entry in database"""
        try:
            async with self.db_manager.get_session() as session:
                system_log = SystemLog(
                    level=entry.level.value,
                    component=entry.component.value,
                    message=entry.message,
                    guild_id=entry.guild_id,
                    user_id=entry.user_id,
                    message_id=entry.message_id,
                    extra_data=json.dumps(entry.extra_data, default=str) if entry.extra_data else None,
                    created_at=entry.timestamp
                )
                
                session.add(system_log)
                await session.commit()
                
        except Exception as e:
            # Don't propagate database logging errors
            self.logger.error(f"Database logging failed: {str(e)}")
            self.stats['db_write_failures'] += 1

    # Convenience methods for different log levels
    async def debug(self, component: LogComponent, message: str, **kwargs):
        """Log debug message"""
        await self.log(LogEntry(LogLevel.DEBUG, component, message, **kwargs))

    async def info(self, component: LogComponent, message: str, **kwargs):
        """Log info message"""
        await self.log(LogEntry(LogLevel.INFO, component, message, **kwargs))

    async def warning(self, component: LogComponent, message: str, **kwargs):
        """Log warning message"""
        await self.log(LogEntry(LogLevel.WARNING, component, message, **kwargs))

    async def error(self, component: LogComponent, message: str, **kwargs):
        """Log error message"""
        await self.log(LogEntry(LogLevel.ERROR, component, message, **kwargs))

    async def critical(self, component: LogComponent, message: str, **kwargs):
        """Log critical message"""
        await self.log(LogEntry(LogLevel.CRITICAL, component, message, **kwargs))

    # Specialized logging methods
    async def log_detection_event(
        self, 
        guild_id: str, 
        message_id: str, 
        user_id: str, 
        channel_id: str,
        detection_result: Dict,
        processing_time_ms: int
    ):
        """Log a detection event with structured data"""
        extra_data = {
            'label': detection_result.get('label', 'unknown'),
            'confidence': detection_result.get('confidence', 0.0),
            'processing_time_ms': processing_time_ms,
            'rules_triggered': detection_result.get('triggered_rules', []),
            'actions_taken': detection_result.get('actions_taken', [])
        }
        
        level = LogLevel.WARNING if detection_result.get('label') == 'scam' else LogLevel.INFO
        
        await self.log(LogEntry(
            level=level,
            component=LogComponent.DETECTOR,
            message=f"Detection completed: {detection_result.get('label', 'unknown')} (confidence: {detection_result.get('confidence', 0.0):.2f})",
            guild_id=guild_id,
            user_id=user_id,
            message_id=message_id,
            channel_id=channel_id,
            extra_data=extra_data
        ))

    async def log_moderator_action(
        self,
        guild_id: str,
        moderator_id: str,
        flagged_message_id: str,
        action: str,
        reason: Optional[str] = None
    ):
        """Log moderator action"""
        extra_data = {
            'flagged_message_id': flagged_message_id,
            'action': action,
            'reason': reason
        }
        
        await self.log(LogEntry(
            level=LogLevel.INFO,
            component=LogComponent.ACTIONER,
            message=f"Moderator action taken: {action}",
            guild_id=guild_id,
            user_id=moderator_id,
            extra_data=extra_data
        ))

    async def log_system_error(
        self,
        component: LogComponent,
        error: Exception,
        context: Optional[Dict] = None,
        **kwargs
    ):
        """Log system error with full traceback"""
        error_details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc(),
            'context': context or {}
        }
        
        await self.log(LogEntry(
            level=LogLevel.ERROR,
            component=component,
            message=f"System error: {type(error).__name__}: {str(error)}",
            extra_data=error_details,
            **kwargs
        ))

    async def log_performance_metrics(
        self,
        component: LogComponent,
        operation: str,
        duration_ms: int,
        metadata: Optional[Dict] = None,
        **kwargs
    ):
        """Log performance metrics"""
        perf_data = {
            'operation': operation,
            'duration_ms': duration_ms,
            'metadata': metadata or {}
        }
        
        level = LogLevel.WARNING if duration_ms > 10000 else LogLevel.INFO  # Warn if over 10 seconds
        
        await self.log(LogEntry(
            level=level,
            component=component,
            message=f"Performance: {operation} completed in {duration_ms}ms",
            extra_data=perf_data,
            **kwargs
        ))

    async def log_rate_limit_hit(
        self,
        guild_id: str,
        user_id: str,
        limit_type: str,
        current_count: int,
        limit: int
    ):
        """Log rate limit violations"""
        extra_data = {
            'limit_type': limit_type,
            'current_count': current_count,
            'limit': limit
        }
        
        await self.log(LogEntry(
            level=LogLevel.WARNING,
            component=LogComponent.BOT,
            message=f"Rate limit hit: {limit_type} ({current_count}/{limit})",
            guild_id=guild_id,
            user_id=user_id,
            extra_data=extra_data
        ))

    @asynccontextmanager
    async def log_operation(
        self,
        component: LogComponent,
        operation: str,
        **kwargs
    ):
        """Context manager for logging operations with timing"""
        start_time = datetime.utcnow()
        
        await self.debug(
            component,
            f"Starting operation: {operation}",
            **kwargs
        )
        
        try:
            yield self
            
            # Success
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            await self.log_performance_metrics(
                component,
                operation,
                int(duration),
                **kwargs
            )
            
        except Exception as e:
            # Error
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            await self.log_system_error(
                component,
                e,
                context={'operation': operation, 'duration_ms': int(duration)},
                **kwargs
            )
            raise

    async def cleanup_old_logs(self, retention_days: int = 30):
        """Clean up old log entries from database"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            async with self.db_manager.get_session() as session:
                # Keep ERROR and CRITICAL logs longer
                result = await session.execute(
                    """DELETE FROM system_logs 
                       WHERE created_at < $1 
                       AND level NOT IN ('ERROR', 'CRITICAL')""",
                    cutoff_date
                )
                
                deleted_count = result.rowcount
                await session.commit()
                
                await self.info(
                    LogComponent.DATABASE,
                    f"Cleaned up {deleted_count} old log entries older than {retention_days} days"
                )
                
                self.stats['last_cleanup'] = datetime.utcnow()
                
        except Exception as e:
            await self.log_system_error(
                LogComponent.DATABASE,
                e,
                context={'operation': 'log_cleanup', 'retention_days': retention_days}
            )

    async def get_recent_errors(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Get recent error logs"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            async with self.db_manager.get_session() as session:
                result = await session.execute(
                    """SELECT * FROM system_logs 
                       WHERE level IN ('ERROR', 'CRITICAL') 
                       AND created_at >= $1 
                       ORDER BY created_at DESC 
                       LIMIT $2""",
                    cutoff_time, limit
                )
                
                return [dict(row) for row in result.fetchall()]
                
        except Exception as e:
            await self.log_system_error(
                LogComponent.DATABASE,
                e,
                context={'operation': 'get_recent_errors'}
            )
            return []

    def get_stats(self) -> Dict:
        """Get logging statistics"""
        return {
            **self.stats,
            'uptime_hours': (datetime.utcnow() - self.stats['last_cleanup']).total_seconds() / 3600,
            'error_rate': self.stats['error_count'] / max(self.stats['total_logs'], 1),
            'db_failure_rate': self.stats['db_write_failures'] / max(self.stats['total_logs'], 1)
        }

    async def health_check(self) -> Dict:
        """Health check for logging system"""
        try:
            # Test database connection
            async with self.db_manager.get_session() as session:
                await session.execute("SELECT 1")
            
            # Test logging
            await self.info(LogComponent.DATABASE, "Health check completed")
            
            return {
                'status': 'healthy',
                'database_connected': True,
                'stats': self.get_stats()
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'database_connected': False,
                'stats': self.get_stats()
            }

# Global logger instance
_global_logger: Optional[AntiScamLogger] = None

def init_logger(db_manager: DatabaseManager, enable_db_logging: bool = True) -> AntiScamLogger:
    """Initialize global logger instance"""
    global _global_logger
    _global_logger = AntiScamLogger(db_manager, enable_db_logging)
    return _global_logger

def get_logger() -> AntiScamLogger:
    """Get global logger instance"""
    if _global_logger is None:
        raise RuntimeError("Logger not initialized. Call init_logger() first.")
    return _global_logger

# Convenience functions for common logging patterns
async def log_info(component: LogComponent, message: str, **kwargs):
    """Quick info logging"""
    logger = get_logger()
    await logger.info(component, message, **kwargs)

async def log_error(component: LogComponent, message: str, **kwargs):
    """Quick error logging"""
    logger = get_logger()
    await logger.error(component, message, **kwargs)

async def log_warning(component: LogComponent, message: str, **kwargs):
    """Quick warning logging"""
    logger = get_logger()
    await logger.warning(component, message, **kwargs)
