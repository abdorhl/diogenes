"""
Enhanced error handling and logging utilities for DIOGENES.
Provides structured exception handling and detailed logging.
"""

import logging
import functools
import traceback
from typing import Optional, Callable, Any
from datetime import datetime
import sys


class ScanError(Exception):
    """Base exception for scanner errors."""
    pass


class NetworkError(ScanError):
    """Network-related errors (timeouts, connection failures)."""
    pass


class ValidationError(ScanError):
    """Input validation errors."""
    pass


class DetectorError(ScanError):
    """Detector-specific errors."""
    pass


class CrawlerError(ScanError):
    """Crawler-specific errors."""
    pass


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None, verbose: bool = False):
    """
    Configure logging with appropriate handlers and formatters.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        verbose: If True, include detailed debug information
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    if verbose:
        fmt = '[%(asctime)s] [%(name)s] [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s'
    else:
        fmt = '[%(levelname)s] %(message)s'
    
    formatter = logging.Formatter(fmt, datefmt='%Y-%m-%d %H:%M:%S')
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers = []  # Clear existing handlers
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)  # Always log everything to file
            root_logger.addHandler(file_handler)
        except Exception as e:
            root_logger.warning(f"Failed to setup file logging: {e}")
    
    # Suppress noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('charset_normalizer').setLevel(logging.WARNING)


def handle_errors(
    default_return: Any = None,
    raise_on_error: bool = False,
    log_traceback: bool = True,
    error_message: str = "Operation failed"
):
    """
    Decorator for robust error handling in functions.
    
    Args:
        default_return: Value to return on error (if not raising)
        raise_on_error: If True, re-raise exceptions after logging
        log_traceback: If True, log full traceback
        error_message: Custom error message prefix
    
    Example:
        @handle_errors(default_return=[], error_message="Crawl failed")
        def crawl_page(url):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(func.__module__)
            try:
                return func(*args, **kwargs)
            except KeyboardInterrupt:
                # Always propagate keyboard interrupts
                raise
            except Exception as e:
                # Log the error with context
                error_context = f"{error_message}: {func.__name__}"
                
                if log_traceback:
                    logger.error(f"{error_context}: {str(e)}", exc_info=True)
                else:
                    logger.error(f"{error_context}: {str(e)}")
                
                if raise_on_error:
                    raise
                
                return default_return
        
        return wrapper
    return decorator


class ErrorContext:
    """
    Context manager for handling errors in code blocks.
    
    Example:
        with ErrorContext("Fetching page", default_return=None) as ctx:
            response = fetch_url(url)
            return response
    """
    
    def __init__(
        self,
        operation: str,
        logger: Optional[logging.Logger] = None,
        default_return: Any = None,
        raise_on_error: bool = False,
        log_traceback: bool = True
    ):
        self.operation = operation
        self.logger = logger or logging.getLogger(__name__)
        self.default_return = default_return
        self.raise_on_error = raise_on_error
        self.log_traceback = log_traceback
        self.exception = None
        self.result = default_return
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, exc_traceback):
        if exc_type is None:
            return True
        
        # Don't suppress keyboard interrupts
        if exc_type is KeyboardInterrupt:
            return False
        
        self.exception = exc_value
        
        # Log the error
        if self.log_traceback:
            self.logger.error(
                f"{self.operation} failed: {str(exc_value)}",
                exc_info=(exc_type, exc_value, exc_traceback)
            )
        else:
            self.logger.error(f"{self.operation} failed: {str(exc_value)}")
        
        # Suppress or propagate
        if self.raise_on_error:
            return False  # Propagate exception
        else:
            return True  # Suppress exception


def log_scan_start(logger: logging.Logger, url: str, config: dict):
    """Log scan initialization with configuration."""
    logger.info("=" * 70)
    logger.info(f"DIOGENES Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Target: {url}")
    logger.info(f"Configuration: {config}")
    logger.info("=" * 70)


def log_scan_complete(logger: logging.Logger, findings_count: int, duration: float, endpoints_count: int):
    """Log scan completion with summary."""
    logger.info("=" * 70)
    logger.info(f"Scan Complete: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Duration: {duration:.2f} seconds")
    logger.info(f"Endpoints tested: {endpoints_count}")
    logger.info(f"Findings: {findings_count}")
    logger.info("=" * 70)


def log_progress(logger: logging.Logger, current: int, total: int, findings: int, operation: str = "Scanning"):
    """Log progress updates."""
    percentage = (current / total * 100) if total > 0 else 0
    logger.info(f"{operation}: {current}/{total} ({percentage:.1f}%) - {findings} findings so far")


def safe_get_attribute(obj: Any, attr: str, default: Any = None) -> Any:
    """Safely get attribute from object with fallback."""
    try:
        return getattr(obj, attr, default)
    except Exception:
        return default


def safe_dict_get(d: dict, key: str, default: Any = None) -> Any:
    """Safely get value from dictionary with type checking."""
    try:
        return d.get(key, default) if isinstance(d, dict) else default
    except Exception:
        return default


def validate_response(response: Any, max_size: int = 2 * 1024 * 1024) -> bool:
    """
    Validate HTTP response object.
    
    Args:
        response: Response object to validate
        max_size: Maximum allowed response size in bytes
    
    Returns:
        True if response is valid and safe to process
    """
    if response is None:
        return False
    
    try:
        # Check status code
        if not hasattr(response, 'status_code') or response.status_code >= 500:
            return False
        
        # Check content length
        if hasattr(response, 'content'):
            content_length = len(response.content or b"")
            if content_length > max_size:
                logging.getLogger(__name__).warning(
                    f"Response too large: {content_length} bytes (max: {max_size})"
                )
                return False
        
        return True
    except Exception as e:
        logging.getLogger(__name__).debug(f"Response validation failed: {e}")
        return False


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string for logging."""
    if not s or len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


class RateLimitWarning:
    """Track and warn about potential rate limiting."""
    
    def __init__(self, threshold: int = 10, window: int = 60):
        self.threshold = threshold
        self.window = window
        self.error_count = 0
        self.last_reset = datetime.now()
        self.logger = logging.getLogger(__name__)
    
    def record_error(self, status_code: int):
        """Record an error response."""
        now = datetime.now()
        
        # Reset counter if window expired
        if (now - self.last_reset).total_seconds() > self.window:
            self.error_count = 0
            self.last_reset = now
        
        # Count rate limit errors (429, 503)
        if status_code in (429, 503):
            self.error_count += 1
            
            if self.error_count >= self.threshold:
                self.logger.warning(
                    f"⚠️  Potential rate limiting detected ({self.error_count} errors in {self.window}s). "
                    f"Consider increasing --delay parameter."
                )
