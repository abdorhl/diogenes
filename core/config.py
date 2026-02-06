"""
Configuration management for DIOGENES scanner.
Provides default settings, environment variable support, and scan profiles.
"""

import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json
from pathlib import Path


@dataclass
class ScanConfig:
    """Configuration for scan behavior and performance tuning."""
    
    # Request settings
    timeout: int = 10
    max_retries: int = 2
    delay: float = 0.0
    delay_jitter: float = 0.0  # Random jitter added to delay (0-1)
    
    # Connection pooling
    pool_size: int = 20
    max_concurrent: int = 5
    
    # Crawling limits
    max_depth: int = 3
    max_urls: int = 500
    max_response_size: int = 2 * 1024 * 1024  # 2MB
    max_script_size: int = 1024 * 1024  # 1MB
    
    # Performance
    cache_responses: bool = True
    cache_size: int = 1000
    enable_concurrent: bool = True
    quick_scan: bool = False
    
    # Detection
    enabled_detectors: List[str] = field(default_factory=lambda: ["xss", "sqli", "csrf", "ssrf", "idor"])
    common_params: List[str] = field(default_factory=lambda: ["q", "search", "id", "input", "keyword", "query", "name"])
    
    # Security
    validate_urls: bool = True
    block_private_ips: bool = True
    allowed_schemes: List[str] = field(default_factory=lambda: ["http", "https"])
    blocked_extensions: List[str] = field(default_factory=lambda: [
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf"
    ])
    
    # Stealth & evasion
    rotate_user_agents: bool = False
    random_order: bool = False
    respect_robots_txt: bool = True
    
    # User agents for rotation
    user_agents: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    ])
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    verbose: bool = False
    
    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'ScanConfig':
        """Create config from dictionary."""
        return cls(**{k: v for k, v in config_dict.items() if k in cls.__annotations__})
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ScanConfig':
        """Load config from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config_dict = json.load(f)
            return cls.from_dict(config_dict)
        except Exception as e:
            raise ValueError(f"Failed to load config from {config_path}: {e}")
    
    @classmethod
    def from_env(cls) -> 'ScanConfig':
        """Load config from environment variables."""
        env_config = {}
        
        # Map environment variables to config fields
        env_mappings = {
            "DIOGENES_TIMEOUT": ("timeout", int),
            "DIOGENES_MAX_RETRIES": ("max_retries", int),
            "DIOGENES_DELAY": ("delay", float),
            "DIOGENES_MAX_DEPTH": ("max_depth", int),
            "DIOGENES_MAX_URLS": ("max_urls", int),
            "DIOGENES_THREADS": ("max_concurrent", int),
            "DIOGENES_QUICK_SCAN": ("quick_scan", lambda x: x.lower() == "true"),
            "DIOGENES_LOG_LEVEL": ("log_level", str),
            "DIOGENES_DETECTORS": ("enabled_detectors", lambda x: x.split(",")),
        }
        
        for env_var, (field_name, converter) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    env_config[field_name] = converter(value)
                except Exception:
                    pass
        
        return cls(**env_config)
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary."""
        return {
            k: v for k, v in self.__dict__.items()
            if not k.startswith('_')
        }
    
    def save(self, config_path: str):
        """Save config to JSON file."""
        config_dict = self.to_dict()
        with open(config_path, 'w') as f:
            json.dump(config_dict, f, indent=2)


# Predefined scan profiles
SCAN_PROFILES = {
    "stealth": ScanConfig(
        delay=1.0,
        delay_jitter=0.5,
        max_concurrent=2,
        max_depth=2,
        rotate_user_agents=True,
        random_order=True,
        quick_scan=False,
        timeout=15
    ),
    
    "balanced": ScanConfig(
        delay=0.3,
        delay_jitter=0.2,
        max_concurrent=5,
        max_depth=3,
        quick_scan=False,
        timeout=10
    ),
    
    "aggressive": ScanConfig(
        delay=0.0,
        delay_jitter=0.0,
        max_concurrent=10,
        max_depth=4,
        max_urls=1000,
        quick_scan=False,
        timeout=8
    ),
    
    "quick": ScanConfig(
        delay=0.0,
        max_concurrent=8,
        max_depth=2,
        max_urls=200,
        quick_scan=True,
        timeout=5
    ),
    
    "deep": ScanConfig(
        delay=0.5,
        max_concurrent=5,
        max_depth=5,
        max_urls=2000,
        quick_scan=False,
        timeout=15
    )
}


def load_config(
    profile: Optional[str] = None,
    config_file: Optional[str] = None,
    use_env: bool = True,
    **overrides
) -> ScanConfig:
    """
    Load configuration with precedence: overrides > config_file > env > profile > defaults
    
    Args:
        profile: Name of predefined profile (stealth, balanced, aggressive, quick, deep)
        config_file: Path to JSON config file
        use_env: Whether to load from environment variables
        **overrides: Direct config overrides
    
    Returns:
        ScanConfig instance
    """
    # Start with profile or defaults
    if profile and profile.lower() in SCAN_PROFILES:
        config = SCAN_PROFILES[profile.lower()]
    else:
        config = ScanConfig()
    
    # Layer environment variables
    if use_env:
        env_config = ScanConfig.from_env()
        for key, value in env_config.to_dict().items():
            if value != getattr(ScanConfig(), key):  # Only override if changed from default
                setattr(config, key, value)
    
    # Layer config file
    if config_file and Path(config_file).exists():
        file_config = ScanConfig.from_file(config_file)
        for key, value in file_config.to_dict().items():
            setattr(config, key, value)
    
    # Layer direct overrides
    for key, value in overrides.items():
        if hasattr(config, key):
            setattr(config, key, value)
    
    return config


# IP validation utilities
def is_private_ip(ip: str) -> bool:
    """Check if IP address is private/internal."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def is_valid_url(url: str, allowed_schemes: List[str] = None) -> bool:
    """Validate URL scheme and format."""
    from urllib.parse import urlparse
    
    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]
    
    try:
        parsed = urlparse(url)
        if parsed.scheme not in allowed_schemes:
            return False
        if not parsed.netloc:
            return False
        return True
    except Exception:
        return False
