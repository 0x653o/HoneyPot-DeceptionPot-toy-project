"""
Configuration loader for the honeypot system.
Reads config.yaml and provides typed access to all settings.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path


@dataclass
class ProtocolConfig:
    """Configuration for a single protocol handler."""
    enabled: bool = True
    port: int = 0
    banner: str = ""
    # SSH-specific
    max_auth_attempts: int = 3
    # HTTP-specific
    server_header: str = "Apache/2.4.58 (Ubuntu)"
    server_hostname: str = "webserver"
    # FTP-specific
    allow_anonymous: bool = True
    # Telnet-specific
    hostname: str = "honeypot-server"
    os_banner: str = "Ubuntu 22.04.3 LTS"
    fake_user: str = "test"
    max_login_attempts: int = 3
    # SMTP-specific
    max_message_size: int = 10240000


@dataclass
class SandboxConfig:
    """nsjail sandbox configuration."""
    enabled: bool = True
    fallback_no_sandbox: bool = True
    time_limit_seconds: int = 30
    memory_limit_mb: int = 16
    seccomp_profile: str = "seccomp-profile.json"


@dataclass
class LoggingConfig:
    """Logging configuration for dual-sink (file + SQLite)."""
    log_file: str = "data/honeypot.log"
    db_file: str = "data/honeypot.db"
    log_level: str = "INFO"
    max_file_size: int = 10485760  # 10 MB
    backup_count: int = 5


@dataclass
class RateLimitConfig:
    """Per-IP rate limiting configuration."""
    enabled: bool = True
    max_connections: int = 20
    window_seconds: int = 60
    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)


@dataclass
class ManagementConfig:
    """Management API configuration."""
    bind: str = "127.0.0.1"
    port: int = 9090
    cors_origins: List[str] = field(default_factory=lambda: [
        "http://localhost:9090",
        "http://127.0.0.1:9090"
    ])


@dataclass
class SSLConfig:
    """SSL configuration for future domain support."""
    enabled: bool = False
    cert_path: str = ""
    key_path: str = ""


@dataclass
class ReverseProxyConfig:
    """Reverse proxy configuration for future domain support."""
    enabled: bool = False
    provider: str = ""


@dataclass
class DomainConfig:
    """Domain configuration (future feature)."""
    name: str = ""
    ssl: SSLConfig = field(default_factory=SSLConfig)
    reverse_proxy: ReverseProxyConfig = field(default_factory=ReverseProxyConfig)


@dataclass
class GeoIPConfig:
    """GeoIP database configuration."""
    db_path: str = "data/GeoLite2-City.mmdb"


@dataclass
class HoneypotConfig:
    """Top-level configuration container."""
    protocols: dict = field(default_factory=dict)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    management: ManagementConfig = field(default_factory=ManagementConfig)
    domain: DomainConfig = field(default_factory=DomainConfig)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)

    def get_protocol(self, name: str) -> ProtocolConfig:
        """Get protocol configuration by name."""
        if name not in self.protocols:
            return ProtocolConfig()
        return self.protocols[name]

    def get_enabled_protocols(self) -> dict:
        """Return only enabled protocol configurations."""
        return {
            name: cfg for name, cfg in self.protocols.items()
            if cfg.enabled
        }


def _build_protocol_config(name: str, data: dict) -> ProtocolConfig:
    """Build a ProtocolConfig from raw YAML dict, using sensible defaults."""
    cfg = ProtocolConfig()
    cfg.enabled = data.get("enabled", True)
    cfg.port = data.get("port", 0)
    cfg.banner = data.get("banner", "")

    # Protocol-specific fields
    if name == "ssh":
        cfg.max_auth_attempts = data.get("max_auth_attempts", 3)
    elif name == "http":
        cfg.server_header = data.get("server_header", cfg.server_header)
        cfg.server_hostname = data.get("server_hostname", cfg.server_hostname)
    elif name == "ftp":
        cfg.allow_anonymous = data.get("allow_anonymous", True)
    elif name == "telnet":
        cfg.hostname = data.get("hostname", cfg.hostname)
        cfg.os_banner = data.get("os_banner", cfg.os_banner)
        cfg.fake_user = data.get("fake_user", cfg.fake_user)
        cfg.max_login_attempts = data.get("max_login_attempts", 3)
    elif name == "smtp":
        cfg.hostname = data.get("hostname", "mail.example.com")
        cfg.banner = data.get("banner", cfg.banner)
        cfg.max_message_size = data.get("max_message_size", 10240000)

    return cfg


def load_config(config_path: str = "config.yaml") -> HoneypotConfig:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the YAML config file.
        
    Returns:
        HoneypotConfig with all settings loaded.
        
    Raises:
        FileNotFoundError: If config file doesn't exist.
        yaml.YAMLError: If config file is malformed.
    """
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r') as f:
        raw = yaml.safe_load(f) or {}

    config = HoneypotConfig()

    # --- Protocols ---
    protocols_raw = raw.get("protocols", {})
    for name, proto_data in protocols_raw.items():
        if isinstance(proto_data, dict):
            config.protocols[name] = _build_protocol_config(name, proto_data)

    # --- Sandbox ---
    sandbox_raw = raw.get("sandbox", {})
    if sandbox_raw:
        config.sandbox = SandboxConfig(
            enabled=sandbox_raw.get("enabled", True),
            fallback_no_sandbox=sandbox_raw.get("fallback_no_sandbox", True),
            time_limit_seconds=sandbox_raw.get("time_limit_seconds", 30),
            memory_limit_mb=sandbox_raw.get("memory_limit_mb", 16),
            seccomp_profile=sandbox_raw.get("seccomp_profile", "seccomp-profile.json"),
        )

    # --- Logging ---
    log_raw = raw.get("logging", {})
    if log_raw:
        config.logging = LoggingConfig(
            log_file=log_raw.get("log_file", "data/honeypot.log"),
            db_file=log_raw.get("db_file", "data/honeypot.db"),
            log_level=log_raw.get("log_level", "INFO"),
            max_file_size=log_raw.get("max_file_size", 10485760),
            backup_count=log_raw.get("backup_count", 5),
        )

    # --- Rate Limit ---
    rl_raw = raw.get("rate_limit", {})
    if rl_raw:
        config.rate_limit = RateLimitConfig(
            enabled=rl_raw.get("enabled", True),
            max_connections=rl_raw.get("max_connections", 20),
            window_seconds=rl_raw.get("window_seconds", 60),
            whitelist=rl_raw.get("whitelist", []),
            blacklist=rl_raw.get("blacklist", []),
        )

    # --- Management ---
    mgmt_raw = raw.get("management", {})
    if mgmt_raw:
        config.management = ManagementConfig(
            bind=mgmt_raw.get("bind", "127.0.0.1"),
            port=mgmt_raw.get("port", 9090),
            cors_origins=mgmt_raw.get("cors_origins", [
                "http://localhost:9090"
            ]),
        )

    # --- Domain (future) ---
    domain_raw = raw.get("domain", {})
    if domain_raw:
        ssl_raw = domain_raw.get("ssl", {})
        rp_raw = domain_raw.get("reverse_proxy", {})
        config.domain = DomainConfig(
            name=domain_raw.get("name", ""),
            ssl=SSLConfig(
                enabled=ssl_raw.get("enabled", False),
                cert_path=ssl_raw.get("cert_path", ""),
                key_path=ssl_raw.get("key_path", ""),
            ),
            reverse_proxy=ReverseProxyConfig(
                enabled=rp_raw.get("enabled", False),
                provider=rp_raw.get("provider", ""),
            ),
        )

    # --- GeoIP ---
    geo_raw = raw.get("geoip", {})
    if geo_raw:
        config.geoip = GeoIPConfig(
            db_path=geo_raw.get("db_path", "data/GeoLite2-City.mmdb"),
        )

    # Ensure data directory exists
    data_dir = Path(config.logging.log_file).parent
    data_dir.mkdir(parents=True, exist_ok=True)

    return config
