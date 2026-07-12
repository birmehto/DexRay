from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import List, Optional

from pydantic_settings import BaseSettings


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    app_name: str = "DexRay"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: LogLevel = LogLevel.INFO

    upload_dir: Path = Path("/tmp/apk-analyzer/uploads")
    output_dir: Path = Path("/tmp/apk-analyzer/reports")
    temp_dir: Path = Path("/tmp/apk-analyzer/temp")
    max_upload_size: int = 500 * 1024 * 1024

    allowed_extensions: List[str] = [".apk"]
    scan_timeout: int = 300

    enable_jadx: bool = True
    enable_apktool: bool = True
    enable_androguard: bool = True
    enable_mobsf: bool = False
    mobsf_url: Optional[str] = None
    mobsf_api_key: Optional[str] = None

    secret_patterns_path: Optional[Path] = None
    custom_rules_path: Optional[Path] = None

    report_title: str = "APK Security Analysis Report"
    report_company_name: str = "DexRay"
    report_logo_path: Optional[Path] = None

    server_host: str = "0.0.0.0"
    server_port: int = 8000
    server_workers: int = 4

    model_config = {"env_prefix": "APK_", "env_file": ".env"}

    @classmethod
    def load(cls, env_file: Optional[str] = None) -> "Settings":
        if env_file:
            return cls(_env_file=env_file)
        return cls()

    def ensure_directories(self) -> None:
        for d in [self.upload_dir, self.output_dir, self.temp_dir]:
            d.mkdir(parents=True, exist_ok=True)


settings = Settings.load()
