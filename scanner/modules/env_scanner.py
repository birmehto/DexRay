from __future__ import annotations

import logging
import re
from typing import List
from zipfile import ZipFile

from core.models import EnvVariable

logger = logging.getLogger(__name__)

SENSITIVE_KEYS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "access_key", "secret_key", "auth", "credential", "private_key",
    "aws_secret", "azure", "connection_string", "database_url",
    "db_password", "ssh_key", "jwt", "oauth", "client_secret",
    "encryption_key", "master_key", "slack_token", "github_token",
    "firebase", "stripe", "paypal", "twilio", "sendgrid",
    "mailgun", "mailchimp", "openai", "anthropic",
]


class EnvScanner:
    def __init__(self) -> None:
        pass

    async def scan(self, apk_path: str) -> List[EnvVariable]:
        variables: List[EnvVariable] = []
        env_files = []

        try:
            with ZipFile(apk_path, "r") as zf:
                for name in zf.namelist():
                    basename = name.split("/")[-1].lower()
                    if basename in (".env", ".env.example", ".env.local", ".env.production",
                                    ".env.staging", ".env.development", ".env.test",
                                    "env", "environment", ".env.sample"):
                        env_files.append(name)

                for env_file in env_files:
                    try:
                        raw = zf.read(env_file)
                        text = raw.decode("utf-8", errors="replace")
                        extracted = self._parse_env_content(text, env_file)
                        variables.extend(extracted)
                    except Exception as e:
                        logger.debug("Failed to parse env file %s: %s", env_file, e)

                for name in zf.namelist():
                    if name.endswith(".gradle") or name.endswith(".gradle.kts"):
                        try:
                            raw = zf.read(name)
                            text = raw.decode("utf-8", errors="replace")
                            for match in re.finditer(
                                r'(?:buildConfigField|resValue)\s*\(\s*(?:\'|")(\w+)(?:\'|")'
                                r'\s*,\s*(?:\'|")(\w+)(?:\'|")\s*,\s*(?:\'|")([^\'"]+)(?:\'|")\s*\)',
                                text,
                            ):
                                key = match.group(2)
                                val = match.group(3)
                                variables.append(EnvVariable(
                                    key=key,
                                    value=val[:200],
                                    file_path=name,
                                    is_sensitive=any(s in key.lower() for s in SENSITIVE_KEYS),
                                ))
                        except Exception:
                            pass

        except Exception as e:
            logger.error("Env scan failed: %s", e)

        return variables

    def _parse_env_content(self, text: str, file_path: str) -> List[EnvVariable]:
        variables: List[EnvVariable] = []
        for i, line in enumerate(text.split("\n"), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.*?)(?:\s*#.*)?$', line)
            if match:
                key = match.group(1)
                value = match.group(2).strip().strip("\"'").strip()
                is_sensitive = any(s in key.lower() for s in SENSITIVE_KEYS)
                variables.append(EnvVariable(
                    key=key,
                    value=value[:200],
                    file_path=file_path,
                    line_number=i,
                    is_sensitive=is_sensitive,
                ))
        return variables
