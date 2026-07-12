from __future__ import annotations

import pytest

from scanner.modules.secret_scanner import SecretScanner


class TestSecretScanner:
    @pytest.mark.asyncio
    async def test_detect_aws_key(self) -> None:
        scanner = SecretScanner()
        secrets = await scanner.extract("/nonexistent.apk", [
            "AKIAIOSFODNN7EXAMPLE",
            "Some random text",
        ])
        types = [s.secret_type for s in secrets]
        assert "AWS Access Key ID" in types

    @pytest.mark.asyncio
    async def test_detect_google_api_key(self) -> None:
        scanner = SecretScanner()
        secrets = await scanner.extract("/nonexistent.apk", [
            "AIzaSyAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaA33",
            "Normal text here",
        ])
        types = [s.secret_type for s in secrets]
        assert "Google API Key" in types or "Firebase API Key" in types

    @pytest.mark.asyncio
    async def test_detect_github_token(self) -> None:
        scanner = SecretScanner()
        secrets = await scanner.extract("/nonexistent.apk", [
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ])
        types = [s.secret_type for s in secrets]
        assert "GitHub Token" in types

    @pytest.mark.asyncio
    async def test_detect_private_key(self) -> None:
        scanner = SecretScanner()
        secrets = await scanner.extract("/nonexistent.apk", [
            "-----BEGIN PRIVATE KEY-----",
            "MIIEpAIBAAKCAQEA...",
        ])
        types = [s.secret_type for s in secrets]
        assert "Private Key PEM" in types

    @pytest.mark.asyncio
    async def test_detect_connection_string(self) -> None:
        scanner = SecretScanner()
        secrets = await scanner.extract("/nonexistent.apk", [
            "jdbc:mysql://localhost:3306/mydb?user=admin&password=secret123",
            "postgres://user:pass@localhost:5432/db",
        ])
        types = [s.secret_type for s in secrets]
        assert "Connection String" in types

    @pytest.mark.asyncio
    async def test_no_false_positives(self) -> None:
        scanner = SecretScanner()
        secrets = await scanner.extract("/nonexistent.apk", [
            "Hello World",
            "This is a normal string",
            "com.example.app",
            "android.permission.INTERNET",
            "https://example.com",
            "<string name='app_name'>MyApp</string>",
        ])
        high_conf = [s for s in secrets if s.confidence >= 0.85]
        assert len(high_conf) == 0
