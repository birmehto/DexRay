from __future__ import annotations

import pytest

from scanner.modules.firebase_scanner import FirebaseScanner


class TestFirebaseScanner:
    @pytest.mark.asyncio
    async def test_detect_firebase_url(self) -> None:
        scanner = FirebaseScanner()
        config = await scanner.extract("/nonexistent.apk", [
            "https://myapp.firebaseio.com/data",
            "Some other string",
        ])
        assert config.present is True
        assert config.database_url is not None

    @pytest.mark.asyncio
    async def test_no_firebase(self) -> None:
        scanner = FirebaseScanner()
        config = await scanner.extract("/nonexistent.apk", [
            "Hello World",
            "com.example.app",
        ])
        assert config.present is False
        assert config.api_key is None
